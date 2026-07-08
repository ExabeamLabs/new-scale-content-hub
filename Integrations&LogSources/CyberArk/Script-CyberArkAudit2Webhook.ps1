<#
.SYNOPSIS
    Pulls audit events from the CyberArk ISPSS Audit SIEM integration API and
    forwards them to a webhook endpoint (e.g. Exabeam) as individual JSON POST requests.

.DESCRIPTION
    Implements the two-endpoint cursor pattern:
        1. POST /api/audits/stream/createQuery  -> returns initial cursorRef
        2. POST /api/audits/stream/results      -> returns events + next cursorRef

    Each audit event is forwarded as a single HTTP POST to the configured webhook URL
    with a Bearer token in the Authorization header. The cursor is persisted to a
    state file after each successfully forwarded page so the script resumes exactly
    where it left off across runs. If the cursor is rejected (stale/expired), a new
    query is created from the last successfully forwarded event timestamp.

    Designed to run as an Azure Automation runbook or Windows Scheduled Task.
    Secrets are retrieved via Get-AutomationVariable (Azure Automation) with a
    fallback to environment variables for local/scheduled task use.

    State (the cursor position) persists via either an Azure Automation variable
    or a local JSON file, controlled by $Config.StatePersistence. Azure Automation
    sandboxes do not retain local disk between runs, so 'AutomationVariable' mode
    is required there - 'File' mode is for Scheduled Task / Hybrid Runbook Worker
    deployments with a persistent disk. See the StatePersistence comment in
    $Config for details.

    The CyberArk API is rate limited to one call per minute, so the script paces
    itself and caps the number of API calls per run.

.NOTES
    Target : CyberArk ISPSS Audit SIEM API -> Webhook (e.g. Exabeam)

    Delivery semantics: at-least-once. The cursor only advances after a full page
    has been forwarded, so a crash mid-run can re-send a page but will never
    silently skip events. Deduplicate downstream on the event 'uuid' field if needed.

.EXAMPLE
    .\CyberArkAuditEndpoint-ForwardAsWebhook.ps1
    .\CyberArkAuditEndpoint-ForwardAsWebhook.ps1 -DryRun          # pull but print instead of posting
    .\CyberArkAuditEndpoint-ForwardAsWebhook.ps1 -ResetCursor     # discard saved cursor, restart from lookback window
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$ResetCursor
)

# =============================================================================
#  CONFIGURATION
# =============================================================================

$Config = @{
    # --- CyberArk Identity (token) ---
    IdentityUrl     = 'https://abc1234.id.cyberark.cloud'         # <-- your Identity tenant URL
    AppId           = 'MySiemApp'                                  # <-- OAuth2 web app Application ID (case-sensitive)
    ClientId        = 'siemsvc@cyberark.cloud.1234'               # <-- service user login name
    Scope           = 'isp.audit.events:read'

    # --- CyberArk Audit API ---
    AuditBaseUrl    = 'https://mycompany.audit.cyberark.cloud'     # <-- from the Export to SIEM integration page
    PageSize        = 500                                          # API max is 500

    # --- Webhook target ---
    WebhookUrl      = 'https://your-exabeam-collector.example.com/api/v1/events'  # <-- webhook endpoint
    WebhookTimeoutSec = 30
    WebhookRetries  = 3                                            # attempts per event before giving up
    WebhookRetryDelaySeconds = 5                                   # pause between retries

    # --- Behaviour ---
    LookbackHours        = 24   # initial window / recovery window (API retains 7 days max)
    OverlapMinutes       = 5    # re-read overlap when rebuilding a lost cursor (at-least-once)
    MaxApiCallsPerRun    = 5    # caps run length; 1 createQuery + N results calls
    ApiCallSpacingSeconds = 61  # CyberArk rate limit is 1 call/min

    # --- State persistence ---
    # 'File'               - state saved to a hardcoded local path on the Hybrid Runbook Worker.
    #                        The directory is created automatically on first run.
    #                        This is the correct mode for a Hybrid Runbook Worker - the local
    #                        filesystem persists between runs so the cursor survives job recycling.
    # 'AutomationVariable' - state saved as an Azure Automation account variable. Use this only
    #                        if running in a standard Azure Automation sandbox (no Hybrid Worker),
    #                        where the local filesystem does NOT persist between runs.
    StatePersistence  = 'File'              # <-- 'File' (Hybrid Worker) or 'AutomationVariable' (Azure sandbox)
    StateVariableName = 'CYBERARK_SYNC_STATE'  # only used when StatePersistence = 'AutomationVariable'

    # --- Local file paths (used when StatePersistence = 'File') ---
    # The WorkDir is created automatically on first run if it does not exist.
    # Adjust the root path to suit your worker's drive layout if needed.
    WorkDir   = 'C:\ProgramData\CyberArkAuditSync'
    StateFile = 'C:\ProgramData\CyberArkAuditSync\state.json'
    LockFile  = 'C:\ProgramData\CyberArkAuditSync\sync.lock'
    LogFile   = ("C:\ProgramData\CyberArkAuditSync\sync_{0:yyyyMMdd}.log" -f (Get-Date))
}

# =============================================================================
#  LOGGING
# =============================================================================

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO'
    )
    $line = "{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}" -f (Get-Date), $Level, $Message
    Write-Host $line
    try { Add-Content -Path $Config.LogFile -Value $line -Encoding UTF8 } catch { }
}

# =============================================================================
#  SECRETS
#
#  Retrieval order:
#    1. Get-AutomationVariable  (Azure Automation runbook)
#    2. Environment variable    (local / Windows Scheduled Task)
#
#  Azure Automation: create variables named CYBERARK_CLIENT_SECRET,
#                    CYBERARK_API_KEY, and WEBHOOK_BEARER_TOKEN in the
#                    Automation Account -> Shared Resources -> Variables.
#                    Mark them as encrypted.
#
#  Scheduled Task:   [Environment]::SetEnvironmentVariable('CYBERARK_CLIENT_SECRET','<value>','Machine')
#                    [Environment]::SetEnvironmentVariable('CYBERARK_API_KEY','<value>','Machine')
#                    [Environment]::SetEnvironmentVariable('WEBHOOK_BEARER_TOKEN','<value>','Machine')
# =============================================================================

function Get-Secret {
    param([Parameter(Mandatory)][string]$Name)

    # Try Azure Automation first
    try {
        $value = Get-AutomationVariable -Name $Name -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
    } catch { }

    # Fall back to environment variable
    $value = [Environment]::GetEnvironmentVariable($Name)
    if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }

    throw "Required secret '$Name' not found in Azure Automation variables or environment variables."
}

# =============================================================================
#  STATE  { cursorRef, lastEventEpoch, lastRunUtc }
#
#  Two persistence backends - see StatePersistence in $Config.
# =============================================================================

function Get-State {
    if ($Config.StatePersistence -eq 'AutomationVariable') {
        if ($ResetCursor) {
            Write-Log "ResetCursor specified - clearing Automation variable '$($Config.StateVariableName)'." 'WARN'
            try { Set-AutomationVariable -Name $Config.StateVariableName -Value '' } catch { }
        }
        $raw = $null
        try { $raw = Get-AutomationVariable -Name $Config.StateVariableName -ErrorAction Stop } catch {
            Write-Log "No existing Automation variable '$($Config.StateVariableName)' found - treating as first run." 'INFO'
        }
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            try { return $raw | ConvertFrom-Json } catch {
                Write-Log "Automation variable content unreadable, starting fresh: $($_.Exception.Message)" 'WARN'
            }
        }
        return [pscustomobject]@{ cursorRef = $null; lastEventEpoch = 0; lastRunUtc = $null }
    }

    # --- File mode ---
    if ($ResetCursor -and (Test-Path $Config.StateFile)) {
        Write-Log "ResetCursor specified - deleting state file." 'WARN'
        Remove-Item $Config.StateFile -Force
    }
    if (Test-Path $Config.StateFile) {
        try {
            return Get-Content $Config.StateFile -Raw | ConvertFrom-Json
        } catch {
            Write-Log "State file unreadable, starting fresh: $($_.Exception.Message)" 'WARN'
        }
    }
    return [pscustomobject]@{ cursorRef = $null; lastEventEpoch = 0; lastRunUtc = $null }
}

function Save-State {
    param([Parameter(Mandatory)]$State)
    $State.lastRunUtc = (Get-Date).ToUniversalTime().ToString('o')
    $json = $State | ConvertTo-Json -Compress

    if ($Config.StatePersistence -eq 'AutomationVariable') {
        if (-not (Get-Command Set-AutomationVariable -ErrorAction SilentlyContinue)) {
            throw "StatePersistence is 'AutomationVariable' but Set-AutomationVariable is not available. " +
                  "This cmdlet only exists inside an Azure Automation sandbox - if running locally or as a " +
                  "Scheduled Task, set StatePersistence = 'File' instead."
        }
        Set-AutomationVariable -Name $Config.StateVariableName -Value $json
        return
    }

    # --- File mode ---
    $json | Set-Content -Path $Config.StateFile -Encoding UTF8
}

# =============================================================================
#  TIME HELPERS
#  CyberArk's docs say 'timestamp' is Unix seconds; live tenants return
#  milliseconds. Handle both by magnitude (13-digit values are ms).
# =============================================================================

function ConvertFrom-UnixTime {
    param([Parameter(Mandatory)][int64]$Value)
    if ($Value -gt 99999999999) {
        return [DateTimeOffset]::FromUnixTimeMilliseconds($Value).UtcDateTime
    }
    return [DateTimeOffset]::FromUnixTimeSeconds($Value).UtcDateTime
}

# =============================================================================
#  CYBERARK API
# =============================================================================

function Get-CyberArkToken {
    $tokenUrl = "{0}/OAuth2/Token/{1}" -f $Config.IdentityUrl, $Config.AppId
    $body = @{
        grant_type    = 'client_credentials'
        client_id     = $Config.ClientId
        client_secret = (Get-Secret 'CYBERARK_CLIENT_SECRET')
        scope         = $Config.Scope
    }
    Write-Log "Requesting access token from $tokenUrl"
    $resp = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $body `
        -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 30
    if (-not $resp.access_token) { throw "Token response did not contain access_token." }
    Write-Log ("Token acquired (expires_in={0}s, scope={1})" -f $resp.expires_in, $resp.scope)
    return $resp.access_token
}

function Get-AuditHeaders {
    param([Parameter(Mandatory)][string]$Token)
    return @{
        'Authorization' = "Bearer $Token"
        'x-api-key'     = (Get-Secret 'CYBERARK_API_KEY')
    }
}

function New-AuditQuery {
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][datetime]$FromUtc,
        [Parameter(Mandatory)][datetime]$ToUtc
    )
    $uri  = "{0}/api/audits/stream/createQuery" -f $Config.AuditBaseUrl
    $body = @{
        query = @{
            pageSize    = $Config.PageSize
            filterModel = @{
                date = @{
                    dateFrom = $FromUtc.ToString('yyyy-MM-dd HH:mm:ss')
                    dateTo   = $ToUtc.ToString('yyyy-MM-dd HH:mm:ss')
                }
            }
        }
    } | ConvertTo-Json -Depth 6

    Write-Log ("createQuery window: {0} -> {1} (UTC)" -f $FromUtc.ToString('s'), $ToUtc.ToString('s'))
    $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers (Get-AuditHeaders $Token) `
        -Body $body -ContentType 'application/json' -TimeoutSec 60
    if (-not $resp.cursorRef) { throw "createQuery did not return a cursorRef." }
    return $resp.cursorRef
}

function Get-AuditResults {
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][string]$CursorRef
    )
    $uri  = "{0}/api/audits/stream/results" -f $Config.AuditBaseUrl
    $body = @{ cursorRef = $CursorRef } | ConvertTo-Json
    return Invoke-RestMethod -Method Post -Uri $uri -Headers (Get-AuditHeaders $Token) `
        -Body $body -ContentType 'application/json' -TimeoutSec 120
}

# =============================================================================
#  WEBHOOK DELIVERY
# =============================================================================

# Fetch the webhook token once at script scope - not per-event - to avoid
# hammering Get-AutomationVariable hundreds of times per run.
$script:WebhookBearerToken = Get-Secret 'WEBHOOK_BEARER_TOKEN'

function Send-WebhookEvent {
    <#
        POSTs a single audit event as JSON to the configured webhook.
        Retries up to WebhookRetries times on transient failure.
        Returns $true on success, $false if all retries exhausted.
    #>
    param([Parameter(Mandatory)]$AuditEvent)

    $body    = $AuditEvent | ConvertTo-Json -Depth 10 -Compress
    $headers = @{
        'Authorization' = "Bearer $script:WebhookBearerToken"
        'Content-Type'  = 'application/json'
    }

    if ($DryRun) {
        Write-Host ("[DRY RUN] Would POST to {0}: {1}" -f $Config.WebhookUrl, $body)
        return $true
    }

    for ($attempt = 1; $attempt -le $Config.WebhookRetries; $attempt++) {
        try {
            $null = Invoke-RestMethod -Method Post -Uri $Config.WebhookUrl `
                -Headers $headers -Body $body -TimeoutSec $Config.WebhookTimeoutSec
            return $true
        } catch {
            $status = $null
            try { $status = [int]$_.Exception.Response.StatusCode } catch { }

            if ($attempt -lt $Config.WebhookRetries) {
                Write-Log ("Webhook attempt {0}/{1} failed (status={2}) - retrying in {3}s: {4}" -f `
                    $attempt, $Config.WebhookRetries, $status, $Config.WebhookRetryDelaySeconds, $_.Exception.Message) 'WARN'
                Start-Sleep -Seconds $Config.WebhookRetryDelaySeconds
            } else {
                Write-Log ("Webhook failed after {0} attempts (status={1}) for event uuid={2}: {3}" -f `
                    $Config.WebhookRetries, $status, $AuditEvent.uuid, $_.Exception.Message) 'ERROR'
                return $false
            }
        }
    }
    return $false
}

# =============================================================================
#  ERROR CLASSIFICATION
# =============================================================================

function Test-CursorError {
    param([Parameter(Mandatory)]$ErrorRecord)
    try {
        $status = [int]$ErrorRecord.Exception.Response.StatusCode
        return ($status -eq 400)
    } catch { return $false }
}

# =============================================================================
#  MAIN
# =============================================================================

# --- Ensure working directory exists (File mode) ---
# Create the directory BEFORE the first Write-Log call so the log file path is valid.
if ($Config.StatePersistence -eq 'File' -and -not (Test-Path $Config.WorkDir)) {
    New-Item -ItemType Directory -Path $Config.WorkDir -Force | Out-Null
    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [INFO] Created working directory: $($Config.WorkDir)"
    try { Add-Content -Path $Config.LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [INFO] Created working directory: $($Config.WorkDir)" -Encoding UTF8 } catch { }
}

# --- Single-instance lock (prevents overlapping runs) ---
# Only meaningful in 'File' mode - see the StatePersistence comment in $Config
# for why 'AutomationVariable' mode relies on non-overlapping schedules instead.
if ($Config.StatePersistence -eq 'File') {
    if (Test-Path $Config.LockFile) {
        $age = (Get-Date) - (Get-Item $Config.LockFile).LastWriteTime
        if ($age.TotalMinutes -lt 30) {
            Write-Log "Lock file present (age $([int]$age.TotalMinutes)m) - another instance is running. Exiting." 'WARN'
            exit 0
        }
        Write-Log "Stale lock file (>30m) - taking over." 'WARN'
    }
    Set-Content -Path $Config.LockFile -Value $PID
}

$eventsForwarded  = 0
$eventsDropped    = 0
$apiCalls         = 0

try {
    $state       = Get-State
    $cyberArkToken = Get-CyberArkToken

    # -------------------------------------------------------------------------
    # Ensure we have a cursor: reuse the persisted one, or create a new query.
    # -------------------------------------------------------------------------
    if ([string]::IsNullOrWhiteSpace($state.cursorRef)) {
        $fromUtc = if ($state.lastEventEpoch -gt 0) {
            (ConvertFrom-UnixTime ([int64]$state.lastEventEpoch)).AddMinutes(-$Config.OverlapMinutes)
        } else {
            (Get-Date).ToUniversalTime().AddHours(-$Config.LookbackHours)
        }

        # Clamp to the API's 7-day retention window.
        $oldestAllowed = (Get-Date).ToUniversalTime().AddDays(-7).AddMinutes(10)
        if ($fromUtc -lt $oldestAllowed) {
            Write-Log "Resume point predates 7-day retention - data gap likely. Clamping window." 'WARN'
            $fromUtc = $oldestAllowed
        }
        $toUtc = (Get-Date).ToUniversalTime()

        $state.cursorRef = New-AuditQuery -Token $cyberArkToken -FromUtc $fromUtc -ToUtc $toUtc
        $apiCalls++
        Save-State $state
        Start-Sleep -Seconds $Config.ApiCallSpacingSeconds
    } else {
        Write-Log "Resuming from persisted cursor."
    }

    # -------------------------------------------------------------------------
    # Page through results until empty, call budget reached, or error.
    # -------------------------------------------------------------------------
    while ($apiCalls -lt $Config.MaxApiCallsPerRun) {

        try {
            $page = Get-AuditResults -Token $cyberArkToken -CursorRef $state.cursorRef
            $apiCalls++
        } catch {
            if (Test-CursorError $_) {
                Write-Log "Cursor rejected by API - clearing. Fresh query will be created next run from lastEventEpoch." 'WARN'
                $state.cursorRef = $null
                Save-State $state
                break
            }
            throw
        }

        $count = if ($page.data) { @($page.data).Count } else { 0 }

        if ($count -eq 0) {
            Write-Log "No new events - caught up. Clearing cursor so next run creates a fresh query from lastEventEpoch."
            # Do NOT keep the exhausted cursor here. The cursor's dateTo is baked in at query
            # creation time, so an exhausted cursor will permanently report "no events" as time
            # moves forward past that window. Clearing it forces a new createQuery on the next
            # run, with a fresh window from lastEventEpoch to now, picking up any new activity.
            $state.cursorRef = $null
            Save-State $state
            break
        }

        Write-Log "Received $count events - forwarding to webhook."

        $pageDropped = 0
        foreach ($evt in $page.data) {
            $ok = Send-WebhookEvent -AuditEvent $evt
            if ($ok) {
                if ($evt.timestamp -and ([int64]$evt.timestamp -gt [int64]$state.lastEventEpoch)) {
                    $state.lastEventEpoch = [int64]$evt.timestamp
                }
            } else {
                $pageDropped++
            }
        }

        $eventsForwarded += ($count - $pageDropped)
        $eventsDropped   += $pageDropped

        if ($pageDropped -gt 0) {
            Write-Log "$pageDropped event(s) could not be delivered after retries and were dropped. Check webhook health." 'WARN'
        }

        # Advance cursor regardless - dropped events are logged but we don't
        # stall the stream indefinitely on a persistently failing event.
        if (-not $page.paging.cursor.cursorRef) {
            Write-Log "Response contained no next cursor - clearing for rebuild next run." 'WARN'
            $state.cursorRef = $null
            Save-State $state
            break
        }
        $state.cursorRef = $page.paging.cursor.cursorRef
        Save-State $state

        # Always sleep after a results call - even on the last iteration - so that
        # if the schedule fires again quickly we don't immediately hit the rate limit.
        Write-Log ("Sleeping {0}s (API rate limit)..." -f $Config.ApiCallSpacingSeconds) 'DEBUG'
        Start-Sleep -Seconds $Config.ApiCallSpacingSeconds
    }

    Write-Log ("Run complete. API calls: {0}, events forwarded: {1}, events dropped: {2}." -f $apiCalls, $eventsForwarded, $eventsDropped)
    if ($eventsDropped -gt 0) { exit 1 }
}
catch {
    Write-Log ("FATAL: {0}" -f $_.Exception.Message) 'ERROR'
    if ($_.ErrorDetails.Message) { Write-Log ("API said: {0}" -f $_.ErrorDetails.Message) 'ERROR' }
    exit 1
}
finally {
    if ($Config.StatePersistence -eq 'File') {
        Remove-Item $Config.LockFile -Force -ErrorAction SilentlyContinue
    }
}
