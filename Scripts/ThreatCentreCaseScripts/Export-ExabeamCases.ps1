<#
.SYNOPSIS
    Export Exabeam Threat Center cases to CSV.

.DESCRIPTION
    Authenticates via OAuth2 client credentials, queries the Exabeam
    Threat Center Search Cases API, and exports results to CSV.

.NOTES
    Rotate your API secret if it has been exposed.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$BaseUrl,

    [Parameter(Mandatory)]
    [string]$ClientId,

    [Parameter(Mandatory)]
    [string]$ClientSecret,

    [Parameter(Mandatory)]
    [string]$StartTime,

    [Parameter(Mandatory)]
    [string]$EndTime,

    [string]$Filter = 'NOT caseId:"__NO_MATCH__"',

    [int]$Limit = 3000,

    [string]$OutputPath = (Get-Location).Path,

    [switch]$ShowJwtPayload
)

# =========================
# Logging
# =========================
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO"    { "Cyan" }
        "SUCCESS" { "Green" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        default   { "White" }
    }

    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $color
}

# =========================
# Ensure UTC Z format
# =========================
function To-UtcZ {
    param(
        [Parameter(Mandatory)]
        [string]$DateText
    )

    if ($DateText -match 'Z$') {
        return $DateText
    }

    try {
        return ([datetime]::Parse($DateText)).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    catch {
        throw "Invalid date format: $DateText"
    }
}

# =========================
# Decode JWT (debug only)
# =========================
function Decode-JWT {
    param(
        [Parameter(Mandatory)]
        [string]$Token
    )

    try {
        $parts = $Token.Split('.')
        if ($parts.Count -lt 2) {
            throw "JWT does not contain enough parts."
        }

        $payload = $parts[1]
        $payload = $payload.Replace('-', '+').Replace('_', '/')

        switch ($payload.Length % 4) {
            2 { $payload += '==' }
            3 { $payload += '=' }
        }

        $json = [System.Text.Encoding]::UTF8.GetString(
            [Convert]::FromBase64String($payload)
        )

        return $json | ConvertFrom-Json
    }
    catch {
        Write-Log "JWT decode failed: $_" "WARN"
        return $null
    }
}

# =========================
# Read raw error body
# =========================
function Get-ErrorResponseBody {
    param(
        [Parameter(Mandatory)]
        $Exception
    )

    try {
        if ($Exception.Response -and $Exception.Response.GetResponseStream) {
            $stream = $Exception.Response.GetResponseStream()
            if ($stream) {
                $reader = New-Object System.IO.StreamReader($stream)
                $body = $reader.ReadToEnd()
                $reader.Close()
                return $body
            }
        }
    }
    catch {
        return $null
    }

    return $null
}

# =========================
# Convert nested values for CSV
# =========================
function Convert-ForCsv {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    if (
        $Value -is [string] -or
        $Value -is [int] -or
        $Value -is [long] -or
        $Value -is [double] -or
        $Value -is [decimal] -or
        $Value -is [bool] -or
        $Value -is [datetime]
    ) {
        return $Value
    }

    if ($Value -is [System.Collections.IDictionary] -or $Value -is [PSCustomObject]) {
        return ($Value | ConvertTo-Json -Compress -Depth 20)
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $items = foreach ($item in $Value) {
            if (
                $item -is [string] -or
                $item -is [int] -or
                $item -is [long] -or
                $item -is [double] -or
                $item -is [decimal] -or
                $item -is [bool] -or
                $item -is [datetime]
            ) {
                $item
            }
            else {
                $item | ConvertTo-Json -Compress -Depth 20
            }
        }
        return ($items -join "; ")
    }

    return [string]$Value
}

# =========================
# Flatten object with priority columns first
# =========================
function Flatten {
    param($obj)

    $priority = @(
        "vendor",
        "caseNumber",
        "caseId",
        "alertId",
        "rules"
    )

    $row = [ordered]@{}

    foreach ($name in $priority) {
        if ($obj.PSObject.Properties.Name -contains $name) {
            $row[$name] = Convert-ForCsv -Value $obj.$name
        }
        else {
            $row[$name] = $null
        }
    }

    foreach ($prop in $obj.PSObject.Properties) {
        if ($priority -notcontains $prop.Name) {
            $row[$prop.Name] = Convert-ForCsv -Value $prop.Value
        }
    }

    [PSCustomObject]$row
}

# =========================
# Prep
# =========================
try {
    $StartTimeUtc = To-UtcZ -DateText $StartTime
    $EndTimeUtc   = To-UtcZ -DateText $EndTime
}
catch {
    Write-Log $_ "ERROR"
    exit 1
}

if (-not (Test-Path $OutputPath)) {
    try {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    catch {
        Write-Log "Failed to create output path: $_" "ERROR"
        exit 1
    }
}

# =========================
# AUTH
# =========================
$tokenUrl = "$BaseUrl/auth/v1/token"

Write-Log "Requesting access token from $tokenUrl"

$tokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
} | ConvertTo-Json -Compress

try {
    $tokenResp = Invoke-RestMethod -Uri $tokenUrl -Method POST -Headers @{
        "accept"       = "application/json"
        "content-type" = "application/json"
    } -Body $tokenBody -ErrorAction Stop

    $token = $tokenResp.access_token

    if (-not $token) {
        throw "Token response did not include access_token."
    }

    Write-Log "Access token obtained successfully." "SUCCESS"
}
catch {
    Write-Log "Authentication failed: $_" "ERROR"

    if ($_.ErrorDetails.Message) {
        Write-Log "API Error Detail: $($_.ErrorDetails.Message)" "ERROR"
    }

    $raw = Get-ErrorResponseBody -Exception $_.Exception
    if ($raw) {
        Write-Log "Raw response body:" "WARN"
        Write-Host $raw
    }

    exit 1
}

if ($ShowJwtPayload) {
    $jwt = Decode-JWT -Token $token
    if ($jwt) {
        Write-Log "Decoded JWT payload below for troubleshooting:"
        $jwt | ConvertTo-Json -Depth 10 | Write-Host

        if ($jwt.PSObject.Properties.Name -contains "aud") {
            Write-Log "JWT aud: $($jwt.aud)" "INFO"
        }
        if ($jwt.PSObject.Properties.Name -contains "iss") {
            Write-Log "JWT iss: $($jwt.iss)" "INFO"
        }
    }
}

# =========================
# SEARCH CASES
# =========================
$casesUrl = "$BaseUrl/threat-center/v1/search/cases"

$bodyObject = @{
    fields    = @("*")
    limit     = $Limit
    startTime = $StartTimeUtc
    endTime   = $EndTimeUtc
    filter    = $Filter
}

$body = $bodyObject | ConvertTo-Json -Compress -Depth 10

Write-Log "Effective StartTime: $StartTimeUtc"
Write-Log "Effective EndTime:   $EndTimeUtc"
Write-Log "Effective Filter:    $Filter"
Write-Log "Effective Limit:     $Limit"
Write-Log "Effective Fields:    *"
Write-Log "Querying cases from $casesUrl"

try {
    $resp = Invoke-RestMethod -Uri $casesUrl -Method POST -Headers @{
        "accept"        = "application/json"
        "content-type"  = "application/json"
        "authorization" = "Bearer $token"
    } -Body $body -ErrorAction Stop
}
catch {
    Write-Log "Cases API call failed: $_" "ERROR"

    if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
        Write-Log "HTTP Status: $([int]$_.Exception.Response.StatusCode)" "ERROR"
    }

    if ($_.ErrorDetails.Message) {
        Write-Log "API Error Detail: $($_.ErrorDetails.Message)" "ERROR"
    }

    $raw = Get-ErrorResponseBody -Exception $_.Exception
    if ($raw) {
        Write-Log "Raw response body:" "WARN"
        Write-Host $raw
    }

    Write-Log "Request body used:" "WARN"
    Write-Host $body

    exit 1
}

# =========================
# HANDLE RESPONSE
# =========================
if ($null -eq $resp) {
    Write-Log "API returned an empty response." "WARN"
    exit 0
}

$data = if ($resp.PSObject.Properties.Name -contains "rows" -and $resp.rows) {
    @($resp.rows)
}
elseif ($resp.PSObject.Properties.Name -contains "cases" -and $resp.cases) {
    @($resp.cases)
}
elseif ($resp.PSObject.Properties.Name -contains "data" -and $resp.data) {
    @($resp.data)
}
elseif ($resp -is [System.Collections.IEnumerable] -and $resp -isnot [string]) {
    @($resp)
}
else {
    @($resp)
}

$count = $data.Count

if ($count -eq 0) {
    Write-Log "No results returned." "WARN"
    exit 0
}

Write-Log "Retrieved $count row(s)." "SUCCESS"

# =========================
# EXPORT CSV
# =========================
$flat = $data | ForEach-Object { Flatten $_ }

$file = Join-Path $OutputPath ("ExabeamCases_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".csv")

try {
    $flat | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
    Write-Log "Exported to $file" "SUCCESS"
}
catch {
    Write-Log "CSV export failed: $_" "ERROR"
    exit 1
}
