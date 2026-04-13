<#
.SYNOPSIS
    Bulk update Exabeam Threat Center cases from a CSV file.

.DESCRIPTION
    Reads a CSV file, extracts case IDs from a specified column, authenticates
    to the Exabeam API using OAuth2 client credentials, and updates each case
    individually using:

        POST /threat-center/v2/cases/{caseId}

    Default update action:
    - stage            = CLOSED
    - closedReason     = Other
    - supportingReason = Bulk update

.PARAMETER BaseUrl
    Exabeam API base URL.
    Example:
      https://api.sa.exabeam.cloud
      https://api.us-west.exabeam.cloud

.PARAMETER ClientId
    Exabeam API client ID.

.PARAMETER ClientSecret
    Exabeam API client secret.

.PARAMETER CsvPath
    Path to the source CSV file.

.PARAMETER CaseIdColumn
    CSV column containing the case IDs.
    Default: caseId

.PARAMETER Stage
    Target case stage.
    Default: CLOSED

.PARAMETER ClosedReason
    Closed reason enum value.
    Default: Other

.PARAMETER SupportingReason
    Supporting reason text.
    Default: Bulk update

.PARAMETER DelayMilliseconds
    Optional delay between requests.
    Default: 0

.PARAMETER ShowJwtPayload
    Decodes and prints the JWT payload for troubleshooting.

.PARAMETER OutputPath
    Optional folder for the results CSV.
    Defaults to the input CSV folder.

.EXAMPLE
    .\Update-ExabeamCasesFromCsv.ps1 `
        -BaseUrl "https://api.sa.exabeam.cloud" `
        -ClientId "YOUR_CLIENT_ID" `
        -ClientSecret "YOUR_CLIENT_SECRET" `
        -CsvPath ".\ExabeamCases_20260409_112640.csv"

.EXAMPLE
    .\Update-ExabeamCasesFromCsv.ps1 `
        -BaseUrl "https://api.sa.exabeam.cloud" `
        -ClientId "YOUR_CLIENT_ID" `
        -ClientSecret "YOUR_CLIENT_SECRET" `
        -CsvPath ".\ExabeamCases_20260409_112640.csv" `
        -WhatIf
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$BaseUrl,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ClientId,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ClientSecret,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$CsvPath,

    [ValidateNotNullOrEmpty()]
    [string]$CaseIdColumn = "caseId",

    [ValidateNotNullOrEmpty()]
    [string]$Stage = "CLOSED",

    [ValidateNotNullOrEmpty()]
    [string]$ClosedReason = "Other",

    [ValidateNotNullOrEmpty()]
    [string]$SupportingReason = "Bulk update",

    [ValidateRange(0, 60000)]
    [int]$DelayMilliseconds = 0,

    [string]$OutputPath,

    [switch]$ShowJwtPayload
)

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("INFO","SUCCESS","WARN","ERROR")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $colour = switch ($Level) {
        "INFO"    { "Cyan" }
        "SUCCESS" { "Green" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colour
}

function Decode-JwtPayload {
    param(
        [Parameter(Mandatory)]
        [string]$Token
    )

    try {
        $parts = $Token -split '\.'
        if ($parts.Count -lt 2) {
            throw "JWT did not contain enough segments."
        }

        $payload = $parts[1].Replace('-', '+').Replace('_', '/')

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
        Write-Log "Failed to decode JWT payload: $_" "WARN"
        return $null
    }
}

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

function New-ResultsObject {
    param(
        [string]$CaseId,
        [string]$Result,
        [string]$Message
    )

    [PSCustomObject]@{
        timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        caseId    = $CaseId
        result    = $Result
        message   = $Message
    }
}

# Validate input CSV
if (-not (Test-Path -Path $CsvPath)) {
    Write-Log "CSV file not found: $CsvPath" "ERROR"
    exit 1
}

try {
    $resolvedCsvPath = (Resolve-Path -Path $CsvPath).Path
}
catch {
    Write-Log "Failed to resolve CSV path: $_" "ERROR"
    exit 1
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Split-Path -Path $resolvedCsvPath -Parent
}

if (-not (Test-Path -Path $OutputPath)) {
    try {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    catch {
        Write-Log "Failed to create output directory '$OutputPath': $_" "ERROR"
        exit 1
    }
}

# Load CSV
try {
    $csvRows = Import-Csv -Path $resolvedCsvPath
}
catch {
    Write-Log "Failed to import CSV: $_" "ERROR"
    exit 1
}

if (-not $csvRows -or $csvRows.Count -eq 0) {
    Write-Log "CSV contains no rows." "ERROR"
    exit 1
}

$firstRow = $csvRows | Select-Object -First 1
$availableColumns = @($firstRow.PSObject.Properties.Name)

if ($availableColumns -notcontains $CaseIdColumn) {
    Write-Log "Column '$CaseIdColumn' was not found in the CSV." "ERROR"
    Write-Log "Available columns: $($availableColumns -join ', ')" "ERROR"
    exit 1
}

# Extract and normalise case IDs
$caseIds = $csvRows |
    ForEach-Object { $_.$CaseIdColumn } |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    ForEach-Object { $_.ToString().Trim() } |
    Select-Object -Unique

if (-not $caseIds -or $caseIds.Count -eq 0) {
    Write-Log "No usable case IDs were found in column '$CaseIdColumn'." "ERROR"
    exit 1
}

Write-Log "CSV loaded from: $resolvedCsvPath"
Write-Log "Total CSV rows: $($csvRows.Count)"
Write-Log "Unique case IDs found: $($caseIds.Count)"

# Authenticate
$tokenUrl = "$BaseUrl/auth/v1/token"

$tokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
} | ConvertTo-Json -Compress

Write-Log "Requesting access token from $tokenUrl"

try {
    $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method POST `
        -Headers @{
            "accept"       = "application/json"
            "content-type" = "application/json"
        } `
        -Body $tokenBody `
        -ErrorAction Stop

    $accessToken = $tokenResponse.access_token

    if (-not $accessToken) {
        throw "Token response did not include access_token."
    }

    Write-Log "Access token obtained successfully." "SUCCESS"
}
catch {
    Write-Log "Authentication failed: $_" "ERROR"

    if ($_.ErrorDetails.Message) {
        Write-Log "API Error Detail: $($_.ErrorDetails.Message)" "ERROR"
    }

    $rawAuthBody = Get-ErrorResponseBody -Exception $_.Exception
    if ($rawAuthBody) {
        Write-Log "Raw authentication response body:" "WARN"
        Write-Host $rawAuthBody
    }

    exit 1
}

if ($ShowJwtPayload) {
    $jwtPayload = Decode-JwtPayload -Token $accessToken
    if ($jwtPayload) {
        Write-Log "Decoded JWT payload:"
        $jwtPayload | ConvertTo-Json -Depth 10 | Write-Host
    }
}

$headers = @{
    "accept"        = "application/json"
    "content-type"  = "application/json"
    "authorization" = "Bearer $accessToken"
}

# Prepare results tracking
$results = New-Object System.Collections.Generic.List[object]
$successCount = 0
$failCount = 0
$skippedCount = 0
$totalCount = $caseIds.Count
$current = 0

Write-Log "Starting update run. Target stage='$Stage', closedReason='$ClosedReason', supportingReason='$SupportingReason'."

foreach ($caseId in $caseIds) {
    $current++

    $caseUrl = "$BaseUrl/threat-center/v2/cases/$caseId"

    $bodyObject = @{
        stage            = $Stage
        closedReason     = $ClosedReason
        supportingReason = $SupportingReason
    }

    $bodyJson = $bodyObject | ConvertTo-Json -Compress -Depth 10

    Write-Log "[$current/$totalCount] Processing caseId '$caseId'..."

    if (-not $PSCmdlet.ShouldProcess($caseId, "Update Exabeam case")) {
        $skippedCount++
        $results.Add((New-ResultsObject -CaseId $caseId -Result "Skipped" -Message "Skipped by WhatIf/ShouldProcess"))
        continue
    }

    try {
        $null = Invoke-RestMethod -Uri $caseUrl -Method POST `
            -Headers $headers `
            -Body $bodyJson `
            -ErrorAction Stop

        $successCount++
        $results.Add((New-ResultsObject -CaseId $caseId -Result "Success" -Message "Updated successfully"))
        Write-Log "Updated caseId '$caseId' successfully." "SUCCESS"
    }
    catch {
        $failCount++

        $apiMessage = $null

        if ($_.ErrorDetails.Message) {
            $apiMessage = $_.ErrorDetails.Message
        }

        $rawBody = Get-ErrorResponseBody -Exception $_.Exception
        if (-not $apiMessage -and $rawBody) {
            $apiMessage = $rawBody
        }

        if (-not $apiMessage) {
            $apiMessage = "$_"
        }

        $results.Add((New-ResultsObject -CaseId $caseId -Result "Failed" -Message $apiMessage))

        Write-Log "Failed to update caseId '$caseId'." "ERROR"
        Write-Log $apiMessage "ERROR"
    }

    if ($DelayMilliseconds -gt 0) {
        Start-Sleep -Milliseconds $DelayMilliseconds
    }
}

# Export run results
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$resultsPath = Join-Path -Path $OutputPath -ChildPath "ExabeamCaseUpdateResults_$timestamp.csv"

try {
    $results | Export-Csv -Path $resultsPath -NoTypeInformation -Encoding UTF8
    Write-Log "Result log exported to: $resultsPath" "SUCCESS"
}
catch {
    Write-Log "Failed to export result log: $_" "ERROR"
}

Write-Log "Run complete. Success=$successCount Failed=$failCount Skipped=$skippedCount Total=$totalCount" "INFO"
