<#
.SYNOPSIS
    Export Exabeam Threat Center cases to CSV.

.DESCRIPTION
    Authenticates via OAuth2 client credentials, queries the Exabeam
    Threat Center Search Cases API, and exports results to CSV.

.NOTES
    IMPORTANT: Rotate your API secret if it has been exposed.
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

    [string]$Filter = 'NOT stage:"CLOSED"',

    [int]$Limit = 30000,

    [string]$OutputPath = (Get-Location).Path,

    [switch]$ShowJwtPayload
)

# =========================
# Logging
# =========================
function Write-Log {
    param($Message, $Level = "INFO")

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO"    { "Cyan" }
        "SUCCESS" { "Green" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
    }

    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $color
}

# =========================
# Ensure UTC Z format
# =========================
function To-UtcZ {
    param($dt)

    if ($dt -match 'Z$') { return $dt }

    return ([datetime]::Parse($dt)).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

# =========================
# Decode JWT (debug only)
# =========================
function Decode-JWT {
    param($token)

    try {
        $payload = $token.Split('.')[1]
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
        Write-Log "JWT decode failed" "WARN"
    }
}

# =========================
# Flatten object for CSV
# =========================
function Flatten {
    param($obj)

    $row = [ordered]@{}

    foreach ($p in $obj.PSObject.Properties) {
        if ($p.Value -is [System.Collections.IEnumerable] -and $p.Value -isnot [string]) {
            $row[$p.Name] = ($p.Value | ConvertTo-Json -Compress)
        }
        elseif ($p.Value -is [PSCustomObject]) {
            $row[$p.Name] = ($p.Value | ConvertTo-Json -Compress)
        }
        else {
            $row[$p.Name] = $p.Value
        }
    }

    [PSCustomObject]$row
}

# =========================
# Prep
# =========================
$StartTime = To-UtcZ $StartTime
$EndTime   = To-UtcZ $EndTime

if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
}

# =========================
# AUTH
# =========================
$tokenUrl = "$BaseUrl/auth/v1/token"

Write-Log "Requesting token..."

$tokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
} | ConvertTo-Json -Compress

try {
    $tokenResp = Invoke-RestMethod -Uri $tokenUrl -Method POST -Headers @{
        "accept"       = "application/json"
        "content-type" = "application/json"
    } -Body $tokenBody

    $token = $tokenResp.access_token
    Write-Log "Token acquired" "SUCCESS"
}
catch {
    Write-Log "Auth failed: $_" "ERROR"
    exit
}

if ($ShowJwtPayload) {
    Decode-JWT $token | ConvertTo-Json -Depth 5 | Write-Host
}

# =========================
# SEARCH CASES
# =========================
$casesUrl = "$BaseUrl/threat-center/v1/search/cases"

$body = @{
    fields    = @("*")   # <-- CRITICAL FIX
    limit     = $Limit
    startTime = $StartTime
    endTime   = $EndTime
    filter    = $Filter
} | ConvertTo-Json -Compress

Write-Log "Querying cases..."

try {
    $resp = Invoke-RestMethod -Uri $casesUrl -Method POST -Headers @{
        "accept"        = "application/json"
        "content-type"  = "application/json"
        "authorization" = "Bearer $token"
    } -Body $body
}
catch {
    Write-Log "API FAILED" "ERROR"

    if ($_.ErrorDetails.Message) {
        Write-Log $_.ErrorDetails.Message "ERROR"
    }

    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $bodyErr = $reader.ReadToEnd()
        Write-Host $bodyErr
    }

    exit
}

# =========================
# HANDLE RESPONSE
# =========================
if ($resp.rows) {
    $data = $resp.rows
}
else {
    $data = $resp
}

$count = $data.Count

if ($count -eq 0) {
    Write-Log "No results returned" "WARN"
    exit
}

Write-Log "Retrieved $count rows" "SUCCESS"

# =========================
# EXPORT CSV
# =========================
$flat = $data | ForEach-Object { Flatten $_ }

$file = Join-Path $OutputPath ("ExabeamCases_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".csv")

$flat | Export-Csv $file -NoTypeInformation -Encoding UTF8

Write-Log "Exported to $file" "SUCCESS"
