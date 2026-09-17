# ============================================================================
# Exabeam DAA Automated Installation via Powershell
# ============================================================================

$ErrorActionPreference = "Continue"

# ----------------------------------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------------------------------

# Supported Regions:
# us-west
# us-east
# ca
# eu
# sa
# sg
# ch
# jp
# au

$Region = "<Region>"

$ClientId = "<Client_ID>"
$ClientSecret = "<Client_Secret>"

$CoreId = "<Collector_ID>"

$TemplateIds = @(
    "<Collector_Template_ID>"
)

$StartLogDate = "2026-09-01T00:00:00Z"

$WorkDir = "C:\Temp\ExabeamDAA"

# ----------------------------------------------------------------------------
# BUILD REGION-BASED API URLS
# ----------------------------------------------------------------------------

$ApiBaseUrl = "https://api.$Region.exabeam.cloud"

$AuthUrl = "$ApiBaseUrl/auth/v1/token"

$InstallCommandUrl = "$ApiBaseUrl/site-collectors/v1/collectors/commands/daa/installation"

# ----------------------------------------------------------------------------
# CREATE WORK DIRECTORY
# ----------------------------------------------------------------------------

if (!(Test-Path $WorkDir))
{
    New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
}

Set-Location $WorkDir

# ----------------------------------------------------------------------------
# AUTHENTICATE
# ----------------------------------------------------------------------------

Write-Host "Getting OAuth token..."

$AuthHeaders = @{
    "accept" = "application/json"
    "content-type" = "application/json"
}

$AuthBody = @{
    grant_type = "client_credentials"
    client_id = $ClientId
    client_secret = $ClientSecret
} | ConvertTo-Json -Compress

$TokenResponse = Invoke-RestMethod `
    -Uri $AuthUrl `
    -Method POST `
    -Headers $AuthHeaders `
    -ContentType "application/json" `
    -Body $AuthBody

$BearerToken = $TokenResponse.access_token

if (-not $BearerToken)
{
    throw "Failed to obtain OAuth token."
}

Write-Host "Token acquired."

# ----------------------------------------------------------------------------
# GENERATE INSTALL COMMAND
# ----------------------------------------------------------------------------

Write-Host "Requesting DAA installation command..."

$CommandHeaders = @{
    "accept" = "application/json"
    "content-type" = "application/json"
    "authorization" = "Bearer $BearerToken"
}

$CommandBody = @{
    type = "DaaWindows"
    coreId = $CoreId
    templateIds = $TemplateIds
    startLogDate = $StartLogDate
} | ConvertTo-Json -Depth 5 -Compress

$CommandResponse = Invoke-RestMethod `
    -Uri $InstallCommandUrl `
    -Method POST `
    -Headers $CommandHeaders `
    -ContentType "application/json" `
    -Body $CommandBody

if (-not $CommandResponse.command)
{
    throw "No installation command returned."
}

# ----------------------------------------------------------------------------
# DECODE COMMAND
# ----------------------------------------------------------------------------

Write-Host "Decoding installation command..."

$DecodedCommand = [System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String($CommandResponse.command)
)

Write-Host ""
Write-Host "=========== DECODED COMMAND ==========="
Write-Host $DecodedCommand
Write-Host "======================================="
Write-Host ""

# Optional troubleshooting file
$DecodedCommand | Out-File `
    -FilePath "$WorkDir\DecodedCommand.txt" `
    -Encoding UTF8 `
    -Force

# ----------------------------------------------------------------------------
# EXECUTE STEP-BY-STEP
# ----------------------------------------------------------------------------

$Commands = $DecodedCommand -split ';'

foreach ($Command in $Commands)
{
    $Command = $Command.Trim()

    Write-Host ""
    Write-Host "Executing:"
    Write-Host $Command
    Write-Host ""

    Invoke-Expression $Command
}

# ----------------------------------------------------------------------------
# VERIFY INSTALLATION
# ----------------------------------------------------------------------------

if (Test-Path ".\daacli.exe")
{
    Write-Host ""
    Write-Host "Collector Status"
    Write-Host "================"

    & ".\daacli.exe" status
}
else
{
    Write-Warning "daacli.exe was not found after installation."
}

Write-Host ""
Write-Host "Installation complete."
