# Exabeam Case Export Script & Bulk Case Status Update (Below)

Download or copy the contents of the `.ps1` file and save it locally (any system that can reach the Exabeam cloud API).

## Usage Notes

- Replace the base URL with your region
- Adjust the date range as required
- The script will export a CSV to the folder you run it from
- If you receive exactly 3000 rows, increase the limit or split the query into smaller time ranges

---

## Regions / Base URLs

Ensure the Base URL matches your tenant region.

Common examples:

- https://api.us-west.exabeam.cloud
- https://api.us-east.exabeam.cloud
- https://api.eu.exabeam.cloud
- https://api.uk.exabeam.cloud
- https://api.ca.exabeam.cloud
- https://api.au.exabeam.cloud
- https://api.jp.exabeam.cloud
- https://api.sg.exabeam.cloud
- https://api.sa.exabeam.cloud
- https://api.ch.exabeam.cloud

---

## Examples
```powershell

## Example One (Pull Cases With Specific Status)

.\Export-ExabeamCases.ps1 `
    -BaseUrl "https://api.sa.exabeam.cloud" `
    -ClientId "YOUR_CLIENT_ID" `
    -ClientSecret "YOUR_CLIENT_SECRET" `
    -StartTime "2025-01-01T00:00:00Z" `
    -EndTime "2026-04-30T23:59:59Z" `
    -Filter 'NOT stage:"CLOSED"' `
    -Limit 3000

---
    
## Example Two (Pull All Cases Any Status)

.\Export-ExabeamCases.ps1 `
    -BaseUrl "https://api.sa.exabeam.cloud" `
    -ClientId "YOUR_CLIENT_ID" `
    -ClientSecret "YOUR_CLIENT_SECRET" `
    -StartTime "2024-05-01T00:00:00Z" `
    -EndTime "2026-06-01T00:00:00Z" `
    -Filter 'NOT caseId:"__NO_MATCH__"' `
    -Limit 3000

---

To use the bulk update script you just need to complete the first pull cases script, and either use the filters to have that
just return the cases you want to close - Or manually do some filtering in Excel/CSV to only keep the rows and most importantly
caseID that you want to bulk change the status of. Point the second script (bulk update) at that CSV via the switch you can 
see below for -CsvPath . 

PS C:\Projects\Export-ExabeamCases> .\Export-ExabeamCases.ps1 `
    -BaseUrl "https://api.sa.exabeam.cloud" `
    -ClientId "XYZ" `
    -ClientSecret "123" `
    -StartTime "2026-04-13T00:00:00Z" `
    -EndTime "2026-04-13T23:59:59Z" `
    -Filter 'NOT stage:"CLOSED"' `
    -Limit 2
    
[2026-04-13 09:36:42] [INFO] Requesting access token from https://api.sa.exabeam.cloud/auth/v1/token
[2026-04-13 09:36:42] [SUCCESS] Access token obtained successfully.
[2026-04-13 09:36:42] [INFO] Effective StartTime: 2026-04-13T00:00:00Z
[2026-04-13 09:36:42] [INFO] Effective EndTime:   2026-04-13T23:59:59Z
[2026-04-13 09:36:42] [INFO] Effective Filter:    NOT stage:"CLOSED"
[2026-04-13 09:36:42] [INFO] Effective Limit:     2
[2026-04-13 09:36:42] [INFO] Effective Fields:    *
[2026-04-13 09:36:42] [INFO] Querying cases from https://api.sa.exabeam.cloud/threat-center/v1/search/cases
[2026-04-13 09:36:44] [SUCCESS] Retrieved  row(s).
[2026-04-13 09:36:44] [SUCCESS] Exported to C:\Projects\Export-ExabeamCases\ExabeamCases_20260413_093644.csv

PS C:\Projects\Export-ExabeamCases> .\ChangeCaseStatus-BulkScript.ps1 `
    -BaseUrl "https://api.sa.exabeam.cloud" `
    -ClientId "XYZ" `
    -ClientSecret "123" `
    -CsvPath ".\ExabeamCases_20260413_093644.csv"

[2026-04-13 09:40:01] [INFO] CSV loaded from: C:\Projects\Export-ExabeamCases\ExabeamCases_20260413_093644.csv
[2026-04-13 09:40:01] [INFO] Total CSV rows: 
[2026-04-13 09:40:01] [INFO] Unique case IDs found: 1
[2026-04-13 09:40:01] [INFO] Requesting access token from https://api.sa.exabeam.cloud/auth/v1/token
[2026-04-13 09:40:02] [SUCCESS] Access token obtained successfully.
[2026-04-13 09:40:02] [INFO] Starting update run. Target stage='CLOSED', closedReason='Other', supportingReason='Bulk update'.
[2026-04-13 09:40:02] [INFO] [1/1] Processing caseId 'c2e7af6e-4343-4e44-9ece-10fd73964cec'...
[2026-04-13 09:40:04] [SUCCESS] Updated caseId 'c2e7af6e-4343-4e44-9ece-10fd73964cec' successfully.
[2026-04-13 09:40:04] [SUCCESS] Result log exported to: C:\Projects\Export-ExabeamCases\ExabeamCaseUpdateResults_20260413_094004.csv
[2026-04-13 09:40:04] [INFO] Run complete. Success=1 Failed=0 Skipped=0 Total=1
