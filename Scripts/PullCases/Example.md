# Exabeam Case Export Script

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

## Example One (Specific case stage)

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

```powershell
.\Export-ExabeamCases.ps1 `
    -BaseUrl "https://api.sa.exabeam.cloud" `
    -ClientId "YOUR_CLIENT_ID" `
    -ClientSecret "YOUR_CLIENT_SECRET" `
    -StartTime "2024-05-01T00:00:00Z" `
    -EndTime "2026-06-01T00:00:00Z" `
    -Filter 'NOT caseId:"__NO_MATCH__"' `
    -Limit 3000

---
