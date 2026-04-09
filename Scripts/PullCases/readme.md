Exabeam Threat Center Case Export (PowerShell)

Export Exabeam Threat Center cases to CSV using the official API.

This script authenticates using OAuth2 (client credentials), queries cases from the Threat Center API, and exports results in a flattened, CSV-friendly format.

Features

OAuth2 client credential authentication
Supports all Exabeam cloud regions
Handles API response formats (rows, cases, data)
Automatically converts timestamps to UTC (Z)
Exports clean, flattened CSV
Debug mode for JWT inspection
Full error handling (including raw API responses)
API References
https://developers.exabeam.com/exabeam/reference/get-access-token
https://developers.exabeam.com/exabeam/reference/threat-center-search-cases

These are the official Exabeam API docs used to build this script.

Regions / Base URLs

Your API base URL must match your tenant region.

If it does not, you will see errors such as:

Audiences in Jwt are not allowed
Common API Base URLs
Region	Base URL
US West	https://api.us-west.exabeam.cloud

US East	https://api.use1.exabeam.cloud

Europe	https://api.eu.exabeam.cloud

UK	https://api.uk.exabeam.cloud

Switzerland	https://api.euw6.exabeam.cloud

Canada	https://api.ca.exabeam.cloud

Australia	https://api.au.exabeam.cloud

Japan	https://api.jp.exabeam.cloud

Singapore	https://api.sg.exabeam.cloud

Saudi Arabia	https://api.sa.exabeam.cloud

Your region typically matches your tenant URL.

Authentication

This script uses OAuth2 Client Credentials flow.

Example request:

      POST /auth/v1/token
      {
        "client_id": "...",
        "client_secret": "...",
        "grant_type": "client_credentials"
      }
      Important: fields Parameter
      
      The fields parameter is required.
      
      If it is omitted, the API will return empty objects:
      
      "rows": [
        {},
        {}
      ]

Correct usage:

"fields": ["*"]

Example Usage

    .\Export-ExabeamCases.ps1 `
        -BaseUrl "https://api.sa.exabeam.cloud" `
        -ClientId "YOUR_CLIENT_ID" `
        -ClientSecret "YOUR_CLIENT_SECRET" `
        -StartTime "2026-04-01T00:00:00Z" `
        -EndTime "2026-04-10T00:00:00Z" `
        -Filter 'NOT stage:"CLOSED"' `
        -ShowJwtPayload
    
Example API Request

    POST /threat-center/v1/search/cases
    
    {
      "fields": ["*"],
      "limit": 10,
      "startTime": "2026-04-01T00:00:00Z",
      "endTime": "2026-04-10T00:00:00Z",
      "filter": "NOT stage:\"CLOSED\""
    }

Output

CSV file generated in the current directory (or -OutputPath)
File naming format:
ExabeamCases_YYYYMMDD_HHMMSS.csv
Nested objects are flattened for CSV compatibility
