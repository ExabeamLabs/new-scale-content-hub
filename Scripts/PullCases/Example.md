Download, or copy and paste the contents of the ps1 file and save on your system (any system it's over cloud API). Make sure you replace the base url with your region, adjust the dates to whatever you need. It will export a CSV within whatever folder you ran it from. If you find you are getting exactly 3000 rows back then you likely need to increase the limit or break it down into different type ranges/runs. 

<img width="363" height="335" alt="image" src="https://github.com/user-attachments/assets/e994867a-5956-4256-b6f3-4815b2151c00" />

Example One (One specific case stage)

.\Export-ExabeamCases.ps1 `
    -BaseUrl "https://api.sa.exabeam.cloud" `
    -ClientId "YOUR_CLIENT_ID" `
    -ClientSecret "YOUR_CLIENT_SECRET" `
    -StartTime "2025-01-01T00:00:00Z" `
    -EndTime "2026-04-30T23:59:59Z" `
    -Filter 'NOT stage:"CLOSED"' `
    -Limit 3000

Example Two (Just pull all cases within the time filter)

.\Export-ExabeamCases.ps1 `
    -BaseUrl "https://api.sa.exabeam.cloud" `
    -ClientId "YOUR_CLIENT_ID" `
    -ClientSecret "YOUR_CLIENT_SECRET" `
    -StartTime "2024-05-01T00:00:00Z" `
    -EndTime "2026-06-01T00:00:00Z" `
    -Filter 'NOT caseId:"__NO_MATCH__"'
    -Limit 3000
