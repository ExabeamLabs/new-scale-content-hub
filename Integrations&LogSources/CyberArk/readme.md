# CyberArk/Idira ISPSS Audit → Webhook Forwarder <img width="161" height="60" alt="image" src="https://github.com/user-attachments/assets/abab539d-fa81-48ea-ab86-d12e3450673a" />

A PowerShell script that pulls audit events from **CyberArk Identity Security Platform Shared Services (ISPSS)** and forwards them to a webhook endpoint — such as an **Exabeam JSON webhook collector** — as individual JSON events.

Built to run as an **Azure Automation runbook** or a **Windows Scheduled Task**, with secrets pulled securely from Azure Automation variables or environment variables. Both of these work fine but it's worth being aware you can only run the Azure jobs once an hour.



---

## Why does this exist?

CyberArk's ISPSS Audit service doesn't push events to your SIEM. You have to pull them using a two-step API pattern (create a query → fetch results with a cursor). Exabeam's native collectors can't handle this pattern — they're stateless and can't chain API calls or remember where they left off between polls.

This script fills that gap. It handles everything:
- OAuth2 token acquisition from CyberArk Identity
- The createQuery → results cursor loop
- Remembering where it got to (cursor persistence across runs)
- Recovering automatically if the cursor expires
- Respecting CyberArk's 1-call-per-minute rate limit
- Forwarding each event to your webhook with retries

---

## Before you start — what you'll need

### From CyberArk (your CyberArk admin can help with this)

You need **5 values** from your CyberArk tenant. The table below tells you exactly where to find each one:

| # | Value | Where to find it |
|---|---|---|
| 1 | **Identity tenant URL** | Shown on the Export to SIEM page in CyberArk. Looks like `https://abc1234.id.cyberark.cloud` |
| 2 | **Application ID** | Identity Administration → Apps & Widgets → Web Apps → open the OAuth2 SIEM app → **Settings tab**. Copy it exactly — it's case-sensitive |
| 3 | **Service user login** | The dedicated service account created for this integration. Looks like `siemsvc@cyberark.cloud.1234` |
| 4 | **Client secret** | The service account's password — treat this like a password, never put it in the script |
| 5 | **Audit API base URL + API key** | CyberArk → Setup space → Export to SIEM → open your integration. The URL looks like `https://mycompany.audit.cyberark.cloud` and the API key is shown alongside it |

> ℹ️ If this is a brand new integration, your CyberArk admin will need to follow the [CyberArk SIEM integration setup guide](https://docs.cyberark.com/admin-space/latest/en/content/siem-integration/siem-export-3rd-party.htm) first. The key things they need to do are: create an OAuth2 Server web app with the `isp.audit.events:read` scope, add the Advanced-tab claims script, create a service user, and create a SIEM integration to get the API key.

### From your SIEM (Exabeam or similar)

| Value | Where to find it |
|---|---|
| **Webhook URL** | Create a new JSON webhook collector in Exabeam — it will give you a URL to POST events to |
| **Webhook bearer token** | Generated when you create the webhook collector in Exabeam |

---

## Setup

### Step 1 — Download the script

Save `CyberArkAuditEndpoint-ForwardAsWebhook.ps1` to a folder on your machine or upload it to Azure Automation as a runbook.

### Step 2 — Edit the configuration block

Open the script in any text editor (Notepad, VS Code, PowerShell ISE). Near the top you'll find the `$Config` block. **These are the only lines you need to change:**

```powershell
$Config = @{
    # --- CyberArk Identity (token) ---
    IdentityUrl  = 'https://abc1234.id.cyberark.cloud'         # 👈 CHANGE: your Identity tenant URL (value 1)
    AppId        = 'MySiemApp'                                  # 👈 CHANGE: your OAuth2 web app Application ID (value 2)
    ClientId     = 'siemsvc@cyberark.cloud.1234'               # 👈 CHANGE: your service user login name (value 3)
    Scope        = 'isp.audit.events:read'                      #    leave this as-is

    # --- CyberArk Audit API ---
    AuditBaseUrl = 'https://mycompany.audit.cyberark.cloud'     # 👈 CHANGE: your Audit API base URL (value 5 - URL part)

    # --- Webhook target ---
    WebhookUrl   = 'https://your-exabeam-collector.example.com/api/v1/events'  # 👈 CHANGE: your webhook URL

    # Everything below this line can stay as default
    ...
}
```

> ⚠️ **Never put your client secret, API key, or webhook token directly in the script.** These go in secrets storage — see Step 3.

### Step 3 — Store your secrets securely

The script needs 3 secrets at runtime. How you store them depends on where you're running the script:

#### Option A — Azure Automation

In your Azure Automation Account, go to **Shared Resources → Variables** and create three variables. **Tick "Encrypted" for each one.**

| Variable name | Value |
|---|---|
| `CYBERARK_CLIENT_SECRET` | Your CyberArk service user password (value 4) |
| `CYBERARK_API_KEY` | Your CyberArk API key (value 5 — the key part) |
| `WEBHOOK_BEARER_TOKEN` | Your webhook bearer token from Exabeam |

The script picks these up automatically via `Get-AutomationVariable` when running as a runbook.

#### Option B — Windows Scheduled Task

Run these commands **once** in PowerShell on the machine that will run the script (as the same account the task will run as):

```powershell
[Environment]::SetEnvironmentVariable('CYBERARK_CLIENT_SECRET', '<your client secret>', 'Machine')
[Environment]::SetEnvironmentVariable('CYBERARK_API_KEY', '<your api key>', 'Machine')
[Environment]::SetEnvironmentVariable('WEBHOOK_BEARER_TOKEN', '<your webhook token>', 'Machine')
```

Open a **new** PowerShell window after running these — environment variables only appear in new sessions.

### Step 4 — Test with a dry run

Before sending any real data to your SIEM, run the script with `-DryRun`. This pulls real events from CyberArk but **prints them to the console instead of posting to the webhook** — nothing gets sent anywhere.

```powershell
.\CyberArkAuditEndpoint-ForwardAsWebhook.ps1 -DryRun
```

A healthy run looks like this:

```
2026-01-15 09:00:01 [INFO] Requesting access token from https://abc1234.id.cyberark.cloud/OAuth2/Token/MySiemApp
2026-01-15 09:00:02 [INFO] Token acquired (expires_in=18000s, scope=isp.audit.events:read)
2026-01-15 09:00:02 [INFO] createQuery window: 2026-01-14T09:00:02 -> 2026-01-15T09:00:02 (UTC)
2026-01-15 09:01:05 [INFO] Received 298 events - forwarding to webhook.
[DRY RUN] Would POST to https://...: {"uuid":"...","applicationCode":"IDP",...}
...
2026-01-15 09:02:08 [INFO] No new events - caught up.
2026-01-15 09:02:08 [INFO] Run complete. API calls: 2, events forwarded: 298, events dropped: 0.
```

If you see errors instead, check the [Troubleshooting](#troubleshooting) section below.

> ℹ️ Dry runs **do** advance the saved cursor. This means when you go live, it will continue from where the dry run left off rather than re-sending everything. If you want the webhook to receive the full lookback window, run once with `-ResetCursor` before your first live run.

### Step 5 — Run it live

Once the dry run looks good, run without `-DryRun`:

```powershell
.\CyberArkAuditEndpoint-ForwardAsWebhook.ps1
```

Check your SIEM to confirm events are arriving.

### Step 6 — Schedule it

#### Azure Automation

Link the runbook to a **Schedule** in your Automation Account. Every 5 minutes is recommended.

#### Windows Scheduled Task

Create a task with these settings:

| Setting | Value |
|---|---|
| Program | `powershell.exe` |
| Arguments | `-NoProfile -ExecutionPolicy Bypass -File "C:\Path\To\CyberArkAuditEndpoint-ForwardAsWebhook.ps1"` |
| Run as | The service account (the one whose environment variables you set in Step 3) |
| Trigger | Every 5 minutes |
| Start in | The folder containing the script |

---

## Commands reference

| Command | What it does |
|---|---|
| `.\CyberArkAuditEndpoint-ForwardAsWebhook.ps1` | Normal run — pulls events and posts to webhook |
| `.\CyberArkAuditEndpoint-ForwardAsWebhook.ps1 -DryRun` | Pulls events, prints them, doesn't post anything |
| `.\CyberArkAuditEndpoint-ForwardAsWebhook.ps1 -ResetCursor` | Forgets saved position and starts fresh from the lookback window |

---

## What gets created alongside the script

The script creates three files automatically in the same folder as the script:

| File | Purpose | What to look for |
|---|---|---|
| `CyberArkAuditSync.state.json` | Remembers where the script got to — the cursor and timestamp of the last event forwarded | If `lastRunUtc` is hours old, the scheduled task has stopped |
| `CyberArkAuditSync_YYYYMMDD.log` | Daily log file with INFO/WARN/ERROR entries | Any ERROR lines or repeated WARN about cursor rebuilds |
| `CyberArkAuditSync.lock` | Prevents two copies running at the same time | If it persists while nothing is running, a previous run died hard — safe to delete |

> Add these to your `.gitignore` — they accumulate real usernames and timestamps at runtime and shouldn't go into source control:
> ```
> *.state.json
> *.log
> *.lock
> ```

---

## Configuration reference

All settings are in the `$Config` block. Most defaults are fine — here's what everything does:

| Setting | Default | Description |
|---|---|---|
| `IdentityUrl` | — | Your CyberArk Identity tenant URL |
| `AppId` | — | OAuth2 web app Application ID — case-sensitive |
| `ClientId` | — | Service user login name |
| `Scope` | `isp.audit.events:read` | Don't change this |
| `AuditBaseUrl` | — | Audit API base URL from the Export to SIEM page |
| `PageSize` | `500` | Events fetched per API call. 500 is the maximum |
| `WebhookUrl` | — | Your webhook endpoint URL |
| `WebhookTimeoutSec` | `30` | Seconds to wait for the webhook to respond |
| `WebhookRetries` | `3` | How many times to retry a failed webhook call before giving up |
| `WebhookRetryDelaySeconds` | `5` | Seconds to wait between retries |
| `LookbackHours` | `24` | How far back to pull events on first run. Max useful value is 168 (7 days) |
| `OverlapMinutes` | `5` | Re-reads the last 5 minutes when recovering from a lost cursor — avoids gaps |
| `MaxApiCallsPerRun` | `5` | Maximum CyberArk API calls per run (1 create + 4 result pages = up to 2,000 events) |
| `ApiCallSpacingSeconds` | `61` | Pause between API calls. Keep this at 61 or above — CyberArk enforces 1 call/minute |

---

## Troubleshooting

| Error message | What it means | Fix |
|---|---|---|
| `Required secret '...' not found` | The secret isn't set in Azure Automation variables or environment variables | Add the missing variable (see Step 3) |
| `invalid_request / unknown app <name>` | The Application ID in the script doesn't match what's in CyberArk | Check the Settings tab of the web app — copy the Application ID exactly, it's case-sensitive |
| `invalid_grant / invalid grant type` | Token request is malformed or the web app doesn't have Client Creds enabled | Check the web app's Tokens tab — Client Creds must be ticked |
| `401 Unauthorized` from the Audit API | The token was issued by the wrong endpoint or the web app is missing its Advanced-tab claims script | Ask your CyberArk admin to verify the Advanced tab has the `setClaim` lines saved |
| `403 Forbidden` from the Audit API | Wrong API key, or the service user doesn't have the right permissions on the web app | Check the API key matches the one on the Export to SIEM page; check the service user has Grant/View/Run/Automatically Deploy |
| `400` on results call | Cursor has expired | The script auto-recovers on the next run — no action needed |
| Webhook retries failing | Webhook endpoint is unreachable or rejecting requests | Verify the webhook URL and bearer token; check Exabeam collector is running |
| `Lock file present` warning | Another run is already in progress, or a previous run crashed | Wait 30 minutes for auto-recovery, or delete the `.lock` file manually if nothing is running |

---

## Event format

Each event arrives at your webhook as a JSON POST — one event per request. Here's an example of what the payload looks like:

```json
{
  "uuid": "ad603d51-87a5-4267-8293-7fe279e0accf",
  "timestamp": 1781181462820,
  "username": "user@example.com",
  "applicationCode": "IDP",
  "auditCode": "IDP2009",
  "auditType": "Info",
  "action": "OAuth token creation",
  "actionType": "Create",
  "source": "203.0.113.10",
  "component": "Identity",
  "serviceName": "Identity",
  "identityType": "HUMAN",
  "isDr": false,
  "originRegion": "eu-west-2",
  "customData": {
    "browser_name": "MicrosoftEdge",
    "device_os": "Windows",
    "geoip_city_name": "London",
    "geoip_country_name": "United Kingdom"
  }
}
```

Key fields for SIEM parsing: `uuid` (deduplicate on this), `timestamp` (milliseconds), `username`, `source` (IP address), `applicationCode` (which CyberArk service), `auditCode`, `auditType`, `action`, `actionType`.

---

## Licence

Add your licence here before publishing.
