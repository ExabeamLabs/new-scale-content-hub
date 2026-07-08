# CyberArk ISPSS Audit → Webhook Forwarder

A PowerShell script that pulls audit events from **CyberArk Identity Security Platform Shared Services (ISPSS)** and forwards them to a webhook endpoint — such as an **Exabeam JSON webhook collector** — as individual JSON events.

Built to run as an **Azure Automation runbook on a Hybrid Runbook Worker**, with secrets pulled securely from Azure Automation variables.

> 📸 *Screenshots coming soon*

---

## Why does this exist?

CyberArk's ISPSS Audit service doesn't push events to your SIEM. You have to pull them using a two-step API pattern (create a query → fetch results with a cursor). Exabeam's native collectors can't handle this pattern — they're stateless and can't chain API calls or remember where they left off between polls.

This script fills that gap. It handles everything:
- OAuth2 token acquisition from CyberArk Identity
- The createQuery → results cursor loop
- Remembering where it got to (cursor persistence across runs, stored on the Hybrid Worker's local disk)
- Automatically recovering if the cursor expires or is exhausted
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

Upload `CyberArkAuditEndpoint-ForwardAsWebhook.ps1` to Azure Automation as a runbook.

### Step 2 — Edit the configuration block

Open the script. Near the top you'll find the `$Config` block. **These are the only lines you need to change:**

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

    # Everything below this line can stay as default unless told otherwise
    ...
}
```

> ⚠️ **Never put your client secret, API key, or webhook token directly in the script.** These go in Azure Automation variables — see Step 3.

### Step 3 — Store your secrets securely

In your Azure Automation Account, go to **Shared Resources → Variables** and create three variables. **Tick "Encrypted" for each one.**

| Variable name | Value |
|---|---|
| `CYBERARK_CLIENT_SECRET` | Your CyberArk service user password (value 4) |
| `CYBERARK_API_KEY` | Your CyberArk API key (value 5 — the key part) |
| `WEBHOOK_BEARER_TOKEN` | Your webhook bearer token from Exabeam |

The script picks these up automatically via `Get-AutomationVariable` when running as a runbook.

### Step 4 — Confirm Hybrid Worker is set

> ⚠️ **This is the most important setting.** Without it, the script will not retain its position between runs.

In Azure Automation, open your runbook and confirm **Run on** is set to your **Hybrid Worker Group** — not Azure. The script relies on the Hybrid Worker's local disk to save its position (the cursor) between executions. If it runs in a standard Azure sandbox, the disk is wiped between jobs and the script will re-pull the same events every time.

### Step 5 — Test with a dry run

Before sending any real data to your SIEM, run the script with `-DryRun`. This pulls real events from CyberArk but **prints them to the console instead of posting to the webhook** — nothing gets sent anywhere.

```powershell
.\CyberArkAuditEndpoint-ForwardAsWebhook.ps1 -DryRun
```

A healthy first run looks like this:

```
2026-01-15 09:00:01 [INFO] Requesting access token from https://abc1234.id.cyberark.cloud/OAuth2/Token/MySiemApp
2026-01-15 09:00:02 [INFO] Token acquired (expires_in=18000s, scope=isp.audit.events:read)
2026-01-15 09:00:02 [INFO] createQuery window: 2026-01-14T09:00:02 -> 2026-01-15T09:00:02 (UTC)
2026-01-15 09:01:05 [INFO] Received 298 events - forwarding to webhook.
[DRY RUN] Would POST to https://...: {"uuid":"...","applicationCode":"IDP",...}
...
2026-01-15 09:02:08 [INFO] No new events - caught up. Clearing cursor so next run creates a fresh query from lastEventEpoch.
2026-01-15 09:02:08 [INFO] Run complete. API calls: 2, events forwarded: 298, events dropped: 0.
```

On the **second run**, you should see this line confirming position is being retained:

```
2026-01-15 09:05:01 [INFO] Resuming from persisted cursor.
```

If you see a fresh `createQuery window` line on every run instead, the runbook is not running on the Hybrid Worker — check Step 4.

If you see errors, check the [Troubleshooting](#troubleshooting) section below.

> ℹ️ Dry runs **do** advance the saved cursor. If you want the webhook to receive the full lookback window on the first live run, run once with `-ResetCursor` before going live.

### Step 6 — Run it live

Once the dry run looks good:

```powershell
.\CyberArkAuditEndpoint-ForwardAsWebhook.ps1
```

Check your SIEM to confirm events are arriving.

### Step 7 — Schedule it

Link the runbook to a **Schedule** in your Azure Automation Account. Every **5 minutes** is recommended.

---

## Commands reference

| Command | What it does |
|---|---|
| `.\CyberArkAuditEndpoint-ForwardAsWebhook.ps1` | Normal run — pulls events and posts to webhook |
| `.\CyberArkAuditEndpoint-ForwardAsWebhook.ps1 -DryRun` | Pulls events, prints them, doesn't post anything |
| `.\CyberArkAuditEndpoint-ForwardAsWebhook.ps1 -ResetCursor` | Forgets saved position and starts fresh from the lookback window |

---

## What gets created on the Hybrid Worker

The script automatically creates a working directory at `C:\ProgramData\CyberArkAuditSync\` on the Hybrid Worker on its first run. Three files live here:

| File | Purpose | What to look for |
|---|---|---|
| `state.json` | Saves the cursor position and timestamp of the last event forwarded — this is how the script remembers where it got to between runs | If this file is missing or empty after a run, the Hybrid Worker setting (Step 4) is likely wrong |
| `sync_YYYYMMDD.log` | Daily log file with INFO/WARN/ERROR entries | Any ERROR lines; repeated WARN about cursor rebuilds |
| `sync.lock` | Prevents two copies of the script running at the same time | If it persists while nothing is running, a previous run died hard — safe to delete manually |

> The working directory path can be changed by editing the `WorkDir`, `StateFile`, `LockFile`, and `LogFile` values in the `$Config` block.

> Add the following to your `.gitignore` — these files accumulate real usernames and timestamps at runtime:
> ```
> *.json
> *.log
> *.lock
> ```

---

## Configuration reference

All settings are in the `$Config` block near the top of the script:

| Setting | Default | Description |
|---|---|---|
| `IdentityUrl` | — | Your CyberArk Identity tenant URL |
| `AppId` | — | OAuth2 web app Application ID — case-sensitive |
| `ClientId` | — | Service user login name |
| `Scope` | `isp.audit.events:read` | Don't change this |
| `AuditBaseUrl` | — | Audit API base URL from the Export to SIEM page |
| `PageSize` | `500` | Events fetched per API call. 500 is the maximum |
| `WebhookUrl` | — | Your webhook endpoint URL |
| `WebhookTimeoutSec` | `30` | Seconds to wait for the webhook to respond before timing out |
| `WebhookRetries` | `3` | How many times to retry a failed webhook call before giving up on that event |
| `WebhookRetryDelaySeconds` | `5` | Seconds to wait between retries |
| `LookbackHours` | `24` | How far back to pull events on first run. Max useful value is 168 (7 days — CyberArk's retention limit) |
| `OverlapMinutes` | `5` | Re-reads the last 5 minutes when rebuilding after a lost cursor — prevents gaps at the cost of occasional duplicates |
| `MaxApiCallsPerRun` | `5` | Maximum CyberArk API calls per run. 1 call creates the query, the rest fetch pages (500 events each) |
| `ApiCallSpacingSeconds` | `61` | Pause between API calls. **Keep at 61 or above** — CyberArk enforces 1 call/minute and will reject faster requests |
| `StatePersistence` | `File` | Where to save the cursor. `File` = Hybrid Worker local disk (recommended). `AutomationVariable` = Azure Automation variable (use only if not on a Hybrid Worker) |
| `WorkDir` | `C:\ProgramData\CyberArkAuditSync` | Root folder for all state, log, and lock files on the Hybrid Worker. Created automatically on first run |

---

## Troubleshooting

| Symptom / Error | What it means | Fix |
|---|---|---|
| Every run shows a fresh `createQuery window` instead of `Resuming from persisted cursor` | The runbook is running in an Azure sandbox, not on the Hybrid Worker — the disk is wiped between jobs | Set **Run on** to your Hybrid Worker Group (Step 4) |
| `Required secret '...' not found` | The secret isn't set as an Azure Automation variable | Create the missing variable in Shared Resources → Variables (Step 3) |
| `invalid_request / unknown app <name>` | The Application ID in the script doesn't match what's in CyberArk | Check the Settings tab of the web app — copy the Application ID exactly, it's case-sensitive |
| `invalid_grant / invalid grant type` | Token request is malformed or Client Creds not enabled on the web app | Check the web app's Tokens tab — Client Creds must be ticked |
| `401 Unauthorized` from the Audit API | Token issued by the wrong endpoint, or the web app is missing its Advanced-tab claims script | Ask your CyberArk admin to verify the Advanced tab has the `setClaim` lines saved and the Scope tab has `isp.audit.events:read` |
| `403 Forbidden` from the Audit API | Wrong API key, or the service user lacks permissions on the web app | Check the API key matches the Export to SIEM page; service user needs Grant/View/Run/Automatically Deploy |
| `400` on results call | Cursor has expired or been invalidated | Script auto-recovers on the next run — no action needed |
| Webhook retries failing | Webhook endpoint is unreachable or rejecting the token | Verify the webhook URL and bearer token; check the Exabeam collector is running and accepting connections |
| `Lock file present` warning | Another run is in progress, or a previous run crashed without cleaning up | Wait 30 minutes for auto-recovery, or delete `sync.lock` from `C:\ProgramData\CyberArkAuditSync\` manually |
| No new events flowing despite activity in CyberArk | Stale cursor with a past `dateTo` ceiling — this was a bug in earlier versions | Ensure you are on the latest version of the script. Delete `state.json` from `C:\ProgramData\CyberArkAuditSync\` to force a clean restart |

---

## Event format

Each event arrives at your webhook as a JSON POST — one event per request. Here's an example payload:

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

Key fields for SIEM parsing: `uuid` (deduplicate on this), `timestamp` (milliseconds — not seconds), `username`, `source` (source IP address), `applicationCode` (which CyberArk service generated the event), `auditCode`, `auditType`, `action`, `actionType`.

---

## Version notes

### Latest version

Four bugs were identified and fixed following initial production deployment:

**1. Cursor not clearing when caught up** *(caused events to stop flowing)*
When the script exhausted all events in a query window, it kept the cursor rather than clearing it. CyberArk bakes a `dateTo` ceiling into every cursor at creation time, so an exhausted cursor permanently reports "no new events" as time moves forward past that ceiling. The fix: when the results call returns empty, the cursor is now cleared. The next run creates a fresh query from the last forwarded event's timestamp to the current time, so new events are always visible.

**2. Webhook bearer token fetched per event** *(performance)*
`Get-AutomationVariable` was being called once for every event forwarded — potentially hundreds of calls per run. The webhook token doesn't change mid-run, so it is now fetched once at startup and reused for all events.

**3. Rate limit sleep not applied after the final API call** *(could cause throttling on back-to-back runs)*
The 61-second API rate limit sleep was conditional on the call budget not being exhausted, meaning the last call of a run had no sleep after it. If the schedule fired again quickly, the next run's first call could hit CyberArk's rate limit. The sleep is now applied unconditionally after every results call.

**4. Duplicate section comment in script** *(cosmetic)*
A copy-paste artefact left the `STATE` section header duplicated in the script. Removed.

---

## Licence

Add your licence here before publishing.
