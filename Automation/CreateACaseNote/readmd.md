# Windmill Action: Exabeam Threat Centre — Rich Case Note

Post a beautifully formatted HTML case note into an Exabeam Threat Centre case, automatically, as part of a Windmill SOAR playbook. The below context is from a Playbook I wrote that will take an IP, check it's risk score on VirusTotal, if it's a genuine threat it will pass to a Fortigate block script, and then finally to this service/script that does a html style report wrap up that adds itself as a case note to the respective case that the playbook was triggered from.

<img width="800" height="617" alt="image" src="https://github.com/user-attachments/assets/9afd2c6a-aaf5-4770-8f25-65ed05e50719" />

---

## What This Does

This Windmill action step takes enrichment data gathered by earlier playbook steps (VirusTotal IP lookup, FortiGate block action) and writes a structured, readable summary back into the relevant Exabeam case as a case note.

The result looks like this in the Exabeam UI:

> **Automated SOC Action Summary**
> **Timestamp:** 2025-05-28 09:14:22 UTC
>
> **Threat Intelligence**
> - Source: VirusTotal
> - IP Address: 1.2.3.4
> - Country: RU
> - ASN: 12345 (Some Hosting Ltd)
> - Reputation Score: -85
> - Malicious Reports: 47
> - Suspicious Reports: 3
> - Harmless Reports: 2
>
> **Verdict**
> High-confidence malicious public IP identified.
>
> **Response Action**
> FortiGate block action executed successfully.
>
> _Triggered automatically by the Windmill SOAR playbook._

---

## The Secret: How Rich Text Formatting Works

Most users post plain text case notes to Exabeam because the API docs don't make this obvious — but the `note` field in the Exabeam case notes endpoint **renders HTML directly in the Threat Centre UI**.

No special flags. No extra headers. Just pass valid HTML as the string value of `"note"` in your JSON payload, and Exabeam renders it.

**Tags confirmed to work:**

| Tag | Effect |
|-----|--------|
| `<h3>`, `<h4>` | Section headings |
| `<b>` | Bold text |
| `<ul>` / `<li>` | Bullet lists |
| `<br>` | Line break |
| `<i>` | Italic text |

**Example payload:**

```json
{
  "note": "<h3>Summary</h3><b>IP:</b> 1.2.3.4<br><ul><li>Malicious: 47</li></ul>"
}
```

That's it. The trick is knowing the field accepts HTML — not fighting with block text formatting.

---

## Playbook Context

This script is designed as the **final write-back step** in a three-step playbook:

```
[Step 1] VirusTotal IP Lookup
         → Output: vt_result (dict)
              ↓
[Step 2] FortiGate Block Action
         → Output: fortigate_result (str)
              ↓
[Step 3] THIS SCRIPT — Post Case Note to Exabeam
         ← Inputs: vt_result, fortigate_result, case_id
```

Connect the outputs of Steps 1 and 2 to the inputs of this step in the Windmill flow editor.

---

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `region` | `str` | ✅ | Exabeam cloud region code, e.g. `uk`, `us-west`, `us-east`, `eu`, `sg`, `jp`, `au`, `ca`, `ch`, `sa`. Builds the API base URL. |
| `client_id` | `str` | ✅ | OAuth2 client ID from Exabeam API Credentials settings. |
| `client_secret` | `str` | ✅ | OAuth2 client secret. **Store as a Windmill Secret — never hardcode.** |
| `case_id` | `str` | ✅ | Exabeam Threat Centre case ID to post the note to. Pass from an upstream step. |
| `vt_result` | `dict` | ⬜ | Output from VirusTotal lookup step. Expected keys listed below. |
| `fortigate_result` | `str` | ⬜ | Output message from FortiGate block step. Used in note narrative. |

### Expected Keys in `vt_result`

```python
{
    "ip": "1.2.3.4",
    "country": "RU",
    "asn": "12345",
    "as_owner": "Some Hosting Ltd",
    "reputation_score": -85,
    "malicious_reports": 47,
    "suspicious_reports": 3,
    "harmless_reports": 2
}
```

Missing keys fall back gracefully to `"Unknown"` or `0` — the script won't crash on incomplete data.

---

## Output

Returns a dict:

```python
{
    "status": 201,           # HTTP status — 201 = note created successfully
    "response": { ... },     # Full Exabeam API response body
    "note_preview": "..."    # The HTML string that was posted (for debugging)
}
```

---

## Authentication

Exabeam uses **OAuth2 client credentials** flow. This script handles the full token exchange automatically — you just supply `client_id`, `client_secret`, and `region`.

1. POSTs credentials to `https://api.{region}.exabeam.cloud/auth/v1/token` (e.g. `https://api.uk.exabeam.cloud/auth/v1/token`)
2. Extracts the `access_token` from the response
3. Uses it as a `Bearer` token on the note POST

Generate API credentials in: **Exabeam Settings → API Credentials → Create New**

---

## Customising the Note

Everything you'd want to change is in the `note` f-string block (Step 3 in the script). It's a standard Python f-string with HTML tags — edit it like you would any HTML.

**Common customisations:**

- **Change the title** — edit the `<h3>` tag text
- **Make Verdict dynamic** — derive it from score threshold, e.g.:
  ```python
  verdict = "High-confidence malicious" if malicious >= 10 else "Suspicious — investigate further"
  ```
- **Add more enrichment sources** — add new parameters and extra `<li>` rows
- **Change the footer line** — update the `<i>` italic tag at the bottom

---

## Dependencies

- `requests` — available by default in the Windmill Python runtime
- `datetime` — Python standard library, no install needed

No `requirements.txt` needed for this script.

---

## Getting Started

1. Copy `exabeam_case_note.py` into your Windmill workspace as a Python action.
2. Store `client_id` and `client_secret` as [Windmill Secrets](https://www.windmill.dev/docs/core_concepts/variables_and_secrets).
3. Wire up `vt_result` and `fortigate_result` from your upstream playbook steps.
4. Set `case_id` — either hardcoded for testing or passed from a case lookup step.
5. Run it.

---

## Notes & Considerations

- **Token lifetime** — the bearer token is fetched fresh each run. Exabeam tokens are short-lived; this avoids stale token issues across playbook executions.
- **case_id source** — in production this should come from an earlier step that looks up or creates the case based on the alert. Don't hardcode it.
- **Error handling** — auth failures and non-JSON responses are caught and returned cleanly rather than raising exceptions, so Windmill can surface the error in the UI.
- **HTML tag support** — tested with the tags listed above. Avoid complex HTML (tables, inline styles) as behaviour may vary across Exabeam versions.

---

## Licence

MIT — use freely, adapt as needed, credit appreciated but not required.
