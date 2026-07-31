"""
=============================================================================
Windmill Action: Post Enriched Case Note to Exabeam Threat Centre
=============================================================================

WHAT THIS SCRIPT DOES
---------------------
This is a Windmill "action" step — it runs as part of a larger SOAR playbook.

Its job is to:
  1. Authenticate with the Exabeam API using client credentials (OAuth2).
  2. Pull enrichment data that was gathered by earlier playbook steps
     (VirusTotal IP lookup, FortiGate block action).
  3. Build a nicely formatted HTML case note summarising what happened.
  4. Post that note directly into the relevant Exabeam Threat Centre case.

HOW THE HTML FORMATTING WORKS (the trick that makes this look good)
---------------------------------------------------------------------
Exabeam's Threat Centre case notes API accepts raw HTML in the "note" field.
Most people don't realise this and end up posting plain text blobs.

By passing HTML tags like <h3>, <b>, <ul>, <li> etc. in the JSON payload,
Exabeam renders them as proper rich text in the case timeline — headings,
bullet lists, bold text, and all. No special API flag is needed; the
endpoint just renders whatever HTML you give it.

Key tags that work well:
  <h3>, <h4>       — section headings
  <b>              — bold text
  <ul> / <li>      — bullet lists
  <br>             — line break
  <i>              — italic text

INPUTS (Windmill function parameters)
--------------------------------------
These appear in the Windmill UI as form fields when you configure the step.

  region        (str)  — Your Exabeam cloud region code, e.g. "uk", "us-west",
                         "us-east", "eu", "sg", "jp", "au", "ca", "ch", "sa".
                         Used to build the correct API base URL.

  client_id     (str)  — OAuth2 client ID from your Exabeam API credentials.
                         Create these in: Exabeam Settings > API Credentials.

  client_secret (str)  — OAuth2 client secret paired with the above.
                         Store this as a Windmill Secret — never hardcode it.

  case_id       (str)  — The Exabeam Threat Centre case ID to post the note to.
                         Usually passed in from an earlier playbook step that
                         identifies or creates the case (default: empty string).

  vt_result     (dict) — Output from a previous VirusTotal lookup step.
                         Expected keys:
                           "ip"                — IP address that was checked
                           "country"           — Country the IP is registered in
                           "asn"               — Autonomous System Number
                           "as_owner"          — Name of the AS owner/ISP
                           "reputation_score"  — VT reputation score (negative = bad)
                           "malicious_reports" — Number of AV engines flagging malicious
                           "suspicious_reports"— Number flagging suspicious
                           "harmless_reports"  — Number flagging harmless
                         (default: empty dict — all values will show as "Unknown" or 0)

  fortigate_result (str) — Output message from a previous FortiGate block step.
                           Currently referenced in the note narrative but not
                           directly displayed. You could extend this to show the
                           raw response if needed. (default: empty string)

OUTPUTS
--------
Returns a dict with:
  "status"       — HTTP status code from Exabeam (201 = note created successfully)
  "response"     — Full JSON response body from Exabeam
  "note_preview" — The HTML string that was posted (useful for debugging)

THINGS YOU MIGHT WANT TO CHANGE
---------------------------------
  - The "Verdict" and "Response Action" sections are currently hardcoded strings.
    You could make these dynamic by passing them in as parameters, or by
    deriving them from the VT/FortiGate results (e.g. conditional on score threshold).

  - The note title "Automated SOC Action Summary" can be whatever you like —
    just edit the <h3> tag in the note block below.

  - Want to add more enrichment sources (e.g. Shodan, AbuseIPDB, internal CMDB)?
    Add new parameters to the function signature and extend the HTML note section.

  - The "Verdict" section currently always says "High-confidence malicious".
    If you want this to be conditional, you could check `malicious` count or
    `reputation` score and set the verdict string dynamically before building the note.

DEPENDENCIES
-------------
  - requests  (standard, available in Windmill Python runtime by default)
  - datetime  (standard library — no install needed)

PREVIOUS STEPS THIS REFERENCES
--------------------------------
This step is designed to be the final "write-back" action in a playbook that
has already run:
  [1] A VirusTotal IP enrichment step  →  produces `vt_result`
  [2] A FortiGate block action step    →  produces `fortigate_result`
  [3] This step                        →  writes the summary back to Exabeam

Make sure those upstream steps are passing their outputs correctly into this
step's input parameters in the Windmill flow editor.

=============================================================================
"""

import requests
from datetime import datetime, timezone


def main(
    region: str,
    client_id: str,
    client_secret: str,
    case_id: str = "",
    vt_result: dict = {},
    fortigate_result: str = "",
):

    # =========================================================================
    # STEP 1: AUTHENTICATE WITH EXABEAM
    # =========================================================================
    # Exabeam uses OAuth2 "client_credentials" flow.
    # We POST our client_id + client_secret to get a short-lived bearer token.
    # That token is then used to authorise the note POST in Step 3.
    #
    # The URL is constructed dynamically using the `region` parameter so this
    # script works across different Exabeam tenants without code changes.
    # Example URL: https://api.uk.exabeam.cloud/auth/v1/token
    # =========================================================================

    auth_url = f"https://api.{region}.exabeam.cloud/auth/v1/token"

    # The body Exabeam expects for client credentials auth
    auth_payload = {
        "grant_type": "client_credentials",  # OAuth2 flow type — don't change this
        "client_id": client_id,
        "client_secret": client_secret,
    }

    # Standard headers for a JSON POST
    auth_headers = {
        "accept": "application/json",
        "content-type": "application/json",
    }

    # Make the authentication request
    # timeout=30 prevents the script hanging indefinitely if the API is slow
    auth_response = requests.post(
        auth_url,
        json=auth_payload,
        headers=auth_headers,
        timeout=30,
    )

    # If auth fails (anything other than HTTP 200), bail out early with detail
    # Common causes: wrong region slug, expired/invalid credentials, network issue
    if auth_response.status_code != 200:
        return {
            "error": "Auth failed",
            "status": auth_response.status_code,
            "detail": auth_response.text,
        }

    # Extract the bearer token from the response
    token = auth_response.json().get("access_token")

    # Defensive check — if somehow a 200 came back without a token, bail out
    if not token:
        return {
            "error": "No access token returned",
            "detail": auth_response.text,
        }

    # =========================================================================
    # STEP 2: PREPARE THE DATA FOR THE NOTE
    # =========================================================================
    # Pull values out of the vt_result dict passed in from the upstream VT step.
    # .get() with a fallback means if a key is missing we show "Unknown" / 0
    # rather than crashing — keeps things resilient if VT data is incomplete.
    # =========================================================================

    # Capture the current UTC time — this stamps when this playbook ran
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Extract each field we want to display from the VirusTotal result dict
    ip          = vt_result.get("ip", "Unknown")
    country     = vt_result.get("country", "Unknown")
    asn         = vt_result.get("asn", "Unknown")
    as_owner    = vt_result.get("as_owner", "Unknown")
    reputation  = vt_result.get("reputation_score", 0)
    malicious   = vt_result.get("malicious_reports", 0)
    suspicious  = vt_result.get("suspicious_reports", 0)
    harmless    = vt_result.get("harmless_reports", 0)

    # =========================================================================
    # STEP 3: BUILD THE HTML NOTE
    # =========================================================================
    # This is the magic bit. Exabeam's case note endpoint renders HTML when
    # you include HTML tags in the "note" field of the JSON payload.
    #
    # This is NOT documented prominently — most users just post plain text.
    # The key insight: the UI renders whatever is in that field as HTML,
    # so wrapping your content in proper tags gives you rich formatting.
    #
    # HOW TO CUSTOMISE THIS SECTION:
    #   - Change the <h3> title to whatever suits your playbook
    #   - Add or remove <li> items under Threat Intelligence
    #   - Update the Verdict/Response text to be dynamic (see notes at top)
    #   - Add additional enrichment sections (Shodan, AbuseIPDB, etc.)
    #   - Adjust the footer italic line to reflect your team/tool name
    #
    # Python f-string syntax: {variable_name} inserts the variable value.
    # .strip() at the end removes any leading/trailing blank lines from the note.
    # =========================================================================

    note = f"""
<h3>Automated SOC Action Summary</h3>

<b>Timestamp:</b> {timestamp}<br><br>

<h4>Threat Intelligence</h4>

<ul>
<li><b>Source:</b> VirusTotal</li>
<li><b>IP Address:</b> {ip}</li>
<li><b>Country:</b> {country}</li>
<li><b>ASN:</b> {asn} ({as_owner})</li>
<li><b>Reputation Score:</b> {reputation}</li>
<li><b>Malicious Reports:</b> {malicious}</li>
<li><b>Suspicious Reports:</b> {suspicious}</li>
<li><b>Harmless Reports:</b> {harmless}</li>
</ul>

<h4>Verdict</h4>

High-confidence malicious public IP identified.<br><br>

<h4>Response Action</h4>

FortiGate block action executed successfully.<br><br>

<h4>Outcome</h4>

IP <b>{ip}</b> was automatically added to the FortiGate blocklist.<br><br>

<i>Triggered automatically by the Windmill SOAR playbook.</i>
""".strip()

    # =========================================================================
    # STEP 4: POST THE NOTE TO THE EXABEAM CASE
    # =========================================================================
    # With the token from Step 1 and the HTML note from Step 3, we now POST
    # the note to the Threat Centre case identified by `case_id`.
    #
    # URL format: /threat-center/v1/cases/{case_id}/notes
    # The case_id should come from an upstream step that identifies the relevant
    # Exabeam case — either by lookup or by creation earlier in the playbook.
    #
    # IMPORTANT: The note must be a string value in the JSON body under "note".
    # Exabeam expects exactly that key name — do not change it.
    # =========================================================================

    note_url = f"https://api.{region}.exabeam.cloud/threat-center/v1/cases/{case_id}/notes"

    note_headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": f"Bearer {token}",  # Token from auth step — do not hardcode
    }

    # The payload — "note" is the only required field; its value is our HTML string
    note_payload = {
        "note": note
    }

    # POST the note to the Exabeam API
    note_response = requests.post(
        note_url,
        json=note_payload,
        headers=note_headers,
        timeout=30,
    )

    # =========================================================================
    # STEP 5: RETURN THE RESULT
    # =========================================================================
    # Parse the response body as JSON if possible; fall back to raw text if not.
    # This keeps things from crashing if Exabeam returns an unexpected format.
    #
    # Return dict:
    #   "status"       — HTTP 201 means the note was created successfully
    #   "response"     — Exabeam's full response (useful for debugging)
    #   "note_preview" — The HTML we sent (lets you verify what was posted)
    # =========================================================================

    try:
        response_body = note_response.json()
    except Exception:
        # If Exabeam returns something that isn't JSON, capture it as plain text
        response_body = note_response.text

    return {
        "status": note_response.status_code,
        "response": response_body,
        "note_preview": note,
    }
