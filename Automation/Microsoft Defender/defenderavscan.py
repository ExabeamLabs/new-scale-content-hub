import json
import urllib.request
import urllib.parse
import urllib.error

# ✅ Credentials (working app)
TENANT_ID     = "XYZ"
CLIENT_ID     = "XYZ"
CLIENT_SECRET = "XYZF"

# Base URLs
TOKEN_URL    = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
DEFENDER_API = "https://api.security.microsoft.com/api"
TIMEOUT      = 15  # seconds

# ─── HTTP Helpers ──────────────────────────────────────────────────────────────
def _post_form(url: str, form: dict) -> dict:
    data = urllib.parse.urlencode(form).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.load(resp)

def _json_request(url: str, headers: dict, method: str = "GET", payload: dict = None) -> dict:
    body = None
    hdrs = headers.copy()
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url=url, data=body, headers=hdrs, method=method)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.load(resp)

# ─── Core Logic ────────────────────────────────────────────────────────────────
def run_scan(device_name: str) -> str:
    logs = []

    # Step 1: Get Access Token
    logs.append("Step 1: Requesting Access Token")
    try:
        token_resp = _post_form(TOKEN_URL, {
            "grant_type":    "client_credentials",
            "client_id":     CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope":         "https://api.securitycenter.microsoft.com/.default"
        })
        token = token_resp.get("access_token")
        if not token:
            logs.append(f"Step 1 Error: No access_token in response: {token_resp}")
            return "\n".join(logs)
        logs.append("Step 1: Access Token retrieved successfully")
    except urllib.error.HTTPError as e:
        logs.append(f"Step 1 Error: HTTP {e.code} fetching token – {e.reason}")
        return "\n".join(logs)
    except Exception as e:
        logs.append(f"Step 1 Error: {e}")
        return "\n".join(logs)

    # Step 2: Lookup Device ID
    logs.append(f"Step 2: Retrieving device ID for '{device_name}'")
    auth_hdr = {"Authorization": f"Bearer {token}"}
    filter_expr = urllib.parse.quote(f"computerDnsName eq '{device_name}'")
    device_url = f"{DEFENDER_API}/machines?$filter={filter_expr}"
    try:
        resp = _json_request(device_url, auth_hdr, method="GET")
        machines = resp.get("value", [])
        if not machines:
            logs.append(f"Step 2 Error: Device '{device_name}' not found in Defender")
            return "\n".join(logs)
        device_id = machines[0]["id"]
        logs.append(f"Step 2: Device ID retrieved: {device_id}")
    except urllib.error.HTTPError as e:
        logs.append(f"Step 2 Error: HTTP {e.code} retrieving device – {e.reason}")
        if e.code == 403:
            logs.append("→ Forbidden: verify Machine.Read.All application permission is granted and admin-consented.")
        return "\n".join(logs)
    except Exception as e:
        logs.append(f"Step 2 Error: {e}")
        return "\n".join(logs)

    # Step 3: Trigger Antivirus Scan
    logs.append(f"Step 3: Starting antivirus scan on {device_name}")
    scan_url = f"{DEFENDER_API}/machines/{device_id}/runAntiVirusScan"
    payload = {
        "Comment": "Triggered via Windmill Python",
        "ScanType": "Quick"  # or "Full" — must be title case
    }
    try:
        _json_request(scan_url, auth_hdr, method="POST", payload=payload)
        logs.append(f"Step 3: Antivirus scan started successfully on {device_name} (ID: {device_id})")
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        logs.append(f"Step 3 Error: HTTP {e.code} starting scan – {e.reason}\n{error_body}")
        if e.code == 403:
            logs.append("→ Forbidden: ensure Machine.Scan permission is granted/admin-consented.")
    except Exception as e:
        logs.append(f"Step 3 Error: {e}")

    return "\n".join(logs)

# ─── Windmill Entrypoint ───────────────────────────────────────────────────────
def main(x: str) -> str:
    # 'x' should be the target device name (e.g., "win10.domain.org.uk")
    return run_scan(x)
