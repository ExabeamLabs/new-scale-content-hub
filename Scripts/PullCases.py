# Charlie MacArthur - TAM Jan 2026
# https://github.com/ExabeamLabs/new-scale-content-hub/tree/main
# Exabeam Threat Center API: Search Cases
#
# What this script does
# ---------------------
# 1) Requests an OAuth2 access token from Exabeam using client_credentials
# 2) Uses that token to call the Threat Center "search cases" endpoint
# 3) Prints each returned case row as nicely formatted JSON (easy to read)
#
# Docs
# ----
# - Get access token:
#   https://developers.exabeam.com/exabeam/reference/get-access-token
# - Search cases:
#   https://developers.exabeam.com/exabeam/reference/threat-center-search-cases
#

# -----------------------------
# ANSI colour codes (terminal)
# -----------------------------
ANSI_GREEN = "\033[92m"   # Bright / neon green
ANSI_RESET = "\033[0m"

import requests
import json
import sys

# =========================================================
# 1) CONFIGURATION - E.G Your Variables
# =========================================================
# Ensure you are choosing the right region. In the Exabeam docs, there is a "base url" dropdown on the token page.
# Example regions you may see: eu, uk, us-west, etc.

REGION = "eu"

# Your OAuth2 client credentials (from your Exabeam API application)
CLIENT_ID = "REPLACEME"
CLIENT_SECRET = "REPLACEME"

# Base URLs derived from REGION
AUTH_URL = f"https://api.{REGION}.exabeam.cloud/auth/v1/token"
CASE_SEARCH_URL = f"https://api.{REGION}.exabeam.cloud/threat-center/v1/search/cases"

# Request tuning
TOKEN_TIMEOUT_SECONDS = 30
API_TIMEOUT_SECONDS = 60

# =========================================================
# 2) AUTHENTICATION: GET AN ACCESS TOKEN e.g. Bearer Token Using CLIENT ID & SECRET
# =========================================================
# Exabeam uses OAuth2. For machine-to-machine access (scripts/automations),the most common flow is "client_credentials".
#
# NOTE: OAuth2 token endpoints typically expect form-encoded data, not JSON. That is why we use data=payload and content-type application/x-www-form-urlencoded.

def get_access_token() -> str:
    payload = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }

    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
    }

    resp = requests.post(AUTH_URL, data=payload, headers=headers, timeout=TOKEN_TIMEOUT_SECONDS)

    # If authentication fails, show useful error details and exit.
    try:
        resp.raise_for_status()
    except requests.HTTPError:
        print("[ERROR] Token request failed")
        print(f"Status: {resp.status_code}")
        print(resp.text)
        sys.exit(1)

    token_json = resp.json()
    access_token = token_json.get("access_token")

    if not access_token:
        print("[ERROR] Token response did not include access_token")
        print(json.dumps(token_json, indent=2))
        sys.exit(1)

    return access_token

# =========================================================
# 3) API CALL: THREAT CENTER SEARCH CASES
# =========================================================
# This function calls the Threat Center endpoint with a fresh token.
#
# Key payload fields:
# - fields: what columns you want back. ["*"] returns all available fields.
# - limit: max rows (cases) to return
# - orderBy: sorting, e.g. "riskScore DESC" "caseCreationTimestamp DESC" "caseNumber DESC"
# - startTime/endTime: time window (ISO8601 UTC)
# - filter: filtering expression (example: exclude CLOSED cases)

def search_cases(access_token: str) -> dict:
    payload = {
        "fields": ["*"],
        "limit": 3000,
        "orderBy": ["caseNumber DESC"],
        "startTime": "2026-01-01T00:00:00Z",
        "endTime": "2026-01-31T00:00:00Z",
        "filter": 'NOT stage:"CLOSED"',
    }

    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": f"Bearer {access_token}",
    }

    resp = requests.post(CASE_SEARCH_URL, json=payload, headers=headers, timeout=API_TIMEOUT_SECONDS)

    try:
        resp.raise_for_status()
    except requests.HTTPError:
        print("[ERROR] Case search request failed")
        print(f"Status: {resp.status_code}")
        print(resp.text)
        sys.exit(1)

    return resp.json()


# =========================================================
# 4) OUTPUT: PRINT RESULTS IN A READABLE WAY
# =========================================================
# We print each row (case) as a separate formatted JSON block.
# This is much easier to read than printing response.text (one long line).

def print_case_rows(data: dict) -> None:
    rows = data.get("rows", [])

    if not rows:
        print("No cases returned.")
        return

    for i, row in enumerate(rows, start=1):
        print(f"\n{ANSI_GREEN}--- Case {i} ---{ANSI_RESET}")
        print(json.dumps(row, indent=2, sort_keys=True))

    if "totalRows" in data:
        print(f"\nTotal rows: {data['totalRows']}")


# =========================================================
# 5) MAIN
# =========================================================
# The "happy path": get token -> call API -> print results

if __name__ == "__main__":
    token = get_access_token()
    result = search_cases(token)
    print_case_rows(result)
