#!/usr/bin/env python3

import time
import requests
import json
from typing import Optional, Any

REQUEST_TIMEOUT = 15  # seconds


# ---------------------------------------------------------------------
# PARAMETERS (set these before running)
# ---------------------------------------------------------------------
MY_USERNAME = "YOUR_USERNAME"
MY_PASSWORD = "YOUR_PASSWORD"
MY_API_KEY = "YOUR_API_KEY"
# Use your tenant's admin base URL (the one you use to login to the ZIA admin console).
# Examples:
#  - "https://admin.zscalerone.net"
#  - "https://zsapi.zscaler.net"
#  - "https://zsapi.zscalerbeta.net"
MY_BASE_URL = "https://zsapi.zscaler.net"
VERIFY_SSL = True
# ---------------------------------------------------------------------


def obfuscate_api_key(api_key: str, timestamp_ms: str) -> str:

    if not isinstance(timestamp_ms, str):
        timestamp_ms = str(timestamp_ms)

    high = timestamp_ms[-6:]
    low = str(int(high) >> 1).zfill(6)

    if len(api_key) < 12:
        raise ValueError("API key too short for obfuscation indexing.")

    obf = []
    for ch in high:
        obf.append(api_key[int(ch)])
    for ch in low:
        obf.append(api_key[int(ch) + 2])
    return "".join(obf)


def normalize_base_url(base_url: str, api_prefix: str = "/api/v1") -> str:

    base = base_url.rstrip("/")
    if base.endswith(api_prefix):
        return base
    return base + api_prefix


def login_to_zscaler(
    username: str,
    password: str,
    api_key: str,
    base_url: str,
    verify_ssl: bool = True,
) -> requests.Session:

    session = requests.Session()
    session.verify = verify_ssl
    base = normalize_base_url(base_url)

    login_url = f"{base}/authenticatedSession"
    ts_ms = str(int(time.time() * 1000))
    obf_key = obfuscate_api_key(api_key, ts_ms)

    payload = {
        "username": username,
        "password": password,
        "apiKey": obf_key,
        "timestamp": ts_ms,
    }
    headers = {"Content-Type": "application/json"}

    # Debug-friendly output but do not print password
    print("POST", login_url)
    print("payload (no password):", {k: v for k, v in payload.items() if k != "password"})

    resp = session.post(login_url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()

    print("Authentication succeeded. HTTP", resp.status_code)
    try:
        print("Response JSON:", resp.json())
    except Exception:
        print("Response text:", resp.text)
    print("Session cookies:", session.cookies.get_dict())

    return session


def get_denylist_urls(session: requests.Session, base_url: str) -> Any:

    base = normalize_base_url(base_url)
    candidates = [
        f"{base}/cyberThreatProtection/maliciousUrls",
        f"{base}/security/maliciousUrls",
        f"{base}/maliciousUrls",
        f"{base}/cyberthreatprotection/maliciousUrls",
        f"{base}/threats/maliciousUrls",
    ]

    last_exception: Optional[Exception] = None

    for url in candidates:
        print("\nGET", url)
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT)
            # If we get a 200, parse and return JSON (even if it's an empty list)
            if resp.status_code == 200:
                try:
                    return resp.json()
                except ValueError:
                    # Return raw text if not JSON (unexpected)
                    return resp.text
            # otherwise raise to go to next candidate and capture the error
            resp.raise_for_status()
        except requests.HTTPError as he:
            last_exception = he
            # show short debug info for each failed candidate
            status = getattr(he.response, "status_code", "<no status>")
            text = getattr(he.response, "text", "") or "<empty body>"
            print(f"  -> HTTP {status} (failed). Response (truncated): {text[:500]}")
        except Exception as e:
            last_exception = e
            print(f"  -> Request failed: {e}")

    # nothing succeeded
    if last_exception:
        raise last_exception
    raise RuntimeError("No denylist endpoints succeeded.")


def logout_from_zscaler(session: requests.Session, base_url: str):

    base = normalize_base_url(base_url)
    logout_url = f"{base}/authenticatedSession"
    print("DELETE", logout_url)
    resp = session.delete(logout_url, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    print("Logged out. HTTP", resp.status_code)


def main(username: str, password: str, api_key: str, base_url: str, verify_ssl: bool = True):
    session: Optional[requests.Session] = None
    try:
        print("[*] Logging in to Zscaler...")
        session = login_to_zscaler(username, password, api_key, base_url, verify_ssl=verify_ssl)

        print("[*] Attempting to retrieve denylist / malicious URLs...")
        denylist = get_denylist_urls(session, base_url)
        print("[+] Retrieved denylist / malicious URLs (raw):")
        # Pretty print JSON or raw text
        if isinstance(denylist, (dict, list)):
            print(json.dumps(denylist, indent=2))
        else:
            print(denylist)

    except requests.exceptions.HTTPError as http_err:
        content = getattr(http_err.response, "text", "<no response body>")
        print(f"[ERROR] HTTP error: {http_err}. Response body (truncated):\n{content[:1000]}")
    except Exception as err:
        print(f"[ERROR] Exception: {err}")
    finally:
        if session:
            try:
                print("[*] Logging out...")
                logout_from_zscaler(session, base_url)
            except Exception as e:
                print(f"[WARNING] Logout failed: {e}")


if __name__ == "__main__":
    if any(v.startswith("YOUR_") for v in (MY_USERNAME, MY_PASSWORD, MY_API_KEY)):
        print("Please update the MY_USERNAME, MY_PASSWORD and MY_API_KEY variables before running.")
    else:
        main(MY_USERNAME, MY_PASSWORD, MY_API_KEY, MY_BASE_URL, verify_ssl=VERIFY_SSL)
