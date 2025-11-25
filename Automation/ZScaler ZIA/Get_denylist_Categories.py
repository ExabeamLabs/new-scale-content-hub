#!/usr/bin/env python3
"""
"""

import time
import requests
import json
from typing import Optional

REQUEST_TIMEOUT = 15  # seconds

# ---------------------------------------------------------------------
# PARAMETERS (set these before running)
# ---------------------------------------------------------------------
MY_USERNAME = "YOUR_USERNAME"
MY_PASSWORD = "YOUR_PASSWORD"
MY_API_KEY = "YOUR_API_KEY"
MY_BASE_URL = "https://admin.zscalerbeta.net"  # e.g. https://zsapi.zscaler.net or https://admin.zscalerbeta.net
VERIFY_SSL = True
# ---------------------------------------------------------------------


def obfuscate_api_key(api_key: str, timestamp_ms: str) -> str:
    """Legacy Zscaler API key obfuscation."""
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
    """Ensure base_url ends with /api/v1 once."""
    base = base_url.rstrip("/")
    if base.endswith(api_prefix):
        return base
    return base + api_prefix


def login_to_zscaler(username: str, password: str, api_key: str, base_url: str, verify_ssl: bool = True) -> requests.Session:
    """Authenticate and return an authorized session."""
    session = requests.Session()
    session.verify = verify_ssl
    base = normalize_base_url(base_url)

    url = f"{base}/authenticatedSession"
    ts_ms = str(int(time.time() * 1000))
    obf_key = obfuscate_api_key(api_key, ts_ms)

    payload = {
        "username": username,
        "password": password,
        "apiKey": obf_key,
        "timestamp": ts_ms,
    }
    headers = {"Content-Type": "application/json"}

    print("POST", url)
    print("payload (no password):", {k: v for k, v in payload.items() if k != "password"})

    resp = session.post(url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()

    print("Authentication succeeded. HTTP", resp.status_code)
    print("Response JSON:", resp.json())
    print("Session cookies:", session.cookies.get_dict())

    return session


def list_all_categories(session: requests.Session, base_url: str):
    """
    Retrieve and print all URL categories (both built-in and custom).
    """
    base = normalize_base_url(base_url)
    endpoint = f"{base}/urlCategories"

    print("GET", endpoint)
    resp = session.get(endpoint, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    categories = resp.json()

    print(f"[+] Found {len(categories)} URL categories:")
    print("=" * 80)

    for cat in categories:
        cid = cat.get("id", "")
        cname = cat.get("configuredName", "")
        desc = cat.get("description", "")
        is_custom = cat.get("customCategory", False)
        urls = cat.get("urls", [])
        print(f"- ID: {cid}")
        print(f"  Name: {cname}")
        print(f"  Custom: {is_custom}")
        print(f"  Description: {desc}")
        print(f"  URLs: {len(urls)} entries")
        if is_custom:
            print("  * This is a custom category you can edit (e.g., CUSTOM_BLACKLIST).")
        print("-" * 80)

    return categories


def logout_from_zscaler(session: requests.Session, base_url: str):
    """Logout by DELETE /authenticatedSession."""
    base = normalize_base_url(base_url)
    endpoint = f"{base}/authenticatedSession"
    print("DELETE", endpoint)
    resp = session.delete(endpoint, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    print("Logged out. HTTP", resp.status_code)


def main(username: str, password: str, api_key: str, base_url: str, verify_ssl=True):
    session: Optional[requests.Session] = None
    try:
        print("[*] Logging in to Zscaler...")
        session = login_to_zscaler(username, password, api_key, base_url, verify_ssl=verify_ssl)

        # Retrieve and list all URL categories
        list_all_categories(session, base_url)

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
