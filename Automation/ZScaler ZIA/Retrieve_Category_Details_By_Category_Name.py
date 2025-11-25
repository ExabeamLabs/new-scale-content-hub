#!/usr/bin/env python3
"""
"""
print(">>> STARTING EXECUTION")

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
MY_BASE_URL = "https://admin.zscalerbeta.net"
VERIFY_SSL = True

# 
MY_CATEGORY_NAME = "CUSTOM_BLACKLIST"
# ---------------------------------------------------------------------


def obfuscate_api_key(api_key: str, timestamp_ms: str) -> str:
    if not isinstance(timestamp_ms, str):
        timestamp_ms = str(timestamp_ms)

    high = timestamp_ms[-6:]
    low = str(int(high) >> 1).zfill(6)

    if len(api_key) < 12:
        raise ValueError("API key too short.")

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


def login_to_zscaler(username: str, password: str, api_key: str, base_url: str, verify_ssl=True) -> requests.Session:
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

    resp = session.post(url, json=payload, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()

    print("Authentication succeeded.")
    return session


# ---------------------------------------------------------------------
# CATEGORY LOOKUP HELPERS
# ---------------------------------------------------------------------

def get_category_id_by_name(categories, category_name):
    for cat in categories:
        if cat.get("configuredName") == category_name:
            return cat.get("id")
    return None


def get_category_by_name(categories, category_name):
    for cat in categories:
        if cat.get("configuredName") == category_name:
            return cat
    return None


# ---------------------------------------------------------------------

def list_all_categories(session: requests.Session, base_url: str):
    base = normalize_base_url(base_url)
    endpoint = f"{base}/urlCategories"

    print("GET", endpoint)
    resp = session.get(endpoint, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()

    categories = resp.json()

    print(f"[+] Found {len(categories)} URL categories.")
    print("Saving full response to all_categories.json…")

    with open("all_categories.json", "w") as f:
        json.dump(categories, f, indent=2)

    #print("\n====== FULL JSON OUTPUT (NO TRUNCATION) ======\n")
    #print(json.dumps(categories, indent=2))

    return categories


def logout_from_zscaler(session: requests.Session, base_url: str):
    base = normalize_base_url(base_url)
    endpoint = f"{base}/authenticatedSession"

    print("DELETE", endpoint)
    resp = session.delete(endpoint, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    print("Logged out.")


def main(username: str, password: str, api_key: str, base_url: str, category_name: str, verify_ssl=True):
    session: Optional[requests.Session] = None
    try:
        print("[*] Logging in…")
        session = login_to_zscaler(username, password, api_key, base_url, verify_ssl=verify_ssl)

        categories = list_all_categories(session, base_url)

        # ---- CATEGORY LOOKUP ----
        print(f"\n[*] Searching for category name: {category_name}")

        cat_id = get_category_id_by_name(categories, category_name)
        if cat_id:
            print(f"[+] Category '{category_name}' has ID: {cat_id}")
        else:
            print(f"[!] Category '{category_name}' not found.")

        cat_obj = get_category_by_name(categories, category_name)
        if cat_obj:
            print("\n[+] Full category object:")
            print(json.dumps(cat_obj, indent=2))

    except Exception as err:
        print(f"[ERROR] {err}")

    finally:
        if session:
            logout_from_zscaler(session, base_url)


if __name__ == "__main__":
    if any(v.startswith("YOUR_") for v in (MY_USERNAME, MY_PASSWORD, MY_API_KEY)):
        print("Please update MY_USERNAME, MY_PASSWORD and MY_API_KEY first.")
    else:
        main(
            MY_USERNAME,
            MY_PASSWORD,
            MY_API_KEY,
            MY_BASE_URL,
            MY_CATEGORY_NAME,
            verify_ssl=VERIFY_SSL
        )
