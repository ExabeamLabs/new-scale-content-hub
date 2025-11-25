#!/usr/bin/env python3

import time
import requests
import json
from typing import Optional, Any

REQUEST_TIMEOUT = 15  # seconds

# ---------------------------------------------------------------------
# PARAMETERS (same style)
# ---------------------------------------------------------------------
MY_USERNAME = "YOUR_USERNAME"
MY_PASSWORD = "YOUR_PASSWORD"
MY_API_KEY = "YOUR_API_KEY"
MY_BASE_URL = "https://admin.zscalerbeta.net"
VERIFY_SSL = True

# You may now pass a LIST of URLs:
# URL_TO_ADD = ["bad1.com", "bad2.com", "bad3.com"]
URL_TO_ADD = ["http://malicious-example.com", "test123.com"]

BLOCKLIST_CATEGORY = "CUSTOM_BLACKLIST"
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

    resp = session.post(url, json=payload, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()

    print("[+] Logged in successfully.")
    return session


def get_category(session: requests.Session, base_url: str, category_id: str):
    base = normalize_base_url(base_url)
    endpoint = f"{base}/urlCategories/{category_id}"

    print("GET", endpoint)
    resp = session.get(endpoint, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()

    category = resp.json()
    print("[+] Retrieved category.")
    return category


def update_category(session: requests.Session, base_url: str, category_id: str, payload: dict):
    base = normalize_base_url(base_url)
    endpoint = f"{base}/urlCategories/{category_id}"

    print("PUT", endpoint)
    resp = session.put(endpoint, json=payload, timeout=REQUEST_TIMEOUT)

    if resp.status_code == 200:
        print("[+] Category updated successfully.")
    else:
        print("[ERROR] PUT failed:", resp.status_code, resp.text)
        resp.raise_for_status()


# ---------------------------------------------------------------------
# ⭐ UPDATED: Support multiple URLs via list input
# ---------------------------------------------------------------------
def add_denylist_url(session: requests.Session, base_url: str, url_to_add: Any, category_id: str):

    # Accept list or string
    if isinstance(url_to_add, str):
        urls_to_add = [url_to_add]
    else:
        urls_to_add = list(url_to_add)

    # Lowercase all inputs
    urls_to_add = [u.lower() for u in urls_to_add]

    category = get_category(session, base_url, category_id)
    existing_urls = category.get("urls", [])

    existing_lower = [u.lower() for u in existing_urls]

    added_count = 0

    for url in urls_to_add:
        if url in existing_lower:
            print(f"[*] URL '{url}' already exists. Skipping.")
            continue

        existing_urls.append(url)
        added_count += 1

    if added_count == 0:
        print("[*] Nothing to add. All URLs already exist.")
        return

    category["urls"] = existing_urls
    update_category(session, base_url, category_id, category)

    print(f"[+] Added {added_count} URL(s) to category {category_id}")


def get_denylist_urls(session: requests.Session, base_url: str, category_id: str) -> Any:
    category = get_category(session, base_url, category_id)
    urls = category.get("urls", [])
    print(json.dumps(urls, indent=2))
    return urls


def logout_from_zscaler(session: requests.Session, base_url: str):
    base = normalize_base_url(base_url)
    endpoint = f"{base}/authenticatedSession"

    resp = session.delete(endpoint, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()

    print("[+] Logged out.")


# ---------------------------------------------------------------------
# main() UNCHANGED – Same signature
# ---------------------------------------------------------------------
def main(username: str, password: str, api_key: str, base_url: str, url_to_add: list, category_id: str, verify_ssl=True):
    session: Optional[requests.Session] = None

    try:
        session = login_to_zscaler(username, password, api_key, base_url, verify_ssl)

        add_denylist_url(session, base_url, url_to_add, category_id)

        get_denylist_urls(session, base_url, category_id)

    except Exception as e:
        print("[ERROR]", e)

    finally:
        if session:
            logout_from_zscaler(session, base_url)


# ---------------------------------------------------------------------

if __name__ == "__main__":
    if any(v.startswith("YOUR_") for v in (MY_USERNAME, MY_PASSWORD, MY_API_KEY)):
        print("Please update MY_USERNAME, MY_PASSWORD, MY_API_KEY before running.")
    else:
        main(
            MY_USERNAME,
            MY_PASSWORD,
            MY_API_KEY,
            MY_BASE_URL,
            URL_TO_ADD,           # <-- can be a list or string
            BLOCKLIST_CATEGORY,
            verify_ssl=VERIFY_SSL
        )
