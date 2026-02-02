#!/usr/bin/env python3
from __future__ import annotations

import csv
import os
import sys
import time
from datetime import datetime, UTC
from typing import Any, Dict, List, Optional

import requests

JAMF_BASE_URL = "https://alphasights.jamfcloud.com"
JAMF_CLIENT_ID = os.getenv("JAMF_CLIENT_ID")
JAMF_CLIENT_SECRET = os.getenv("JAMF_CLIENT_SECRET")

PAGE_SIZE = int(os.getenv("JAMF_PAGE_SIZE", "200"))
PAGE_START = int(os.getenv("JAMF_PAGE_START", "0"))
SLEEP_SEC = float(os.getenv("JAMF_SLEEP_SEC", "0.15"))
TIMEOUT_SEC = int(os.getenv("JAMF_TIMEOUT_SEC", "180"))

OUT_CSV = "/app/data/jamf_devices_friendly.csv"

session = requests.Session()
session.headers.update({"Accept": "application/json"})

_token: Optional[str] = None
_token_expires_at: float = 0.0

def require_env(name: str, value: Optional[str]) -> str:
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def safe_get(d: Dict[str, Any], *path: str) -> Any:
    cur: Any = d
    for p in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur

def get_oauth_token() -> str:
    global _token, _token_expires_at

    client_id = require_env("JAMF_CLIENT_ID", JAMF_CLIENT_ID)
    client_secret = require_env("JAMF_CLIENT_SECRET", JAMF_CLIENT_SECRET)

    if _token and time.time() < (_token_expires_at - 60):
        return _token

    url = f"{JAMF_BASE_URL}/api/oauth/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}

    resp = session.post(url, data=data, headers=headers, timeout=TIMEOUT_SEC)
    resp.raise_for_status()
    payload = resp.json()

    access_token = payload.get("access_token")
    expires_in = int(payload.get("expires_in", 1200))

    if not access_token:
        raise RuntimeError(f"OAuth response missing access_token: {payload}")

    _token = access_token
    _token_expires_at = time.time() + expires_in
    return _token

def api_get(path: str, params: Optional[dict] = None) -> Dict[str, Any]:
    url = f"{JAMF_BASE_URL}{path}"

    for attempt in range(1, 6):
        token = get_oauth_token()
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        try:
            resp = session.get(url, headers=headers, params=params, timeout=TIMEOUT_SEC)
        except requests.Timeout:
            time.sleep(min(2 * attempt, 10))
            continue

        if resp.status_code == 401:
            global _token_expires_at
            _token_expires_at = 0.0
            time.sleep(min(attempt, 3))
            continue

        if resp.status_code == 429:
            ra = resp.headers.get("Retry-After")
            sleep_s = int(ra) if ra and ra.isdigit() else min(5 * attempt, 30)
            time.sleep(sleep_s)
            continue

        if resp.status_code in (500, 502, 503, 504):
            time.sleep(min(2 * attempt, 10))
            continue

        resp.raise_for_status()
        return resp.json()

    raise RuntimeError(f"Failed GET {path} after retries")

def list_all_device_ids() -> List[str]:
    ids: List[str] = []
    page = PAGE_START
    total_count: Optional[int] = None

    while True:
        data = api_get(
            "/api/v3/computers-inventory",
            params={
                "section": "GENERAL",
                "page": page,
                "page-size": PAGE_SIZE,
                "sort": "general.name:asc",
            },
        )

        if total_count is None:
            total_count = data.get("totalCount")
            print(f"[INFO] totalCount: {total_count}")

        results = data.get("results") or []
        if not results:
            break

        for item in results:
            cid = item.get("id")
            if cid is not None:
                ids.append(str(cid))

        print(f"[INFO] Page {page}: {len(results)} devices (running total: {len(ids)})")
        page += 1

    ids = list(dict.fromkeys(ids))
    print(f"[INFO] Total IDs collected: {len(ids)}")
    return ids


def get_detail(device_id: str) -> Dict[str, Any]:
    return api_get(f"/api/v3/computers-inventory-detail/{device_id}")

def is_primary_user_local_admin(detail: Dict[str, Any]) -> str:
    primary = safe_get(detail, "general", "lastLoggedInUsernameBinary")
    if not primary:
        return "unknown"

    accounts = detail.get("localUserAccounts") or []
    if not isinstance(accounts, list):
        return "unknown"

    for acct in accounts:
        if isinstance(acct, dict) and acct.get("username") == primary:
            return "yes" if acct.get("admin") is True else "no"
    return "unknown"


DEVICE_FIELDS = [
    "serial_number","jamf_id","udid","device_name","platform",
    "user_email","user_username","user_realname","department_id",
    "primary_local_username","local_admin",
    "last_contact_time","report_date","last_ip","last_logged_in_username","jamf_binary_version",
    "enrolled_via_ade","user_approved_mdm","supervised","remote_managed","ddm_enabled",
    "last_enrolled_date","mdm_profile_expiration","site_name","enrolment_method",
    "make","model","model_identifier","mac_address","processor_type","total_ram_mb",
    "apple_silicon","battery_health","battery_capacity_percent",
    "os_name","os_version","os_build","filevault_status",
    "filevault2_enabled",
    "firewall_enabled","sip_status","gatekeeper_status","secure_boot_level",
    "bootstrap_token_escrowed_status","activation_lock_enabled","recovery_lock_enabled","attestation_status",
    "purchased","leased",
]

def build_device_row(detail: Dict[str, Any]) -> Dict[str, Any]:
    general = detail.get("general") or {}
    hardware = detail.get("hardware") or {}
    osinfo = detail.get("operatingSystem") or {}
    userloc = detail.get("userAndLocation") or {}
    disk = detail.get("diskEncryption") or {}
    sec = detail.get("security") or {}
    purchasing = detail.get("purchasing") or {}

    row = {
        "serial_number": hardware.get("serialNumber"),
        "jamf_id": detail.get("id"),
        "udid": detail.get("udid"),
        "device_name": general.get("name"),
        "platform": general.get("platform"),

        "user_email": userloc.get("email") or userloc.get("username"),
        "user_username": userloc.get("username"),
        "user_realname": userloc.get("realname"),
        "department_id": userloc.get("departmentId"),

        "primary_local_username": general.get("lastLoggedInUsernameBinary"),
        "local_admin": is_primary_user_local_admin(detail),

        "last_contact_time": general.get("lastContactTime"),
        "report_date": general.get("reportDate"),
        "last_ip": general.get("lastReportedIp") or general.get("lastIpAddress"),
        "last_logged_in_username": general.get("lastLoggedInUsernameBinary"),
        "jamf_binary_version": general.get("jamfBinaryVersion"),
        "enrolled_via_ade": general.get("enrolledViaAutomatedDeviceEnrollment"),
        "user_approved_mdm": general.get("userApprovedMdm"),
        "supervised": general.get("supervised"),
        "remote_managed": safe_get(general, "remoteManagement", "managed"),
        "ddm_enabled": general.get("declarativeDeviceManagementEnabled"),
        "last_enrolled_date": general.get("lastEnrolledDate"),
        "mdm_profile_expiration": general.get("mdmProfileExpiration"),
        "site_name": safe_get(general, "site", "name"),
        "enrolment_method": safe_get(general, "enrollmentMethod", "objectName"),

        "make": hardware.get("make"),
        "model": hardware.get("model"),
        "model_identifier": hardware.get("modelIdentifier"),
        "mac_address": hardware.get("macAddress"),
        "processor_type": hardware.get("processorType"),
        "total_ram_mb": hardware.get("totalRamMegabytes"),
        "apple_silicon": hardware.get("appleSilicon"),
        "battery_health": hardware.get("batteryHealth"),
        "battery_capacity_percent": hardware.get("batteryCapacityPercent"),

        "os_name": osinfo.get("name"),
        "os_version": osinfo.get("version"),
        "os_build": osinfo.get("build"),
        "filevault_status": osinfo.get("fileVault2Status"),

        "filevault2_enabled": disk.get("fileVault2Enabled"),
        "firewall_enabled": sec.get("firewallEnabled"),
        "sip_status": sec.get("sipStatus"),
        "gatekeeper_status": sec.get("gatekeeperStatus"),
        "secure_boot_level": sec.get("secureBootLevel"),
        "bootstrap_token_escrowed_status": sec.get("bootstrapTokenEscrowedStatus"),
        "activation_lock_enabled": sec.get("activationLockEnabled"),
        "recovery_lock_enabled": sec.get("recoveryLockEnabled"),
        "attestation_status": sec.get("attestationStatus"),

        "purchased": purchasing.get("purchased"),
        "leased": purchasing.get("leased"),
    }
    return {k: row.get(k) for k in DEVICE_FIELDS}

def write_csv(path: str, fieldnames: List[str], rows: List[Dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    try:
        require_env("JAMF_CLIENT_ID", JAMF_CLIENT_ID)
        require_env("JAMF_CLIENT_SECRET", JAMF_CLIENT_SECRET)
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        return 2

    _ = get_oauth_token()
    ids = list_all_device_ids()

    rows: List[Dict[str, Any]] = []
    for idx, device_id in enumerate(ids, start=1):
        try:
            detail = get_detail(device_id)
            rows.append(build_device_row(detail))
        except Exception as e:
            print(f"[WARN] Failed device id={device_id}: {e}", file=sys.stderr)

        if idx % 25 == 0:
            print(f"[INFO] Processed {idx}/{len(ids)} devices")

        time.sleep(SLEEP_SEC)

    write_csv(OUT_CSV, DEVICE_FIELDS, rows)
    print(f"[DONE] Wrote {OUT_CSV} ({len(rows)} rows) at {datetime.now(UTC).isoformat()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
