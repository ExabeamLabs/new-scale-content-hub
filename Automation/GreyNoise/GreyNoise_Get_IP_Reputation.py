# Author: Exabeam Labs
# Version: 1.0
# Date updated: Oct 14 2026
# Action Name: GreyNoise_Get_IP_Reputation
# Description: Retrieves GreyNoise reputation for a given IP address, including classification, actor, tags, and business service (RIOT) context.

import urllib.request
import urllib.error
import json
import ipaddress
import wmill


def _verdict(isi, bsi):
    # Scanner classification wins over a business-service match, so a
    # known service that is also seen attacking still reports as malicious.
    if isi.get("found"):
        return isi.get("classification") or "unknown"
    if bsi.get("found"):
        return "benign_service"
    return "not_observed"


def check_ip_greynoise(ip):
    url = f"https://api.greynoise.io/v3/ip/{ip}"
    api_key = wmill.get_variable("f/exabeam/GreyNoise/GreyNoise/GN_API_KEY")
    headers = {"key": api_key, "accept": "application/json"}
    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())

        isi = data.get("internet_scanner_intelligence") or {}
        bsi = data.get("business_service_intelligence") or {}
        metadata = isi.get("metadata") or {}
        tags = isi.get("tags") or []

        return {
            # 206 means the plan returned a subset of fields; still a usable result
            "status_code": 200,
            "data": {
                "ip": ip,
                "verdict": _verdict(isi, bsi),
                "noise": bool(isi.get("found")),
                "riot": bool(bsi.get("found")),
                "classification": isi.get("classification", ""),
                "actor": isi.get("actor", ""),
                "first_seen": isi.get("first_seen", ""),
                "last_seen": isi.get("last_seen", ""),
                "spoofable": isi.get("spoofable"),
                "tor": isi.get("tor"),
                "vpn": isi.get("vpn"),
                "vpn_service": isi.get("vpn_service", ""),
                "tags": [t.get("name") for t in tags if t.get("name")],
                "recommend_block_tags": [t.get("name") for t in tags if t.get("recommend_block")],
                "cves": isi.get("cves") or [],
                "country": metadata.get("source_country", ""),
                "organization": metadata.get("organization", ""),
                "asn": metadata.get("asn", ""),
                "rdns": metadata.get("rdns", ""),
                "network_category": metadata.get("category", ""),
                "business_service_name": bsi.get("name", ""),
                "business_service_category": bsi.get("category", ""),
                "business_service_trust_level": bsi.get("trust_level", ""),
                "link": f"https://viz.greynoise.io/ip/{ip}",
            },
        }

    except urllib.error.HTTPError as e:
        return {"status_code": e.code, "error": f"API request failed: {e.reason}"}
    except Exception as e:
        return {"status_code": 500, "error": f"API request failed: {e}"}


def main(ip_to_check):
    # Check if input is a list, and pick the first item
    if isinstance(ip_to_check, list):
        if not ip_to_check:
            return {"status_code": 400, "error": "No IP address provided."}
        ip_to_check = ip_to_check[0]

    if not isinstance(ip_to_check, str) or not ip_to_check.strip():
        return {"status_code": 400, "error": "No IP address provided."}

    ip_to_check = ip_to_check.strip()

    # Validate IP address; GreyNoise only has data on routable addresses
    try:
        ip_obj = ipaddress.ip_address(ip_to_check)
    except ValueError:
        return {
            "status_code": 400,
            "error": f"Invalid IP address provided: {ip_to_check}",
        }
    if not ip_obj.is_global:
        return {
            "status_code": 400,
            "error": f"IP address is not publicly routable: {ip_to_check}",
        }

    return check_ip_greynoise(ip_to_check)
