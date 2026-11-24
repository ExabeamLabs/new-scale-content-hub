# Author: Exabeam Labs
# Version: 1.0
# Date updated: Oct 14 2026
# Action Name: GreyNoise_Community_IP_Lookup
# Description: Retrieves free GreyNoise Community reputation for a given IPv4 address (noise, RIOT, classification, name, last seen).

import urllib.request
import urllib.error
import json
import ipaddress
import wmill


def _verdict(data):
    if data.get("noise"):
        return data.get("classification") or "unknown"
    if data.get("riot"):
        return "benign_service"
    return "not_observed"


def _community_result(ip, data):
    return {
        "status_code": 200,
        "data": {
            "ip": ip,
            "verdict": _verdict(data),
            "noise": bool(data.get("noise")),
            "riot": bool(data.get("riot")),
            "classification": data.get("classification", ""),
            "name": data.get("name", ""),
            "last_seen": data.get("last_seen", ""),
            "message": data.get("message", ""),
            "link": data.get("link") or f"https://viz.greynoise.io/ip/{ip}",
        },
    }


def check_ip_greynoise_community(ip):
    url = f"https://api.greynoise.io/v3/community/{ip}"
    api_key = wmill.get_variable("f/exabeam/GreyNoise/GreyNoise/GN_API_KEY")
    headers = {"key": api_key, "accept": "application/json"}
    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
        return _community_result(ip, data)

    except urllib.error.HTTPError as e:
        # 404 means GreyNoise has no record of the IP; that is a valid lookup result
        if e.code == 404:
            try:
                data = json.loads(e.read().decode())
            except Exception:
                data = {}
            return _community_result(ip, data)
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

    # The Community API only accepts routable IPv4 addresses
    try:
        ip_obj = ipaddress.IPv4Address(ip_to_check)
    except ValueError:
        return {
            "status_code": 400,
            "error": f"Invalid IPv4 address provided: {ip_to_check}",
        }
    if not ip_obj.is_global:
        return {
            "status_code": 400,
            "error": f"IP address is not publicly routable: {ip_to_check}",
        }

    return check_ip_greynoise_community(ip_to_check)
