# Author: Exabeam Labs
# Version: 1.0
# Date updated: Oct 12 2026
# Action Name: IPQualityScore_Action_Get_IP_Reputation
# Description: Retrieves a fraud score and proxy, VPN, TOR, bot, and recent-abuse indicators for a given IP address.

import urllib.request
import urllib.error
import json
import ipaddress
from urllib.parse import quote, urlencode
import wmill

IPQS_API_BASE = "https://www.ipqualityscore.com/api/json"


def check_ip_ipqs(ip, strictness):
    api_key = wmill.get_variable("f/exabeam/IPQualityScore/IPQualityScore/IPQS_API_KEY")
    query = urlencode({"strictness": strictness, "allow_public_access_points": "true"})
    url = f"{IPQS_API_BASE}/ip/{quote(api_key, safe='')}/{quote(ip, safe='')}?{query}"
    req = urllib.request.Request(url, headers={"accept": "application/json"}, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            status_code = response.status
            data = json.loads(response.read().decode())

        # IPQS returns HTTP 200 for most errors (bad key, no credits, invalid IP)
        if not data.get("success", False):
            return {
                "status_code": 400,
                "error": f"IPQualityScore request failed: {data.get('message', 'Unknown error')}",
            }

        return {
            "status_code": status_code,
            "data": {
                "ip": ip,
                "is_public": ipaddress.ip_address(ip).is_global,
                "fraud_score": data.get("fraud_score", 0),
                "proxy": data.get("proxy"),
                "vpn": data.get("vpn"),
                "tor": data.get("tor"),
                "active_vpn": data.get("active_vpn"),
                "active_tor": data.get("active_tor"),
                "bot_status": data.get("bot_status"),
                "is_crawler": data.get("is_crawler"),
                "recent_abuse": data.get("recent_abuse"),
                "abuse_velocity": data.get("abuse_velocity"),
                "connection_type": data.get("connection_type"),
                "country_code": data.get("country_code"),
                "region": data.get("region"),
                "city": data.get("city"),
                "isp": data.get("ISP"),
                "organization": data.get("organization"),
                "asn": data.get("ASN"),
                "host": data.get("host"),
                "request_id": data.get("request_id"),
            }
        }

    except urllib.error.HTTPError as e:
        return {"status_code": e.code, "error": f"API request failed: {e.reason}"}
    except Exception as e:
        return {"status_code": 500, "error": f"API request failed: {e}"}


def main(ip_to_check, strictness: int = 0):
    # Check if input is a list, and pick the first item
    if isinstance(ip_to_check, list):
        if not ip_to_check:
            return {"status_code": 400, "error": "No IP address provided."}
        ip_to_check = ip_to_check[0]

    if not isinstance(ip_to_check, str) or not ip_to_check.strip():
        return {"status_code": 400, "error": "No IP address provided."}

    ip_to_check = ip_to_check.strip()

    # Validate IP address
    try:
        ipaddress.ip_address(ip_to_check)
    except ValueError:
        return {
            "status_code": 400,
            "error": f"Invalid IP address provided: {ip_to_check}",
        }

    if strictness not in (0, 1, 2, 3):
        return {"status_code": 400, "error": "strictness must be 0, 1, 2, or 3."}

    return check_ip_ipqs(ip_to_check, strictness)
