# Author: Exabeam Labs
# Version: 1.2
# Date updated: Sept 21 2026
# Action Name: VirusTotal_Action_Get_IP_Report
# Description: Retrieves a report for a given IP address. The report includes threat reputation from various antivirus engines.

import urllib.request
import json
import ipaddress
import wmill

def check_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    api_key = wmill.get_variable("f/exabeam/VirusTotal/VirusTotal/VT_API_KEY")
    headers = {"x-apikey": api_key}
    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            attrs = data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})

        return {
            "status_code": response.status,
            "data": {
                "ip": ip,
                "is_public": not ipaddress.ip_address(ip).is_private,
                "malicious_reports": stats.get("malicious", 0),
                "suspicious_reports": stats.get("suspicious", 0),
                "harmless_reports": stats.get("harmless", 0),
                "reputation_score": attrs.get("reputation", 0),
                "country": attrs.get("country", "Unknown"),
                "as_owner": attrs.get("as_owner", "Unknown"),
                "asn": attrs.get("asn", "Unknown"),
            }
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

    # Validate IP address
    try:
        ipaddress.ip_address(ip_to_check)
    except ValueError:
        return {
            "status_code": 400,
            "error": f"Invalid IP address provided: {ip_to_check}",
        }

    return check_ip_virustotal(ip_to_check)


