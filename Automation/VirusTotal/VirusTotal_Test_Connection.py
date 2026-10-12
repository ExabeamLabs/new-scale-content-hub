# Author: Exabeam Labs
# Version: 1.2
# Date updated: Sept 21 2026
# Action Name: VirusTotal_Test_Connection
# Description: Makes a connection to VirusTotal and validates API key.

import urllib.request
import ipaddress
import wmill

def check_connection_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    api_key = wmill.get_variable("f/exabeam/VirusTotal/VirusTotal/VT_API_KEY")
    headers = {"x-apikey": api_key}
    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req) as response:
            return {
                "status_code": response.status,
                "data": {
                    "connected": True,
                    "ip": ip,
                },
            }

    except urllib.error.HTTPError as e:
        return {"status_code": e.code, "error": f"API request failed: {e.reason}"}
    except Exception as e:
        return {"status_code": 500, "error": f"API request failed: {e}"}

def main():
    ip_to_check = "1.1.1.1"
    ip_to_check = ip_to_check.strip()

    # Validate IP address
    try:
        ipaddress.ip_address(ip_to_check)
    except ValueError:
        return {
            "status_code": 400,
            "error": f"Invalid IP address provided: {ip_to_check}",
        }

    return check_connection_virustotal(ip_to_check)
