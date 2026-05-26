# Mark Ulmer US Service Consultant - May 2026 - Initial

import urllib.request
import json
import ipaddress

def check_ip_virustotal(ip, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            attributes = data["data"]["attributes"]["last_analysis_stats"]

            return {
                "IP": ip,
                "Malicious Reports": attributes["malicious"],
                "Harmless Reports": attributes["harmless"],
                "Suspicious Reports": attributes["suspicious"]
            }

    except urllib.error.HTTPError as e:
        return f"API request failed: {e.reason} ({e.code})"
    except Exception as e:
        return f"API request failed: {e}"

def main(ip_to_check, VT_API_KEY: str):
    ip_to_check = "1.1.1.1"

  # Check VT_API_KEY
    if not VT_API_KEY:
        raise RuntimeError("VT_API_KEY environment variable is not set")

    ip_to_check = ip_to_check.strip()

    # Validate IP address
    try:
        ipaddress.ip_address(ip_to_check)
    except ValueError:
        return f"Invalid IP address provided: {ip_to_check}"

    result = check_ip_virustotal(ip_to_check, VT_API_KEY)
    return result
