# Charlie Mac UK TAM - May 2025 - Email If Stuck #
# Link "IP TO CHECK" variable to an IP field from input flow #

import urllib.request
import json
import ipaddress

# Your VirusTotal API Key (Replace with your actual API key)
VT_API_KEY = "XYZ"

def check_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}

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

def main(ip_to_check):
    # Check if input is a list, and pick the first item
    if isinstance(ip_to_check, list):
        if not ip_to_check:
            return "No IP address provided."
        ip_to_check = ip_to_check[0]

    ip_to_check = ip_to_check.strip()

    # Validate IP address
    try:
        ipaddress.ip_address(ip_to_check)
    except ValueError:
        return f"Invalid IP address provided: {ip_to_check}"

    result = check_ip_virustotal(ip_to_check)
    return result