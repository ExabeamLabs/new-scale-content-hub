# Mark Ulmer US Service Consultant - July 2026 - Initial

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
            attributes = data["data"]["attributes"]["last_analysis_stats"]

            return {
                "IP": ip
            }

    except urllib.error.HTTPError as e:
        return f"API request failed: {e.reason} ({e.code})"
    except Exception as e:
        return f"API request failed: {e}"

def main():
    ip_to_check = "1.1.1.1"
    ip_to_check = ip_to_check.strip()

    # Validate IP address
    try:
        ipaddress.ip_address(ip_to_check)
    except ValueError:
        return f"Invalid IP address provided: {ip_to_check}"

    result = check_ip_virustotal(ip_to_check)
    return result
