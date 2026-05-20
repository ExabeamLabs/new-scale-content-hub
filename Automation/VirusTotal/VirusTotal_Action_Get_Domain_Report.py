# Mark Ulmer US Service Consultant - May 2026 - Domain Lookup #

import urllib.request
import json
import ipaddress

def check_domain_virustotal(domain, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            attributes = data["data"]["attributes"]["last_analysis_stats"]

            return {
                "Domain": domain,
                "Malicious Reports": attributes["malicious"],
                "Harmless Reports": attributes["harmless"],
                "Suspicious Reports": attributes["suspicious"]
            }

    except urllib.error.HTTPError as e:
        return f"API request failed: {e.reason} ({e.code})"
    except Exception as e:
        return f"API request failed: {e}"

def main(domain_to_check, VT_API_KEY):
    # Check VT_API_KEY
    if not VT_API_KEY:
        raise RuntimeError("VT_API_KEY environment variable is not set")

    # Check if input is a list, and pick the first item
    if isinstance(domain_to_check, list):
        if not domain_to_check:
            return "No domain provided."
        domain_to_check = domain_to_check[0]

    domain_to_check = domain_to_check.strip()

    result = check_domain_virustotal(domain_to_check, VT_API_KEY)
    return result
