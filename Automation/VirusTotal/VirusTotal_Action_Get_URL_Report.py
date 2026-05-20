# Mark Ulmer US Service Consultant - May 2026 - URL Report #

import urllib.request
import json
import base64
import requests

def check_url_virustotal(url, api_key):
    url_id = base64.urlsafe_b64encode(f"url".encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            attributes = data["data"]["attributes"]["last_analysis_stats"]

            return {
                "URL": url,
                "Malicious Reports": attributes["malicious"],
                "Harmless Reports": attributes["harmless"],
                "Suspicious Reports": attributes["suspicious"]
            }

    except urllib.error.HTTPError as e:
        return f"API request failed: {e.reason} ({e.code})"
    except Exception as e:
        return f"API request failed: {e}"

def main(url_to_check, VT_API_KEY):
    # Check VT_API_KEY
    if not VT_API_KEY:
        raise RuntimeError("VT_API_KEY environment variable is not set")

    # Check if input is a list, and pick the first item
    if isinstance(url_to_check, list):
        if not url_to_check:
            return "No URL provided."
        url_to_check = url_to_check[0]

    url_to_check = url_to_check.strip()

    result = check_url_virustotal(url_to_check, VT_API_KEY)
    return result
