# Mark Ulmer US Service Consultant - May 2026 - URL Report #

import urllib.request
import json
import base64
from urllib.parse import urlparse


def check_url_virustotal(url, api_key):
    """
    Checks a URL against the VirusTotal API.
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string.")

    parsed_url = urlparse(url)
    if not (parsed_url.scheme and parsed_url.netloc):
        raise ValueError(f"Invalid URL format: '{url}'. A scheme (e.g., http, https) and a domain are required.")

    url_id = base64.urlsafe_b64encode(f"{url}".encode()).decode().strip("=")
    urlreport = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    req = urllib.request.Request(urlreport, headers=headers, method="GET")

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

    try:
        result = check_url_virustotal(url_to_check, VT_API_KEY)
        return result
    except ValueError as e:
        # Catch validation errors from check_url_virustotal
        return str(e)
