# Mark Ulmer US Service Consultant - July 2026 - URL Report #

import wmill
import urllib.request
import json
import base64
from urllib.parse import urlparse


def check_url_virustotal(url, asHTML: bool):
    api_key = wmill.get_variable("f/exabeam/VirusTotal/VirusTotal/VT_API_KEY")
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
            attrs = data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})

        if asHTML:
            note = f"""<h4>Threat Intelligence Summary</h4>
            <ul>
            <li><b>Source:</b> VirusTotal</li>
            <li><b>URL:</b> {url}</li>
            <li><b>Reputation Score:</b> {attrs.get("reputation", 0)}</li>
            <li><b>Malicious Reports:</b> {stats.get("malicious", 0)}</li>
            <li><b>Suspicious Reports:</b> {stats.get("suspicious", 0)}</li>
            <li><b>Harmless Reports:</b> {stats.get("harmless", 0)}</li>
            </ul>""".strip()
            return note
        else:
            return {
                "URL": url,
                "Malicious Reports": stats.get("malicious", 0),
                "Suspicious Reports": stats.get("harmless", 0),
                "Harmless Reports": stats.get("suspicious", 0)
            }

    except urllib.error.HTTPError as e:
        return f"API request failed: {e.reason} ({e.code})"
    except Exception as e:
        return f"API request failed: {e}"

def main(url_to_check, asHTML: bool):
    #Check imputs.
    parsed_url = urlparse(url_to_check)

    if not (parsed_url.scheme and parsed_url.netloc):
        raise ValueError(f"Invalid URL format: '{url}'. A scheme (e.g., http, https) and a domain are required.")

    report = check_url_virustotal(url_to_check, asHTML)
    return report
