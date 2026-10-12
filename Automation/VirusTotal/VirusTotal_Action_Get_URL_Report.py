# Author: Exabeam Labs
# Version: 1.2
# Date updated: Sept 21 2026
# Action Name: VirusTotal_Action_Get_URL_Report
# Description: Retrieves a report for a given URL. The report includes threat reputation from various antivirus engines.
# 

import wmill
import urllib.request
import json
import base64
from urllib.parse import urlparse


def check_url_virustotal(url):
    url_id = base64.urlsafe_b64encode(f"{url}".encode()).decode().strip("=")
    urlreport = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    api_key = wmill.get_variable("f/exabeam/VirusTotal/VirusTotal/VT_API_KEY")
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

        return {
            "status_code": response.status,
            "data": {
                "url": url,
                "reputation_score": attrs.get("reputation", 0),
                "malicious_reports": stats.get("malicious", 0),
                "suspicious_reports": stats.get("suspicious", 0),
                "harmless_reports": stats.get("harmless", 0),
            }
        }

    except urllib.error.HTTPError as e:
        return {"status_code": e.code, "error": f"API request failed: {e.reason}"}
    except Exception as e:
        return {"status_code": 500, "error": f"API request failed: {e}"}

def main(url_to_check):
    if isinstance(url_to_check, list):
        if not url_to_check:
            return {"status_code": 400, "error": "No URL provided."}
        url_to_check = url_to_check[0]

    if not isinstance(url_to_check, str) or not url_to_check.strip():
        return {"status_code": 400, "error": "No URL provided."}

    url_to_check = url_to_check.strip()
    parsed_url = urlparse(url_to_check)

    if not (parsed_url.scheme and parsed_url.netloc):
        return {
            "status_code": 400,
            "error": f"Invalid URL format: '{url_to_check}'. A scheme and domain are required.",
        }

    return check_url_virustotal(url_to_check)
