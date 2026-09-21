# Author: Exabeam Labs
# Version: 1.2
# Date updated: Sept 21 2026
# Action Name: VirusTotal_Action_Get_Domain_Report
# Description: Retrieves a report for a given Domain. The report includes threat reputation from various antivirus engines.

import urllib.request
import json
import wmill

def check_domain_virustotal(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
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
                "domain": domain,
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

def main(domain_to_check):
    # Check if input is a list, and pick the first item
    if isinstance(domain_to_check, list):
        if not domain_to_check:
            return {"status_code": 400, "error": "No domain provided."}
        domain_to_check = domain_to_check[0]

    if not isinstance(domain_to_check, str) or not domain_to_check.strip():
        return {"status_code": 400, "error": "No domain provided."}

    domain_to_check = domain_to_check.strip()
    return check_domain_virustotal(domain_to_check)
