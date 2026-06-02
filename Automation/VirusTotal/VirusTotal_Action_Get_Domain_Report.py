# Mark Ulmer US Service Consultant - May 2026 - Domain Lookup #

import urllib.request
import json
import wmill
import ipaddress

def check_domain_virustotal(domain, asHTML: bool):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    api_key = wmill.get_variable("f/exabeam/VirusTotal/VirusTotal/VT_API_KEY")
    headers = {"x-apikey": api_key}

    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            attrs = data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})

        if asHTML: 
            note = f"""<h4>Threat Intelligence Summary</h4>
            <ul>
            <li><b>Source:</b> VirusTotal</li>
            <li><b>Domain:</b> {domain}</li>
            <li><b>Reputation Score:</b> {attrs.get("reputation", 0)}</li>
            <li><b>Malicious Reports:</b> {stats.get("malicious", 0)}</li>
            <li><b>Suspicious Reports:</b> {stats.get("suspicious", 0)}</li>
            <li><b>Harmless Reports:</b> {stats.get("harmless", 0)}</li>
            </ul>""".strip()
            return note
        else:
            return {
                "domain": domain,
                "reputation_score": attrs.get("reputation", 0),
                "malicious_reports": stats.get("malicious", 0),
                "suspicious_reports": stats.get("suspicious", 0),
                "harmless_reports": stats.get("harmless", 0),
            }

    except urllib.error.HTTPError as e:
        return f"API request failed: {e.reason} ({e.code})"
    except Exception as e:
        return f"API request failed: {e}"

def main(domain_to_check, asHTML: bool):
    # Check if input is a list, and pick the first item
    if isinstance(domain_to_check, list):
        if not domain_to_check:
            return "No domain provided."
        domain_to_check = domain_to_check[0]

    domain_to_check = domain_to_check

    report = check_domain_virustotal(domain_to_check, asHTML)
    return report
