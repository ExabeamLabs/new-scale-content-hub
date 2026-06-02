# Mark Ulmer US Service Consultant - May 2026 - Get an IP Address Report #

import urllib.request
import json
import ipaddress
import wmill

def check_ip_virustotal(ip, asHTML: bool):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
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
            <li><b>IP Address:</b> {ip}</li>
            <li><b>Country:</b> {attrs.get("country", "Unknown")}</li>
            <li><b>ASN:</b> {attrs.get("asn", "Unknown")} ({attrs.get("as_owner", "Unknown")})</li>
            <li><b>Reputation Score:</b> {attrs.get("reputation", 0)}</li>
            <li><b>Malicious Reports:</b> {stats.get("malicious", 0)}</li>
            <li><b>Suspicious Reports:</b> {stats.get("suspicious", 0)}</li>
            <li><b>Harmless Reports:</b> {stats.get("harmless", 0)}</li>
            </ul>""".strip()
            return note
        else:
            return {
                "ip": ip,
                "is_public": not ipaddress.ip_address(ip).is_private,
                "malicious_reports": stats.get("malicious", 0),
                "suspicious_reports": stats.get("suspicious", 0),
                "harmless_reports": stats.get("harmless", 0),
                "reputation_score": attrs.get("reputation", 0),
                "country": attrs.get("country", "Unknown"),
                "as_owner": attrs.get("as_owner", "Unknown"),
                "asn": attrs.get("asn", "Unknown"),
            }

    except urllib.error.HTTPError as e:
        return f"API request failed: {e.reason} ({e.code})"
    except Exception as e:
        return f"API request failed: {e}"

def main(ip_to_check, asHTML: bool):
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

    report = check_ip_virustotal(ip_to_check, asHTML)
    return report


