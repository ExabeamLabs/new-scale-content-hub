# Author: Exabeam Labs
# Version: 1.0
# Date updated: Oct 12 2026
# Action Name: IPQualityScore_Action_Get_URL_Reputation
# Description: Scans a URL or domain for phishing, malware, parking, and spam, and returns a risk score and domain details.

import urllib.request
import urllib.error
import json
from urllib.parse import quote, urlencode, urlparse
import wmill

IPQS_API_BASE = "https://www.ipqualityscore.com/api/json"


def check_url_ipqs(url_to_check, strictness):
    api_key = wmill.get_variable("f/exabeam/IPQualityScore/IPQualityScore/IPQS_API_KEY")
    query = urlencode({"strictness": strictness})
    # Full URLs must be URL-encoded into the path
    url = f"{IPQS_API_BASE}/url/{quote(api_key, safe='')}/{quote(url_to_check, safe='')}?{query}"
    req = urllib.request.Request(url, headers={"accept": "application/json"}, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            status_code = response.status
            data = json.loads(response.read().decode())

        # IPQS returns HTTP 200 for most errors (bad key, no credits, invalid URL)
        if not data.get("success", False):
            return {
                "status_code": 400,
                "error": f"IPQualityScore request failed: {data.get('message', 'Unknown error')}",
            }

        domain_age = data.get("domain_age") or {}

        return {
            "status_code": status_code,
            "data": {
                "url": url_to_check,
                "domain": data.get("domain"),
                "root_domain": data.get("root_domain"),
                "ip_address": data.get("ip_address"),
                "risk_score": data.get("risk_score", 0),
                "unsafe": data.get("unsafe"),
                "phishing": data.get("phishing"),
                "malware": data.get("malware"),
                "suspicious": data.get("suspicious"),
                "spamming": data.get("spamming"),
                "parking": data.get("parking"),
                "adult": data.get("adult"),
                "category": data.get("category"),
                "domain_rank": data.get("domain_rank"),
                "domain_age": domain_age.get("human") if isinstance(domain_age, dict) else domain_age,
                "dns_valid": data.get("dns_valid"),
                "risky_tld": data.get("risky_tld"),
                "country_code": data.get("country_code"),
                "page_status_code": data.get("status_code"),
                "final_url": data.get("final_url"),
                "redirected": data.get("redirected"),
                "request_id": data.get("request_id"),
            }
        }

    except urllib.error.HTTPError as e:
        return {"status_code": e.code, "error": f"API request failed: {e.reason}"}
    except Exception as e:
        return {"status_code": 500, "error": f"API request failed: {e}"}


def main(url_to_check, strictness: int = 0):
    if isinstance(url_to_check, list):
        if not url_to_check:
            return {"status_code": 400, "error": "No URL provided."}
        url_to_check = url_to_check[0]

    if not isinstance(url_to_check, str) or not url_to_check.strip():
        return {"status_code": 400, "error": "No URL provided."}

    url_to_check = url_to_check.strip()

    # IPQS accepts either a full URL or a bare domain
    parsed_url = urlparse(url_to_check)
    if parsed_url.scheme:
        if not parsed_url.netloc:
            return {
                "status_code": 400,
                "error": f"Invalid URL format: '{url_to_check}'. A domain is required.",
            }
    elif "." not in url_to_check or " " in url_to_check:
        return {
            "status_code": 400,
            "error": f"Invalid URL or domain: '{url_to_check}'.",
        }

    if strictness not in (0, 1, 2):
        return {"status_code": 400, "error": "strictness must be 0, 1, or 2."}

    return check_url_ipqs(url_to_check, strictness)
