# Author: Exabeam Labs
# Version: 1.0
# Date updated: Oct 12 2026
# Action Name: IPQualityScore_Action_Get_Email_Reputation
# Description: Validates an email address and returns a fraud score plus disposable, leaked, honeypot, and recent-abuse indicators.

import urllib.request
import urllib.error
import json
from urllib.parse import quote, urlencode
import wmill

IPQS_API_BASE = "https://www.ipqualityscore.com/api/json"


def _human(value):
    # domain_age / first_seen come back as {"human": ..., "timestamp": ..., "iso": ...}
    return value.get("human") if isinstance(value, dict) else value


def check_email_ipqs(email, timeout, abuse_strictness):
    api_key = wmill.get_variable("f/exabeam/IPQualityScore/IPQualityScore/IPQS_API_KEY")
    query = urlencode({"timeout": timeout, "abuse_strictness": abuse_strictness})
    url = f"{IPQS_API_BASE}/email/{quote(api_key, safe='')}/{quote(email, safe='')}?{query}"
    req = urllib.request.Request(url, headers={"accept": "application/json"}, method="GET")

    try:
        # Allow the mail provider timeout plus headroom for the IPQS round trip
        with urllib.request.urlopen(req, timeout=timeout + 30) as response:
            status_code = response.status
            data = json.loads(response.read().decode())

        # IPQS returns HTTP 200 for most errors (bad key, no credits, invalid email)
        if not data.get("success", False):
            return {
                "status_code": 400,
                "error": f"IPQualityScore request failed: {data.get('message', 'Unknown error')}",
            }

        return {
            "status_code": status_code,
            "data": {
                "email": email,
                "valid": data.get("valid"),
                "fraud_score": data.get("fraud_score", 0),
                "disposable": data.get("disposable"),
                "recent_abuse": data.get("recent_abuse"),
                "leaked": data.get("leaked"),
                "honeypot": data.get("honeypot"),
                "spam_trap_score": data.get("spam_trap_score"),
                "frequent_complainer": data.get("frequent_complainer"),
                "suspect": data.get("suspect"),
                "catch_all": data.get("catch_all"),
                "deliverability": data.get("deliverability"),
                "smtp_score": data.get("smtp_score"),
                "overall_score": data.get("overall_score"),
                "dns_valid": data.get("dns_valid"),
                "domain_age": _human(data.get("domain_age")),
                "first_seen": _human(data.get("first_seen")),
                "domain_velocity": data.get("domain_velocity"),
                "sanitized_email": data.get("sanitized_email"),
                "timed_out": data.get("timed_out"),
                "request_id": data.get("request_id"),
            }
        }

    except urllib.error.HTTPError as e:
        return {"status_code": e.code, "error": f"API request failed: {e.reason}"}
    except Exception as e:
        return {"status_code": 500, "error": f"API request failed: {e}"}


def main(email_to_check, timeout: int = 7, abuse_strictness: int = 0):
    if isinstance(email_to_check, list):
        if not email_to_check:
            return {"status_code": 400, "error": "No email address provided."}
        email_to_check = email_to_check[0]

    if not isinstance(email_to_check, str) or not email_to_check.strip():
        return {"status_code": 400, "error": "No email address provided."}

    email_to_check = email_to_check.strip()

    local_part, _, domain = email_to_check.rpartition("@")
    if not local_part or "." not in domain or " " in email_to_check:
        return {
            "status_code": 400,
            "error": f"Invalid email address provided: {email_to_check}",
        }

    if not 1 <= timeout <= 60:
        return {"status_code": 400, "error": "timeout must be between 1 and 60 seconds."}

    if abuse_strictness not in (0, 1, 2):
        return {"status_code": 400, "error": "abuse_strictness must be 0, 1, or 2."}

    return check_email_ipqs(email_to_check, timeout, abuse_strictness)
