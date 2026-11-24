# Author: Exabeam Labs
# Version: 1.0
# Date updated: Oct 12 2026
# Action Name: IPQualityScore_Action_Get_Phone_Reputation
# Description: Validates a phone number and returns a fraud score, line type, carrier, and VOIP, prepaid, spammer, and recent-abuse indicators.

import urllib.request
import urllib.error
import json
from urllib.parse import quote, urlencode
import wmill

IPQS_API_BASE = "https://www.ipqualityscore.com/api/json"


def check_phone_ipqs(phone, countries, strictness):
    api_key = wmill.get_variable("f/exabeam/IPQualityScore/IPQualityScore/IPQS_API_KEY")
    params = [("strictness", strictness)] + [("country[]", country) for country in countries]
    query = urlencode(params)
    url = f"{IPQS_API_BASE}/phone/{quote(api_key, safe='')}/{quote(phone, safe='')}?{query}"
    req = urllib.request.Request(url, headers={"accept": "application/json"}, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            status_code = response.status
            data = json.loads(response.read().decode())

        # IPQS returns HTTP 200 for most errors (bad key, no credits, invalid number)
        if not data.get("success", False):
            return {
                "status_code": 400,
                "error": f"IPQualityScore request failed: {data.get('message', 'Unknown error')}",
            }

        return {
            "status_code": status_code,
            "data": {
                "phone": phone,
                "valid": data.get("valid"),
                "active": data.get("active"),
                "fraud_score": data.get("fraud_score", 0),
                "risky": data.get("risky"),
                "recent_abuse": data.get("recent_abuse"),
                "spammer": data.get("spammer"),
                "leaked": data.get("leaked"),
                "voip": data.get("VOIP"),
                "prepaid": data.get("prepaid"),
                "do_not_call": data.get("do_not_call"),
                "line_type": data.get("line_type"),
                "carrier": data.get("carrier"),
                "active_status": data.get("active_status"),
                "formatted": data.get("formatted"),
                "country": data.get("country"),
                "region": data.get("region"),
                "city": data.get("city"),
                "request_id": data.get("request_id"),
            }
        }

    except urllib.error.HTTPError as e:
        return {"status_code": e.code, "error": f"API request failed: {e.reason}"}
    except Exception as e:
        return {"status_code": 500, "error": f"API request failed: {e}"}


def main(phone_to_check, countries: list = None, strictness: int = 0):
    """
    Args:
        phone_to_check: Phone number, ideally including the country dialing code.
        countries: Optional expected country codes, e.g. ["US", "CA"]. A
                   comma-separated string is also accepted. Recommended for
                   numbers under 10 digits.
        strictness: Optional verification strictness (0 is recommended).
    """
    if isinstance(phone_to_check, list):
        if not phone_to_check:
            return {"status_code": 400, "error": "No phone number provided."}
        phone_to_check = phone_to_check[0]

    if not isinstance(phone_to_check, (str, int)) or not str(phone_to_check).strip():
        return {"status_code": 400, "error": "No phone number provided."}

    # Strip formatting such as +, spaces, dashes, dots, and parentheses
    digits = "".join(ch for ch in str(phone_to_check) if ch.isdigit())
    if not 7 <= len(digits) <= 15:
        return {
            "status_code": 400,
            "error": f"Invalid phone number provided: {phone_to_check}",
        }

    if isinstance(countries, str):
        countries = countries.split(",")
    countries = [str(c).strip().upper() for c in (countries or []) if str(c).strip()]

    if not isinstance(strictness, int) or strictness < 0:
        return {"status_code": 400, "error": "strictness must be a non-negative integer."}

    return check_phone_ipqs(digits, countries, strictness)
