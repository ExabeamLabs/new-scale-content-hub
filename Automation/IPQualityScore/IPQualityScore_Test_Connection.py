# Author: Exabeam Labs
# Version: 1.0
# Date updated: Oct 12 2026
# Action Name: IPQualityScore_Test_Connection
# Description: Makes a connection to IPQualityScore and validates API key.

import urllib.request
import urllib.error
import json
from urllib.parse import quote
import wmill

IPQS_API_BASE = "https://www.ipqualityscore.com/api/json"


def check_connection_ipqs(ip):
    api_key = wmill.get_variable("f/exabeam/IPQualityScore/IPQualityScore/IPQS_API_KEY")
    url = f"{IPQS_API_BASE}/ip/{quote(api_key, safe='')}/{quote(ip, safe='')}"
    req = urllib.request.Request(url, headers={"accept": "application/json"}, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            status_code = response.status
            data = json.loads(response.read().decode())

        # An invalid key or exhausted credits still returns HTTP 200 with success=false
        if not data.get("success", False):
            return {
                "status_code": 401,
                "error": f"IPQualityScore connection failed: {data.get('message', 'Unknown error')}",
            }

        return {
            "status_code": status_code,
            "data": {
                "connected": True,
                "ip": ip,
            },
        }

    except urllib.error.HTTPError as e:
        return {"status_code": e.code, "error": f"API request failed: {e.reason}"}
    except Exception as e:
        return {"status_code": 500, "error": f"API request failed: {e}"}


def main():
    # Note: this performs one IP lookup, which uses one IPQS credit
    return check_connection_ipqs("1.1.1.1")
