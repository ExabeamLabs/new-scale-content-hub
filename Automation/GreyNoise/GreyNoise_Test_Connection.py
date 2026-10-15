# Author: Exabeam Labs
# Version: 1.0
# Date updated: Oct 14 2026
# Action Name: GreyNoise_Test_Connection
# Description: Makes a connection to GreyNoise and validates the API key.

import urllib.request
import urllib.error
import json
import wmill


def main():
    url = "https://api.greynoise.io/ping"
    api_key = wmill.get_variable("f/exabeam/GreyNoise/GreyNoise/GN_API_KEY")
    headers = {"key": api_key, "accept": "application/json"}
    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            return {
                "status_code": response.status,
                "data": {
                    "connected": True,
                    "plan": data.get("plan", ""),
                    "expiration": data.get("expiration", ""),
                    "modules": data.get("modules", ""),
                },
            }

    except urllib.error.HTTPError as e:
        return {"status_code": e.code, "error": f"API request failed: {e.reason}"}
    except Exception as e:
        return {"status_code": 500, "error": f"API request failed: {e}"}
