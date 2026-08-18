# Reference:  https://developer.crowdstrike.com/api-reference/collections/iocs/#devicesranon
#TODO - Add try catch & http Response codes
#TODO - Add asHTML option.  Need to see and select the various information.

import requests
import urllib.parse
import wmill

CLIENT_ID = wmill.get_variable("f/exabeam/CrowdStrike_Falcon/Falcon_API/CLIENT_ID"),
CLIENT_SECRET = wmill.get_variable("f/exabeam/CrowdStrike_Falcon/Falcon_API/CLIENT_SECRET"),
BASE_URL =  wmill.get_variable("f/exabeam/CrowdStrike_Falcon/Falcon_API/BASE_URL")


def get_oauth2_token():
    url = f"{BASE_URL}/oauth2/token"
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    resp = requests.post(url, data=data)
    resp.raise_for_status()
    return resp.json()['access_token']


def list_processes(ioc_type, ioc_value, device_id):
    token = get_oauth2_token()
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }
    params = {
        'type': ioc_type,
        'value': ioc_value,
        'device_id': device_id
    }
    url = f"{BASE_URL}/indicators/queries/processes/v1?{urllib.parse.urlencode(params)}"
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    data = resp.json()

    if not data.get("resources"):
        raise Exception(
            f"No processes found for IOC '{ioc_value}' ({ioc_type}) on device '{device_id}'"
        )

    return data


def main(ioc_type, ioc_value, device_id):
    if isinstance(ioc_type, list):
        ioc_type = ioc_type[0] if ioc_type else ""
    if isinstance(ioc_value, list):
        ioc_value = ioc_value[0] if ioc_value else ""
    if isinstance(device_id, list):
        device_id = device_id[0] if device_id else ""

    return list_processes(ioc_type, ioc_value, device_id)


if __name__ == "__main__":
    result = main(
        ioc_type="",     # e.g. "sha256", "md5", "sha1", "domain", "ipv4", "ipv6"
        ioc_value="",    # the actual IOC, e.g. a hash, domain, or IP
        device_id=""     # CrowdStrike AID for the host
    )
    print(result)