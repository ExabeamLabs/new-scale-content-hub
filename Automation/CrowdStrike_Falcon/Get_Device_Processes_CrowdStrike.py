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

def get_device_id_by_hostname(hostname):
    try:
        token = get_oauth2_token()
        headers = {'Authorization': f'Bearer {token}'}
        filter_str = f'hostname:"{hostname}"'
        search_url = f"{BASE_URL}/devices/queries/devices/v1?filter={urllib.parse.quote(filter_str)}"
        resp = requests.get(search_url, headers=headers, timeout=30)
        _raise_for_status(resp, f"CrowdStrike device search for hostname '{hostname}'")
        ids = resp.json().get("resources", [])
        if not ids:
            raise ValueError(f"No device found with hostname '{hostname}'")
        return ids[0]
    except (requests.RequestException, ValueError, RuntimeError):
        raise

def list_processes(device_id, ioc_type, ioc_value):
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


def main(hostname, ioc_type, ioc_value):
    try:
        if isinstance(hostname, list):
            hostname = hostname[0] if hostname else ""
        if not hostname:
            raise ValueError("Hostname is required")
        if isinstance(ioc_type, list):
            ioc_type = ioc_type[0] if ioc_type else ""
        if isinstance(ioc_value, list):
            ioc_value = ioc_value[0] if ioc_value else ""

        device_id = get_device_id_by_hostname(hostname)

        return list_processes(device_id, ioc_type, ioc_value)
    except (ValueError, RuntimeError) as exc:
        raise RuntimeError(f"Get_Device_Details_CrowdStrike main failed: {exc}") from exc
