import requests
import urllib.parse
import wmill

CLIENT_ID = wmill.get_variable("f/exabeam/CrowdStrike_Falcon/Falcon_API/CLIENT_ID")
CLIENT_SECRET = wmill.get_variable("f/exabeam/CrowdStrike_Falcon/Falcon_API/CLIENT_SECRET")
BASE_URL = wmill.get_variable("f/exabeam/CrowdStrike_Falcon/Falcon_API/BASE_URL")


def get_oauth2_token():
    url = f"{BASE_URL}/oauth2/token"
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    resp = requests.post(url, data=data)
    resp.raise_for_status()
    return resp.json()['access_token']


def get_device_id_by_hostname(hostname, token):
    headers = {'Authorization': f'Bearer {token}'}
    filter_str = f'hostname:"{hostname}"'
    search_url = f"{BASE_URL}/devices/queries/devices/v1?filter={urllib.parse.quote(filter_str)}"
    resp = requests.get(search_url, headers=headers)
    resp.raise_for_status()
    ids = resp.json().get("resources", [])
    if not ids:
        raise Exception(f"No device found with hostname '{hostname}'")
    return ids[0]


def get_device_details(device_id, token):
    headers = {'Authorization': f'Bearer {token}'}
    url = f"{BASE_URL}/devices/entities/devices/v1?ids={device_id}"
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    return resp.json()


def lift_containment(device_id, token):
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    url = f"{BASE_URL}/devices/entities/devices-actions/v2?action_name=lift_containment"
    data = {
        "ids": [device_id]
    }
    resp = requests.post(url, headers=headers, json=data)
    resp.raise_for_status()
    return resp.json()


def main(hostname):
    if isinstance(hostname, list):
        hostname = hostname[0] if hostname else ""

    try:
        print("Requesting OAuth2 token...")
        token = get_oauth2_token()

        print(f"Looking up device ID for hostname '{hostname}'...")
        device_id = get_device_id_by_hostname(hostname, token)
        print(f"Device ID found: {device_id}")

        print("Getting device details...")
        details = get_device_details(device_id, token)
        print("Device details:")
        print(details)

        print("Attempting to lift containment on the device...")
        lift_response = lift_containment(device_id, token)
        print("Lift containment response:")
        print(lift_response)

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":  # supply real values here or via your platform
    main(hostname="")
