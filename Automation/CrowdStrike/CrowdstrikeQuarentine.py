# Crowdstrike Get Device Details and Quarentine Action - Nick Oneill US TAM - Oct 2025 - Reach out with any questions
import requests
import urllib.parse

# === CONFIGURATION ===
def main(hostname: str,CLIENT_ID: str,CLIENT_SECRET: str,): # I am using hostname as the main variable to run the action on, you can use results.a.srcHosts[0] for input.
    CLIENT_ID: str
CLIENT_SECRET: str
FALCON_API = 'https://api.us-2.crowdstrike.com' # Replace with your region for CS.

def get_oauth2_token():
        url = f"{FALCON_API}/oauth2/token"
        data = {
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
    }
        resp = requests.post(url, data=data)
        resp.raise_for_status()
        return resp.json()['access_token']

def get_device_id_by_hostname(hostname: str) -> str: # This gets the device id since Crowdstrike needs ID for hostname to run quarentine action.
        token = get_oauth2_token()
        headers = {'Authorization': f'Bearer {token}'}
        filter_str = f'hostname:"{hostname}"'
        search_url = f"{FALCON_API}/devices/queries/devices/v1?filter={urllib.parse.quote(filter_str)}"
        resp = requests.get(search_url, headers=headers)
        resp.raise_for_status()
        ids = resp.json().get("resources", [])
        if not ids:
            raise Exception(f"No device found with hostname '{hostname}'")
        return ids[0]

def get_device_details(device_id: str) -> dict: # This gets additional device details in case we want to use more data for variables at some point.
        token = get_oauth2_token()
        headers = {'Authorization': f'Bearer {token}'}
        url = f"{FALCON_API}/devices/entities/devices/v1?ids={device_id}"
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        return resp.json()

def contain_device(device_id: str) -> dict: # This is the actual containment of the machine using the id associated with the host that we obtained earlier.
        token = get_oauth2_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
    }
        url = f"{FALCON_API}/devices/entities/devices-actions/v2?action_name=contain"
        data = {
            "ids": [device_id]
    }
        resp = requests.post(url, headers=headers, json=data)
        resp.raise_for_status()
        return resp.json()

    # Set the hostname here or use input()
        try:
            print(f"Looking up device ID for hostname '{hostname}'...")
            device_id = get_device_id_by_hostname(hostname)
            print(f"Device ID found: {device_id}")

            print("Getting device details...")
            details = get_device_details(device_id)
            print("Device details:")
            print(details)

            print("Attempting to contain the device...")
            containment_response = contain_device(device_id)
            print("Containment response:")
            print(containment_response)

        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
