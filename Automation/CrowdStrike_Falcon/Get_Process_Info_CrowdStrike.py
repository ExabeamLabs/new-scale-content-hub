# Reference:  https://developer.crowdstrike.com/api-reference/collections/ioc/#entities_processes

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


def get_process_info(, process_id):
    token = get_oauth2_token()
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }
    url = f"{BASE_URL}/processes/entities/processes/v1?ids={urllib.parse.quote(process_id)}"
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    data = resp.json()

    if not data.get("resources"):
        raise Exception(f"No process info found for '{process_id}'")

    return data


def main(process_id):
    if isinstance(process_id, list):
        process_id = process_id[0] if process_id else ""

    return get_process_info(process_id)


if __name__ == "__main__":
    result = main(process_id="")
    print(result)