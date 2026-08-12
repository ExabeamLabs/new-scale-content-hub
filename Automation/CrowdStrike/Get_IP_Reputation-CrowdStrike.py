import requests
import urllib.parse
import wmill

CLIENT_ID = wmill.get_variable("f/exabeam/CrowdStrike/Falcon_API/CLIENT_ID"),
CLIENT_SECRET = wmill.get_variable("f/exabeam/CrowdStrike/Falcon_API/CLIENT_SECRET"),
BASE_URL =  wmill.get_variable("f/exabeam/CrowdStrike/Falcon_API/BASE_URL")

def get_oauth2_token():
    url = f"{BASE_URL}/oauth2/token"
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    resp = requests.post(url, data=data)
    resp.raise_for_status()
    return resp.json()['access_token']


def get_ip_reputation(ip):
    token = get_oauth2_token()
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }
    filter_str = f'type:"ip_address"+indicator:"{ip}"'
    url = f"{BASE_URL}/intel/combined/indicators/v1?filter={urllib.parse.quote(filter_str)}"
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    data = resp.json()

    if not data.get("resources"):
        raise Exception(f"No reputation data found for '{ip}'")

    return data


def main(ip):
    if isinstance(ip, list):
        ip = ip[0] if ip else ""
    return get_ip_reputation(ip)


if __name__ == "__main__":
    result = main(ip="")
    print(result)
