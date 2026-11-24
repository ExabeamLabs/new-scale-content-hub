# Reference:  https://developer.crowdstrike.com/api-reference/collections/intel/#queryintelindicatorentities

#TODO - Add try catch & http Response codes
#TODO - Add asHTML option.  Need to see and select the various information.

import requests
import urllib.parse
import wmill

CLIENT_ID = wmill.get_variable("f/exabeam/CrowdStrike_Falcon/CrowdStrike_Falcon/CLIENT_ID"),
CLIENT_SECRET = wmill.get_variable("f/exabeam/CrowdStrike_Falcon/CrowdStrike_Falcon/CLIENT_SECRET"),
BASE_URL =  wmill.get_variable("f/exabeam/CrowdStrike_Falcon/CrowdStrike_Falcon/BASE_URL")


def get_oauth2_token():
    url = f"{BASE_URL}/oauth2/token"
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    resp = requests.post(url, data=data)
    resp.raise_for_status()
    return resp.json()['access_token']


def get_domain_reputation(domain):
    token = get_oauth2_token(
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }
    filter_str = f'type:"domain"+indicator:"{domain}"'
    url = f"{BASE_URL}/intel/combined/indicators/v1?filter={urllib.parse.quote(filter_str)}"
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    data = resp.json()

    if not data.get("resources"):
        raise Exception(f"No reputation data found for '{domain}'")

    return data


def main(domain):
    if isinstance(domain, list):
        domain = domain[0] if domain else ""

    return get_domain_reputation(domain)


if __name__ == "__main__":
    result = main(domain="")
    print(result)
