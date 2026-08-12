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


def get_user_uuid_by_username(username):
    token = get_oauth2_token()
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }
    filter_str = f'username:"{username}"'
    url = f"{BASE_URL}/user-management/queries/users/v1?filter={urllib.parse.quote(filter_str)}"
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    uuids = resp.json().get("resources", [])

    if not uuids:
        raise Exception(f"No user UUID found for username '{username}'")

    return uuids[0]


def get_user_info(user_uuid):
    token = get_oauth2_token()
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }
    url = f"{BASE_URL}/users/entities/users/v1?ids={urllib.parse.quote(user_uuid)}"
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    data = resp.json()

    if not data.get("resources"):
        raise Exception(f"No user info found for UUID '{user_uuid}'")

    return data


def main(username):
    if isinstance(username, list):
        username = username[0] if username else ""

    user_uuid = get_user_uuid_by_username(username)
    return get_user_info(user_uuid)


if __name__ == "__main__":
    result = main(username="")
    print(result)