# Marcos Schejtman LATAM SE Manager <marcos.schejtman@exabeam.com> - July 2026 - Email If Stuck #

import requests
from urllib.parse import quote


def get_graph_token(tenant_id: str, client_id: str, client_secret: str):
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default"
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded"
    }
    response = requests.post(url, data=payload, headers=headers)

    if response.status_code == 200:
        return response.json()

    return response.json()


def graph_headers(access_token: str):
    return {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": "Bearer " + str(access_token)
    }


def graph_result(response):
    if response.text:
        try:
            return response.json()
        except ValueError:
            return {
                "status_code": response.status_code,
                "response": response.text
            }

    return {
        "status_code": response.status_code,
        "success": response.ok
    }


def encode_user_id(user_id: str):
    return quote(str(user_id).strip(), safe="")


def main(
    user_id: str,
    tenant_id: str,
    client_id: str,
    client_secret: str
):
    key = get_graph_token(tenant_id, client_id, client_secret)
    if "access_token" not in key:
        return key

    encoded_user_id = encode_user_id(user_id)
    headers = graph_headers(key["access_token"])

    disable_url = f"https://graph.microsoft.com/v1.0/users/{encoded_user_id}"
    disable_payload = {
        "accountEnabled": False
    }
    disable_response = requests.patch(disable_url, json=disable_payload, headers=headers)

    revoke_url = f"https://graph.microsoft.com/v1.0/users/{encoded_user_id}/revokeSignInSessions"
    revoke_response = requests.post(revoke_url, headers=headers)

    return {
        "disable_user": graph_result(disable_response),
        "revoke_session": graph_result(revoke_response)
    }
