# py311
import requests  # import the requests library to handle HTTP requests

# -------------------------------
# 1. Configuration / Credentials
# -------------------------------
tenant_id = "X"  # Azure AD tenant ID
client_id = "Y"  # App registration client ID
client_secret = "Z"  # App registration secret
scope = "https://api.securitycenter.microsoft.com/.default"  # Scope for Microsoft Defender API

def main(device_name: str) -> None:
    """
    Windmill entrypoint. Provide the hostname/prefix via `device_name`.
    Logic is unchanged from the original script.
    """

    # OAuth2 token endpoint for client credentials flow
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    # -------------------------------
    # 2. Acquire Access Token
    # -------------------------------
    print("Requesting access token...")

    # Prepare the POST body for OAuth2 client credentials flow
    data = {
        "grant_type": "client_credentials",  # standard OAuth2 grant type
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope
    }

    # Send request to Azure AD to get an access token
    response = requests.post(token_url, data=data)
    response.raise_for_status()  # raise exception if request failed

    # Extract access token from response JSON
    token = response.json().get("access_token")
    print("Token acquired.")

    # Prepare headers for future API requests
    headers = {
        "Authorization": f"Bearer {token}"  # Bearer token auth required by Microsoft Defender API
    }

    # -------------------------------
    # 3. Query for Device
    # -------------------------------
    device_name = (device_name or "").strip()
    print(f"\nQuerying Defender for devices matching '{device_name}' ...")

    # Construct API URL to search devices using 'startswith' filter on computerDnsName
    url = f"https://api.securitycenter.microsoft.com/api/machines?$filter=startswith(computerDnsName,'{device_name}')"

    # Send GET request to retrieve matching devices
    r = requests.get(url, headers=headers)

    results = {}  # keep scope safe for later use
    # Check if request succeeded
    if r.status_code == 200:
        results = r.json()
        if results.get("value"):
            # If devices found, iterate and print basic info
            print("Device found:")
            for d in results["value"]:
                print(f" - {d['computerDnsName']} (ID: {d['id']})")
        else:
            # No devices matched the query
            print("Device not found.")
    else:
        # HTTP error occurred
        print(f"ERROR: {r.status_code} {r.reason}")
        print(r.text)

    # -------------------------------
    # 4. Unisolate Device
    # -------------------------------
    if results.get("value"):
        device = results["value"][0]  # pick first match (can modify to loop over all matches)
        device_id = device["id"]
        device_dns = device["computerDnsName"]

        print(f"\nAbout to unisolate {device_dns} (ID: {device_id})")

        # Construct the unisolation API endpoint
        unisolate_url = f"https://api.securitycenter.microsoft.com/api/machines/{device_id}/unisolate"

        # Payload: comment only
        payload = {"Comment": "unisolation via script"}

        # POST request to initiate unisolation
        resp = requests.post(unisolate_url, headers={**headers, "Content-Type": "application/json"}, json=payload)

        # Print HTTP status and response JSON for verification
        print("HTTP", resp.status_code)
        try:
            print(resp.json())
        except Exception:
            # fallback in case response is not JSON
            print(resp.text)
