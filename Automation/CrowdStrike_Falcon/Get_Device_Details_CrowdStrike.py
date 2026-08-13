import requests
import urllib.parse
import wmill
import json

CLIENT_ID = wmill.get_variable("f/exabeam/CrowdStrike_Falcon/Falcon_API/CLIENT_ID")
CLIENT_SECRET = wmill.get_variable("f/exabeam/CrowdStrike_Falcon/Falcon_API/CLIENT_SECRET")
BASE_URL = wmill.get_variable("f/exabeam/CrowdStrike_Falcon/Falcon_API/BASE_URL")


def _raise_for_status(resp, action):
    try:
        resp.raise_for_status()
    except requests.HTTPError as exc:
        error_message = getattr(resp, "text", "")
        raise RuntimeError(f"{action} failed with HTTP {resp.status_code}: {error_message[:500]}") from exc


def get_oauth2_token():
    url = f"{BASE_URL}/oauth2/token"
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    try:
        resp = requests.post(url, data=data, timeout=30)
        _raise_for_status(resp, "CrowdStrike OAuth token request")
        token_data = resp.json()
        if "access_token" not in token_data:
            raise RuntimeError(f"CrowdStrike OAuth token response missing access_token. HTTP {resp.status_code}: {resp.text[:500]}")
        return token_data["access_token"]
    except requests.RequestException as exc:
        raise RuntimeError(f"CrowdStrike OAuth token request failed: {exc}") from exc


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


def get_device_details(device_id, asHTML: bool):
    try:
        token = get_oauth2_token()
        headers = {'Authorization': f'Bearer {token}'}
        url = f"{BASE_URL}/devices/entities/devices/v1?ids={device_id}"
        resp = requests.get(url, headers=headers, timeout=30)
        _raise_for_status(resp, f"CrowdStrike device details request for ID '{device_id}'")

        # Parse the JSON payload from the API response and read the actual
        # device attributes from the first resource object.
        response_data = resp.json()
        resources = response_data.get("resources", [])
        if not resources:
            raise ValueError(f"No device details found for device id '{device_id}'")

        device = resources[0]
        device_data = {
            "manufacture": device.get("system_manufacturer", "N/A"),
            "hostname": device.get("hostname", "N/A"),
            "product": device.get("system_product_name", "N/A"),
            "type": device.get("chassis_type_desc", "N/A"),
            "os": device.get("os_product_name", "N/A"),
            "local_ip": device.get("local_ip", "N/A"),
            "connection_ip": device.get("connection_ip", "N/A"),
            "external_ip": device.get("external_ip", "N/A"),
            "last_login_user": device.get("last_login_user", "N/A")
        }

        if asHTML:
            # Using an f-string to build the HTML structure.
            # The <div> provides a nice container for the information.
            html_output = f"""<div>
            <h3>Device Details: {device_data.get('hostname')}</h3>
            <ul>
                <li><strong>Manufacturer:</strong> {device_data.get('manufacture')}</li>
                <li><strong>Product:</strong> {device_data.get('product')}</li>
                <li><strong>Device Type:</strong> {device_data.get('type')}</li>
                <li><strong>Operating System:</strong> {device_data.get('os')}</li>
                <li><strong>Local IP:</strong> {device_data.get('local_ip')}</li>
                <li><strong>Connection IP:</strong> {device_data.get('connection_ip')}</li>
                <li><strong>External IP:</strong> {device_data.get('external_ip')}</li>
                <li><strong>Last Login:</strong> {device_data.get('last_login_user')}</li>
            </ul>
        </div>"""
            return html_output.strip()
        else:
            # Return the full data dictionary as a formatted JSON string.
            return json.dumps(device_data, indent=4, default=str)
    except (requests.RequestException, ValueError, RuntimeError) as exc:
        raise RuntimeError(f"Get device details failed for device id '{device_id}': {exc}") from exc


def main(hostname, asHTML: bool):
    try:
        if isinstance(hostname, list):
            hostname = hostname[0] if hostname else ""

        if not hostname:
            raise ValueError("Hostname is required")

        device_id = get_device_id_by_hostname(hostname)
        return get_device_details(device_id, asHTML)
    except (ValueError, RuntimeError) as exc:
        raise RuntimeError(f"Get_Device_Details_CrowdStrike main failed: {exc}") from exc