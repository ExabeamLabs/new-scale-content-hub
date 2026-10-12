import requests
import re
import json


def main(client_id, client_secret, detections_info, table_name):
    base_url = "https://api.us-west.exabeam.cloud"

    # --- Parse IPs from detections_info ---
    if isinstance(detections_info, (list, dict)):
        detections_str = json.dumps(detections_info)
    else:
        detections_str = str(detections_info)

    src_ip_pattern = r'\\?"src_ip\\?"\s*:\s*\\?"([^"\\]+)\\?"'
    matches = re.findall(src_ip_pattern, detections_str)

    ipv4_matches = []
    ipv6_matches = []
    for ip in matches:
        if "." in ip:
            ipv4_matches.append(ip)
        elif ":" in ip:
            ipv6_matches.append(ip)

    ips = list(set(ipv4_matches + ipv6_matches))

    if not ips:
        raise Exception(f"No IPs found in detections_info. Sample: {detections_str[:300]}")

    # --- Auth ---
    auth_url = f"{base_url}/auth/v1/token"
    auth_payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    }
    auth_headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }
    auth_response = requests.post(auth_url, json=auth_payload, headers=auth_headers)
    auth_response.raise_for_status()
    access_token = auth_response.json().get("access_token")
    if not access_token:
        raise Exception(f"No access_token found in auth response: {auth_response.text}")

    headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}"
    }

    # --- Look up table metadata to get table ID and attribute ID for "IP" column ---
    tables_url = f"{base_url}/context-management/v1/tables"
    tables_response = requests.get(tables_url, headers=headers, timeout=60)
    tables_response.raise_for_status()
    all_tables = tables_response.json()

    table_metadata = None
    for table in all_tables:
        if table.get("name") == table_name:
            table_metadata = table
            break
    if not table_metadata:
        raise ValueError(f"Context table with name '{table_name}' not found.")

    table_id = table_metadata["id"]
    attribute_map = {attr["displayName"]: attr["id"] for attr in table_metadata.get("attributes", [])}

    ip_attr_id = attribute_map.get("IP")
    if not ip_attr_id:
        raise ValueError(f"Attribute 'IP' not found in table '{table_name}'. Available: {list(attribute_map.keys())}")

    # --- Build records using attribute ID as the key ---
    translated_records = [{ip_attr_id: ip} for ip in ips]

    records_url = f"{base_url}/context-management/v1/tables/{table_id}/addRecords"
    payload = {
        "operation": "append",
        "data": translated_records
    }

    response = requests.post(records_url, headers=headers, json=payload, timeout=60)
    response.raise_for_status()

    return {
        "status": "success",
        "message": f"Successfully appended {len(ips)} records to table '{table_name}'.",
        "ips_added": ips,
        "response": response.text
    }
