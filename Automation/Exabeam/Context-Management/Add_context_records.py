import requests

import requests
from typing import List, Dict, Any

# --- Helper Functions ---
def _get_access_token(api_key_id: str, api_key_secret: str, base_url: str) -> str:
    """Internal function to fetch a fresh access token."""
    token_url = f"{base_url}/auth/v1/token"
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }

    payload = {
        'grant_type': 'client_credentials',
        'client_id': api_key_id,
        'client_secret': api_key_secret
    }
    try:
        response = requests.post(token_url, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()['access_token']
    except requests.exceptions.RequestException as e:
        raise Exception(f"Authentication failed: {e}")

def _get_table_metadata(base_url: str, headers: Dict, table_name: str):
    tables_url = f"{base_url}/context-management/v1/tables"
    try:
        response = requests.get(tables_url, headers=headers, timeout=60)
        response.raise_for_status()
        all_tables = response.json()
        for table in all_tables:
            if table.get("name") == table_name:
                return table
        # If the loop completes without finding a match, raise an error.
        raise ValueError(f"Context table with name '{table_name}' not found.")
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to look up table metadata: {e}")

def _translate_record_attributes_to_id(base_url: str, headers: dict, table_name: str, records: list) -> list:
    table_metadata = _get_table_metadata(base_url=base_url, headers=headers, table_name=table_name)
    attribute_map = {attr['displayName']: attr['id'] for attr in table_metadata.get('attributes', [])}
    translated_records = []
    for record in records:
        translated_record = {}
        for key, value in record.items():
            attr_id = attribute_map.get(key)
            if attr_id:
                translated_record[attr_id] = value
            else:
                raise ValueError(f"Attribute '{key}' not found in table metadata.")
        translated_records.append(translated_record)
    return translated_records

def _get_table_id_from_name(base_url: str, headers: Dict, table_name: str) -> str:
    """Finds a table's ID from its name by querying the list of all tables."""
    table = _get_table_metadata(base_url, headers, table_name)
    return table["id"]

def _add_record_to_table(base_url: str, headers: dict, table_name: str, records: list, mode: str = 'append') -> Dict[str, Any]:
    mode = mode.lower()
    if mode not in ['append', 'replace']:
        raise ValueError("Invalid mode specified. Must be either 'append' or 'replace'.")

    try:
        table_id = _get_table_metadata(base_url=base_url, headers=headers, table_name=table_name).get('id', None)
        if not table_id:
            raise ValueError(f"Context table with name '{table_name}' not found.")

        records_url = f"{base_url}/context-management/v1/tables/{table_id}/addRecords"

        translated_records = _translate_record_attributes_to_id(base_url=base_url, headers=headers, table_name=table_name, records=records)

        payload = {
            'operation': mode,
            'data': translated_records
            }

        # Use the chosen method to make the API call.
        response = requests.post(records_url, headers=headers, json=payload, timeout=60)
        response.raise_for_status()

        # Create a user-friendly success message based on the mode.
        action_verb = "appended/updated" if mode == 'append' else "replaced all"
        message = f"Successfully {action_verb} {len(records)} records in table '{table_name}'."

        return {"status": "success", "message": message}
    except (requests.exceptions.RequestException, ValueError) as e:
        raise Exception(f"Failed to {mode} records: {e}")

# --- Main Action Function ---
def main(exabeam_api_service_configuration: dict,
         table_name: str,
         records: List[Dict[str, Any]],
         mode: str = 'append') -> Dict[str, Any]:
    """
    AAM Action: Adds or replaces records in a context table by its display name.

    Args:
        exabeam_api_service_configuration: A dictionary containing 'region', 'key_id', and 'key_secret'.
        table_name: The human-readable name of the context table.
        records: A list of dictionaries, where each dictionary is a record.
        mode: The operation mode. 'append' (default) adds/updates records. 
              'replace' deletes all existing records and replaces them with the new set.
    """

    # Build the URL dynamically based on the provided region.
    region = exabeam_api_service_configuration["region"]
    base_url = f"https://api.{region}.exabeam.cloud"

    api_key_id = exabeam_api_service_configuration["key_id"]
    api_key_secret = exabeam_api_service_configuration["key_secret"]

    access_token = _get_access_token(api_key_id=api_key_id, api_key_secret=api_key_secret, base_url=base_url)

    auth_headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
    }

    record_add_result = _add_record_to_table(base_url=base_url,
                                             headers=auth_headers,
                                             table_name=table_name,
                                             records=records,
                                             mode=mode)
    return record_add_result
