# Delete records from an existing custom context table
import requests
from typing import List, Dict, Union
import json

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

def _get_table_id_from_name(base_url: str, headers: Dict, table_name: str) -> str:
    """Finds a table's ID from its name by querying the list of all tables."""
    try:
        tables_url = f"{base_url}/context-management/v1/tables"
        response = requests.get(tables_url, headers=headers, timeout=60)
        response.raise_for_status()
        all_tables = response.json()
        for table in all_tables:
            if table.get("name") == table_name:
                return table["id"]
        # If the loop completes without finding a match, raise an error.
        raise ValueError(f"Context table with name '{table_name}' not found.")
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to look up table ID: {e}")

def _delete_records_from_table_by_key(base_url: str, headers: dict, table_name: str, record_keys: List[str]):

    table_id = _get_table_id_from_name(base_url, headers, table_name)

    url = f"{base_url}/context-management/v1/tables/{table_id}/deleteRecords"

    payload = {"ids": record_keys}

    response = requests.delete(url, json=payload, headers=headers, timeout=60)
    response.raise_for_status()

    delete_response = response.json()
    return delete_response

# --- Main Action Function ---
def main(
    exabeam_api_service_configuration: dict,
    table_name: str,
    record_keys: Union[list, str]) -> Dict[str, str]:
    """
    AAM Action: Deletes a single record from a context table identified by a key-value pair.

    Args:
        exabeam_api_service_configuration: A dictionary containing 'region', 'key_id', and 'key_secret'.
        table_name: The human-readable name of the context table.
        record_keys: The value of the key to identify the record to delete (e.g., "192.168.1.100").
    """
    # Build the URL dynamically based on the provided region.
    region = exabeam_api_service_configuration["region"]
    base_url = f"https://api.{region}.exabeam.cloud"
    
    api_key_id = exabeam_api_service_configuration["key_id"]
    api_key_secret = exabeam_api_service_configuration["key_secret"]

    access_token = _get_access_token(api_key_id=api_key_id, api_key_secret=api_key_secret, base_url=base_url)

    headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
    }

    if isinstance(record_keys, str):
        record_keys = [record_keys]

    try:
        delete_response = _delete_records_from_table_by_key(base_url, headers, table_name, record_keys)
        delete_count = delete_response.get('jsonEntries')
        return {
            "status": "success",
            "message": f"Successfully deleted {delete_count} records from table '{table_name}' where key value = {json.dumps(record_keys)}.",
        }

    except (requests.exceptions.RequestException, ValueError) as e:
        raise Exception(f"Failed to delete record: {e}")
