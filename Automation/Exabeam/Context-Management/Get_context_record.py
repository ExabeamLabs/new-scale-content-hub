import requests
from typing import List, Dict, Any, Tuple, Optional

def _get_access_token(base_url: str, client_id: str, client_secret: str) -> str:
    """Fetches a fresh OAuth2 access token from the Exabeam API."""
    token_url = f"{base_url}/auth/v1/token"
    payload = {'grant_type': 'client_credentials', 'client_id': client_id, 'client_secret': client_secret}
    try:
        response = requests.post(token_url, data=payload)
        response.raise_for_status()
        return response.json()['access_token']
    except requests.exceptions.RequestException as e:
        raise Exception(f"Authentication failed: {e}")

def _get_table_id_from_name(base_url: str, headers: Dict, table_name: str) -> str:
    """Finds a table's unique ID from its human-readable name."""
    try:
        tables_url = f"{base_url}/context-management/v1/tables"
        response = requests.get(tables_url, headers=headers)
        response.raise_for_status()
        for table in response.json():
            if table.get("name") == table_name:
                return table["id"]
        raise ValueError(f"Context table with name '{table_name}' not found.")
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to look up table ID: {e}")

def _get_key_id_and_translation_map(base_url: str, headers: Dict, table_id: str) -> Tuple[str, Dict[str, str]]:
    """Retrieves table metadata to get the primary key's ID and an ID-to-name translation map."""
    try:
        metadata_url = f"{base_url}/context-management/v1/tables/{table_id}"
        response = requests.get(metadata_url, headers=headers)
        response.raise_for_status()
        metadata = response.json()
        primary_key_id = None
        translation_map = {}
        for attr in metadata.get("attributes", []):
            translation_map[attr["id"]] = attr["displayName"]
            if attr.get("isKey") is True:
                primary_key_id = attr["id"]
        if not primary_key_id:
            raise ValueError(f"No primary key attribute is defined for this table.")
        return primary_key_id, translation_map
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to retrieve table metadata: {e}")

def _find_record_with_pagination(base_url: str, headers: Dict, table_id: str, primary_key_id: str, key_value: Any) -> Optional[Dict[str, Any]]:
    """Handles pagination to find a specific record using its primary key ID and value."""
    limit = 500
    offset = 0
    while True:
        records_url = f"{base_url}/context-management/v1/tables/{table_id}/records"
        params = {'limit': limit, 'offset': offset}
        try:
            response = requests.get(records_url, headers=headers, params=params)
            response.raise_for_status()
            records_data = response.json().get("records", [])
            for record in records_data:
                if str(record.get(primary_key_id)) == str(key_value):
                    return record
            if len(records_data) < limit:
                return None
            offset += limit
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed while paginating through records: {e}")

def _translate_record_keys(raw_record: Dict[str, Any], translation_map: Dict[str, str]) -> Dict[str, Any]:
    """Translates a record's internal attribute IDs to human-readable names."""
    translated_record = {}
    for attr_id, value in raw_record.items():
        readable_name = translation_map.get(attr_id, attr_id)
        translated_record[readable_name] = value
    return translated_record

def main(
    exabeam_api_service_configuration: dict,
    table_name: str,
    record_key: str,
) -> Dict[str, Any]:
    """
    AAM Action: Gets a single record from a context table by its primary key value.
    """
    try:
        # Unpack configuration for readability
        region = exabeam_api_service_configuration["region"]
        client_id = exabeam_api_service_configuration["key_id"]
        client_secret = exabeam_api_service_configuration["key_secret"]
        
        base_url = f"https://api.{region}.exabeam.cloud"
        access_token = _get_access_token(base_url, client_id, client_secret)
        headers = {"accept": "application/json", "Authorization": f"Bearer {access_token}"}

        table_id = _get_table_id_from_name(base_url, headers, table_name)
        primary_key_id, translation_map = _get_key_id_and_translation_map(base_url, headers, table_id)

        raw_record = _find_record_with_pagination(base_url, headers, table_id, primary_key_id, record_key)

        if not raw_record:
            primary_key_name = translation_map.get(primary_key_id, primary_key_id)
            raise ValueError(f"Record with key '{primary_key_name}' not found.")

        return _translate_record_keys(raw_record, translation_map)

    except (requests.exceptions.RequestException, ValueError) as e:
        raise Exception(f"Failed to get record: {e}")
