# requirements:
# wmill
# requests
# json

import requests
import wmill
import json
from typing import List, Dict, Any

def get_access_token():
    region = wmill.get_variable("f/exabeam/Exabeam_Threat_Center/Exabeam_Threat_Center/region")
    url = f"https://api.{region}.exabeam.cloud/auth/v1/token"

    payload = {
        "grant_type": "client_credentials",
        "client_id": wmill.get_variable("f/exabeam/Exabeam_Threat_Center/Exabeam_Threat_Center/key_id"),
        "client_secret": wmill.get_variable("f/exabeam/Exabeam_Threat_Center/Exabeam_Threat_Center/key_secret")
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200:
        key = response.json()
    else:
        return(response.json())

    headers = {
        "content-type": "application/json",
        "authorization": "Bearer " + str(key['access_token'])
    }
    return headers

def add_note_to_case(case_id: str, note) -> str:
    """Adds a note to a specific case via the Exabeam API."""
    # Construct the API endpoint URL for your region
    region = wmill.get_variable("f/exabeam/Exabeam_Threat_Center/Exabeam_Threat_Center/region")
    base_url = f"https://api.{region}.exabeam.cloud"
    url = f"{base_url}/threat-center/v1/cases/{case_id}/notes"

    headers = get_access_token()
    
    # Ensure note is a string at this point
    note_text = str(note)
    payload = {"note": note_text}

    # Send the POST request to Exabeam
    response = requests.post(url, json=payload, headers=headers)
    return

def main(CASE_UUID: str, NOTE_CONTENT):

    # --- Input Validation ---
    if not CASE_UUID or not isinstance(CASE_UUID, str):
        raise ValueError("CASE_UUID must be a non-empty string.")
    if not NOTE_CONTENT:
        # Allow empty notes, but log a warning as it's unusual.
        print("Warning: NOTE_CONTENT is empty. An empty note will be added to the case.")

    try:
        add_note_to_case(CASE_UUID, NOTE_CONTENT)
        print("Successfully added the note to the case!")
        return
    except requests.exceptions.RequestException as e:
        # This will catch network errors, and also HTTP errors (4xx, 5xx) from raise_for_status()
        print(f"Failed to add note. Error: {e}")
        if e.response is not None:
            print(f"Response Body: {e.response.text}")
        return None
