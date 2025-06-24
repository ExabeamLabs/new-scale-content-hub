import argparse
import os
import csv
import requests
import json


# Function to authenticate with Exabeam
def authenticate_with_exabeam(exabeam_url):
    api_key = os.getenv("EXABEAM_API_KEY")
    api_secret = os.getenv("EXABEAM_API_SECRET")

    if not api_key or not api_secret:
        print("Exabeam API credentials are not set in the environment.")
        return None

    auth_url = f"{exabeam_url}/auth/v1/token"
    payload = {
        "client_id": api_key,
        "client_secret": api_secret,
        "grant_type": "client_credentials"
    }

    try:
        response = requests.post(auth_url, headers={'Content-Type': 'application/json'}, data=json.dumps(payload), verify=False)
        response.raise_for_status()
        token = response.json().get('access_token')
        print("Authenticated with Exabeam successfully.")
        return token
    except requests.exceptions.RequestException as e:
        print(f"Error during Exabeam authentication: {e}")
        return None


# Function to get context table ID from Exabeam
def get_context_table_id(token, exabeam_url, table_name):
    headers = {'Authorization': f'Bearer {token}'}
    try:
        response = requests.get(f"{exabeam_url}/context-management/v1/tables", headers=headers, verify=False)
        response.raise_for_status()
        tables = response.json()
        for table in tables:
            if table['name'] == table_name:
                print(f"Context table '{table_name}' found with ID: {table['id']}")
                return table['id']
        print(f"Context table '{table_name}' not found.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error fetching context table: {e}")
        return None


# Function to upload CSV to Exabeam context table
def upload_csv_to_exabeam(csv_filename, token, table_id, exabeam_url):
    headers = {'Authorization': f'Bearer {token}'}
    file_path = "/Users/jbergeron/Desktop/"
    try:
        with open(file_path + csv_filename, 'rb') as f:
            response = requests.post(
                f"{exabeam_url}/context-management/v1/tables/{table_id}/addRecordsFromCsv",
                headers=headers,
                files={'file': f},
                data={'operation': 'Replace'},
                verify=False
            )
        print(response.text)
        response.raise_for_status()
        print(f"CSV file {csv_filename} uploaded successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error uploading CSV to Exabeam: {e}")


# Main function
def main():
    parser = argparse.ArgumentParser(description="Recorded Future to Exabeam Integration Script")
    parser.add_argument("--exabeam-url", required=True, help="Exabeam API URL")
    parser.add_argument("--context-table-name", required=True, help="Name of the Exabeam context table")
    parser.add_argument("--csv-filename", required=True, help="Name of the Exabeam csv file to be uploaded")
    #    parser.add_argument("--recordedFuture-url", required=True, help="Recorded Future URL")
    #    parser.add_argument("--recordedFuture-api-key", required=True, help="Recorded Future API key")

    args = parser.parse_args()


    # Authenticate with Exabeam
    token = authenticate_with_exabeam(args.exabeam_url)
    if not token:
        print("Failed to authenticate with Exabeam. Exiting.")
        return

    # Get context table ID from Exabeam
    table_id = get_context_table_id(token, args.exabeam_url, args.context_table_name)
    if not table_id:
        print("Failed to retrieve context table ID. Exiting.")
        return

    # Upload CSV to Exabeam
    upload_csv_to_exabeam(args.csv_filename, token, table_id, args.exabeam_url)


if __name__ == '__main__':
    main()
