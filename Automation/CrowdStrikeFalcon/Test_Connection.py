# Test Connection Action
# Mark Ulmer US Service Consultant - May 2026 - Initial #

import requests
import json

def get_oauth2_token(BASE_URL, CLIENT_ID, CLIENT_SECRET):
    url = f"https://{BASE_URL}/oauth2/token"
    data = {
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
    }

    response = requests.post(url, data=data)
    response.raise_for_status()
    return response.json()['access_token']

def main(BASE_URL: str, CLIENT_ID: str, CLIENT_SECRET: str):
    if not BASE_URL:
        raise RuntimeError("BASE_URL environment variable is not set")
    if not CLIENT_ID:
        raise RuntimeError("CLIENT_ID environment variable is not set")
    if not CLIENT_SECRET:
        raise RuntimeError("CLIENT_SECRET environment variable is not set")

    try:
        result = get_oauth2_token(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        return result
    except Exception as e:
        print(f"Error: {e}")
    
