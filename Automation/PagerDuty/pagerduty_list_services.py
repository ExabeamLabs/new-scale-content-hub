# Action name: List Services
# Descritpion: List Services
# Version 1.0
# Doc Reference:  https://developer.pagerduty.com/api-reference/e960cca205c0f-list-services
# Author: 

import requests
import json

def main(apikey: str):

    url = "https://api.pagerduty.com/services"
    querystring = {"name":"Default Service"}

    headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "From": from_email,
    "Authorization": f"Token token={apikey}" 
}

    response = requests.post(url, headers=headers, params=querystring)

    try:
        # Access the 'id' of the first service
        service_id = response["services"][0]["id"]
        print(service_id)

    except json.JSONDecodeError:
        print("Non-JSON response received:")
        print("Status Code:", response.status_code)
        print("Response Text:", response.text)
