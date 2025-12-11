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
    "Authorization": f"Token token={apikey}" 
}

    response = requests.get(url, headers=headers, params=querystring)
    data = response.json()
    # Access the 'id' of the first service

    services = data.get("services", [])
    if not services:
        raise ValueError("No services found in the response.")

    service_id = services[0].get("id")
    print(service_id)
