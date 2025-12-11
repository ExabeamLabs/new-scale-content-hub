# Action name: Create an Incident
# Descritpion: Create an incident synchronously without a corresponding event from a monitoring service. An incident represents a problem or an issue that needs to be addressed and resolved.
# Version 1.0
# Doc Reference:  https://www.postman.com/pagerduty/pagerduty-public-api-collection/request/owz0ryf/create-an-incident
# Author: Nick Oneill US TAM - Sept 2025 - Reach out with any questions
# Author: Mark Ulmer US Service Consultant - Dec 2025 - Moved apikey to instance variable

import requests
import json

def get_default_id(apikey: str):

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

    return services[0].get("id")


def main(case_id: str, case_title: str, fromEmail: str, apikey: str):

    url = "https://api.pagerduty.com/incidents"

    payload = { "incident": {
        "type": "Security Incident",
        "title": case_title, #choose what you'd like from flow_input for the incident title
        "service": {
            "id": get_default_id(apikey),
            "type": "service"
        },
        "urgency": "high",
        "incident_key": case_id, # Consider sending Exabeam Case ID
        "body": {
            "type": "incident_body",
            "details": "Notable User or Asset has reached a high risk score."
        }
    } }
    headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "From": fromEmail,
    "Authorization": f"Token token={apikey}" 
}

    response = requests.post(url, json=payload, headers=headers)

    try:
        print(response.json())
    except json.JSONDecodeError:
        print("Non-JSON response received:")
        print("Status Code:", response.status_code)
        print("Response Text:", response.text)
