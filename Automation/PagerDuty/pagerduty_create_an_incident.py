# Action name: Create an Incident
# Descritpion: Create an incident synchronously without a corresponding event from a monitoring service. An incident represents a problem or an issue that needs to be addressed and resolved.
# Version 1.0
# Doc Reference:  https://www.postman.com/pagerduty/pagerduty-public-api-collection/request/owz0ryf/create-an-incident
# Author: Nick Oneill US TAM - Sept 2025 - Reach out with any questions

import requests
import json
from typing import TypedDict

class pagerduty(TypedDict):
    apikey: str

def main(
    case_title: str,
    apikey: str,
    incident_key: str,):

    url = "https://api.pagerduty.com/incidents"

    payload = { "incident": {
        "type": "incident",
        "title": case_title, #choose what you'd like from flow_input for the incident title
        "service": {
            "id": "XYZ", #specify service id and type
            "type": "service"
        },
        "priority": {
            "id": "XYZ", #specify priority id
            "type": "priority"
        },
        "urgency": "high",
        "incident_key": incident_key, # set this to case id from flow_input
        "body": {
            "type": "incident_body",
            "details": "Notable User or Asset has reached a high risk score."
        },
        "escalation_policy": {
            "id": "XYZ", #specify id and type
            "type": "XYZ"
        }
    } }
    headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "From": "XYZ", # email incident is coming from
    "Authorization": f"Token token={apikey}" 
}

    response = requests.post(url, json=payload, headers=headers)


    try:
        print(response.json())
    except json.JSONDecodeError:
        print("Non-JSON response received:")
        print("Status Code:", response.status_code)
        print("Response Text:", response.text)

