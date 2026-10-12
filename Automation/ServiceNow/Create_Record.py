# Author: Exabeam ServiceNow Integration
# Version: 1.0
# Date updated: 2026-10-12
# Action Name: Create a record
# Description: Create a new ServiceNow record in the target table using the Table API POST operation.

import requests
import json
import wmill
from requests.auth import HTTPBasicAuth
from typing import TypedDict


# Define your service_now credentials
def main(
        short_description: str | None,
        description: str | None,
        category: str | None,
        case_id: str | None,
        vendor_ticket: str | None,
        case_url: str |None,
        tenant: str | None,
        mitre_tactic: str | None,
        mitre_tactic_key: str | None,
        mitre_technique: str | None,
        mitre_technique_key: str | None,
        exabeam_risk_score: str | None,
        assignment_group: str | None
):
    """
    Create a new incident record in ServiceNow.

    The action reads the instance credentials from Windmill variables and sends
    a POST request to the ServiceNow Table API.
    """
    # ---- 1. Pull the configured ServiceNow credentials for this automation ----
    username = wmill.get_variable("f/exabeam/ServiceNow/ServiceNow/username")
    password = wmill.get_variable("f/exabeam/ServiceNow/ServiceNow/password")
    tenant = wmill.get_variable("f/exabeam/ServiceNow/ServiceNow/tenant")

    # ---- 2. Build the ServiceNow Table API URL for the incident table ---------
    url = f"https://{tenant}.service-now.com/api/now/table/incident"

    # ---- 3. Assemble the payload for the ServiceNow incident fields -----------
    payload = json.dumps({
        "caller_id": "Exabeam Service",
        "assignment_group": assignment_group,
        "short_description": short_description,
        "description": description,
        "additional_comments": case_url,
        "category": category,
        "u_mitre_tactic": mitre_tactic,
        "u_mitre_tactic_key": mitre_tactic_key,
        "u_mitre_technique": mitre_technique,
        "u_mitre_technique_key": mitre_technique_key,
        "u_exabeam_risk_score": exabeam_risk_score
    })

    # ---- 4. Submit the POST request to create the record ----------------------
    response = requests.post(
        url,
        headers={"Content-Type": "application/json"},
        data=payload,
        auth=HTTPBasicAuth(username, password)
    )

    response.raise_for_status()
    return response.json()
    print(response.json)
