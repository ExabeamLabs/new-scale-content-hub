import requests
import json
from requests.auth import HTTPBasicAuth
from typing import TypedDict


# Define your service_now credentials
class ServiceNow(TypedDict):
    username: str
    password: str
    tenant: str


def main(
        # auth: ServiceNow,
        # tableName: str,
        # sysparm_display_value: str | None,
        # sysparm_exclude_reference_link: str | None,
        # sysparm_fields: str | None,
        # sysparm_input_display_value: str | None,
        # sysparm_suppress_auto_sys_field: str | None,
        # sysparm_view: str | None,
        username: str | None,
        password: str | None,
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
    Create a record
    """
    url = f"https://{tenant}.service-now.com/api/now/table/incident"

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

    response = requests.post(
        url,
        headers={"Content-Type": "application/json"},
        data=payload,
        auth=HTTPBasicAuth(username, password)
    )

    response.raise_for_status()
    return response.json()
    print(response.json)
