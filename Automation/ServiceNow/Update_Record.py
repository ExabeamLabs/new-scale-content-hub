# Author: Exabeam ServiceNow Integration
# Version: 1.0
# Date updated: 2026-10-12
# Action Name: Update a record
# Description: Update a ServiceNow record by sys_id using the Table API PATCH operation.

from typing import Any
from urllib.parse import quote

import requests
import wmill
from requests.auth import HTTPBasicAuth


def main(
    tableName: str,
    sys_id: str,
    record: dict[str, Any],
    sysparm_display_value: str | None = None,
    sysparm_exclude_reference_link: bool | None = None,
    sysparm_fields: str | None = None,
    sysparm_input_display_value: bool | None = None,
    sysparm_suppress_auto_sys_field: bool | None = None,
    sysparm_view: str | None = None,
    sysparm_query_no_domain: bool | None = None,
):
    """
    Update selected fields on an existing ServiceNow record.

    This action uses the PATCH Table API method to merge the supplied JSON
    object into the record identified by sys_id.
    """
    # ---- 1. Pull the configured ServiceNow credentials for this automation ----
    username = wmill.get_variable("f/exabeam/ServiceNow/ServiceNow/username")
    password = wmill.get_variable("f/exabeam/ServiceNow/ServiceNow/password")
    tenant = wmill.get_variable("f/exabeam/ServiceNow/ServiceNow/tenant")

    # ---- 2. Build the ServiceNow record endpoint using table name and sys_id ----
    url = (
        f"https://{tenant}.service-now.com/api/now/v2/table/"
        f"{quote(tableName, safe='')}/{quote(sys_id, safe='')}"
    )

    # ---- 3. Add optional response-formatting query parameters ------------
    params = {
        "sysparm_display_value": sysparm_display_value,
        "sysparm_exclude_reference_link": sysparm_exclude_reference_link,
        "sysparm_fields": sysparm_fields,
        "sysparm_input_display_value": sysparm_input_display_value,
        "sysparm_suppress_auto_sys_field": sysparm_suppress_auto_sys_field,
        "sysparm_view": sysparm_view,
        "sysparm_query_no_domain": sysparm_query_no_domain,
    }
    params = {key: value for key, value in params.items() if value is not None}

    # ---- 4. Submit the PATCH request to update the matching fields ----------
    response = requests.patch(
        url,
        json=record,
        params=params,
        auth=HTTPBasicAuth(username, password),
        timeout=60,
    )
    response.raise_for_status()
    if not response.content:
        return {"status_code": response.status_code}
    return response.json()