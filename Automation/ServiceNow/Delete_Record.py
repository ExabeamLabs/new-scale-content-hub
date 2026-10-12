# Author: Exabeam ServiceNow Integration
# Version: 1.0
# Date updated: 2026-10-12
# Action Name: Delete a record
# Description: Delete a ServiceNow record by sys_id from the target table using the Table API DELETE operation.

from urllib.parse import quote

import requests
import wmill
from requests.auth import HTTPBasicAuth


def main(
    tableName: str,
    sys_id: str,
    sysparm_query_no_domain: bool | None = None,
):
    """
    Delete a record from the configured ServiceNow table.

    Args:
        tableName: The ServiceNow table name, such as incident or task.
        sys_id: The sys_id of the record to delete.
        sysparm_query_no_domain: Optional flag that skips domain filtering.
    """
    # ---- 1. Pull the configured ServiceNow credentials for this automation ----
    username = wmill.get_variable("f/exabeam/ServiceNow/ServiceNow/username")
    password = wmill.get_variable("f/exabeam/ServiceNow/ServiceNow/password")
    tenant = wmill.get_variable("f/exabeam/ServiceNow/ServiceNow/tenant")

    # ---- 2. Build the target record URL including the row identifier ----------
    url = (
        f"https://{tenant}.service-now.com/api/now/v2/table/"
        f"{quote(tableName, safe='')}/{quote(sys_id, safe='')}"
    )

    # ---- 3. Add any optional query parameters supported by the API -----------
    params = {
        "sysparm_query_no_domain": sysparm_query_no_domain,
    }
    params = {key: value for key, value in params.items() if value is not None}

    # ---- 4. Submit the DELETE request to remove the record --------------------
    response = requests.delete(
        url,
        params=params,
        auth=HTTPBasicAuth(username, password),
        timeout=60,
    )
    response.raise_for_status()
    if not response.content:
        return {"status_code": response.status_code, "deleted": True}
    return response.json()