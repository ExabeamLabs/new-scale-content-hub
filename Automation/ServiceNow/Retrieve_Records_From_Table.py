# Author: Exabeam ServiceNow Integration
# Version: 1.0
# Date updated: 2026-10-12
# Action Name: Retrieve records from a table
# Description: Query an entire ServiceNow table and return matching records using the Table API GET operation.

import requests
from urllib.parse import quote

import requests
import wmill
from requests.auth import HTTPBasicAuth


def main(
    tableName: str,
    sysparm_query: str | None = None,
    sysparm_display_value: str | None = None,
    sysparm_exclude_reference_link: bool | None = None,
    sysparm_suppress_pagination_header: bool | None = None,
    sysparm_fields: str | None = None,
    sysparm_limit: int | None = None,
    sysparm_view: str | None = None,
    sysparm_query_category: str | None = None,
    sysparm_query_no_domain: bool | None = None,
    sysparm_no_count: bool | None = None,
):
    """
    Retrieve records from the specified ServiceNow table.

    This action accepts optional query and filtering parameters so downstream
    automation can narrow results to the exact incident or task set needed.
    """
    # ---- 1. Pull the configured ServiceNow credentials for this automation ----
    username = wmill.get_variable("f/exabeam/ServiceNow/ServiceNow/username")
    password = wmill.get_variable("f/exabeam/ServiceNow/ServiceNow/password")
    tenant = wmill.get_variable("f/exabeam/ServiceNow/ServiceNow/tenant")

    # ---- 2. Build the collection endpoint for the requested table ------------
    url = (
        f"https://{tenant}.service-now.com/api/now/v2/table/"
        f"{quote(tableName, safe='')}"
    )

    # ---- 3. Add optional filters and formatting parameters for the query -----
    params = {
        "sysparm_query": sysparm_query,
        "sysparm_display_value": sysparm_display_value,
        "sysparm_exclude_reference_link": sysparm_exclude_reference_link,
        "sysparm_suppress_pagination_header": sysparm_suppress_pagination_header,
        "sysparm_fields": sysparm_fields,
        "sysparm_limit": sysparm_limit,
        "sysparm_view": sysparm_view,
        "sysparm_query_category": sysparm_query_category,
        "sysparm_query_no_domain": sysparm_query_no_domain,
        "sysparm_no_count": sysparm_no_count,
    }
    params = {key: value for key, value in params.items() if value is not None}

    # ---- 4. Submit the GET request to list matching rows ---------------------
    response = requests.get(
        url,
        params=params,
        auth=HTTPBasicAuth(username, password),
        timeout=60,
    )
    response.raise_for_status()
    return response.json()