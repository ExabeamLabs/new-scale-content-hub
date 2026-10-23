import json
import requests
from typing import Dict, Any
from urllib.parse import quote


GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"

# Number of sign-ins to return.
DEFAULT_SIGNIN_COUNT = 20


def _get_access_token(
    tenant_id: str,
    client_id: str,
    client_secret: str
) -> str:
    """
    Get Microsoft Graph access token using
    OAuth 2.0 Client Credentials flow.
    """

    token_url = (
        f"https://login.microsoftonline.com/"
        f"{tenant_id}/oauth2/v2.0/token"
    )

    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials"
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    try:

        response = requests.post(
            token_url,
            data=payload,
            headers=headers,
            timeout=60
        )

        if response.status_code >= 400:

            try:
                error_body = response.json()
            except ValueError:
                error_body = response.text

            raise Exception(
                "Microsoft Entra token request failed.\n"
                f"HTTP Status: {response.status_code}\n"
                f"Response: "
                f"{json.dumps(error_body, indent=2)}"
            )

        token_data = response.json()

        access_token = token_data.get(
            "access_token"
        )

        if not access_token:

            raise Exception(
                "Microsoft authentication response "
                "did not contain an access token."
            )

        return access_token

    except requests.exceptions.RequestException as e:

        error_body = ""

        if e.response is not None:

            try:
                error_body = e.response.json()
            except ValueError:
                error_body = e.response.text

        raise Exception(
            "Microsoft Entra authentication failed.\n"
            f"HTTP Status: "
            f"{e.response.status_code if e.response is not None else 'unknown'}\n"
            f"Error: {e}\n"
            f"Response: "
            f"{json.dumps(error_body, indent=2) if isinstance(error_body, dict) else error_body}"
        )


def _normalize_user(user) -> str:
    """
    Normalize the user value received from Exabeam AAM.

    Supports:

        "user@company.com"

    and:

        ["user@company.com"]

    Returns:

        "user@company.com"
    """

    if isinstance(user, list):

        if len(user) != 1:

            raise ValueError(
                f"Expected exactly one user, "
                f"but received: {user}"
            )

        user = user[0]

    if not isinstance(user, str):

        raise ValueError(
            f"Invalid user type: "
            f"{type(user).__name__}. "
            f"Expected string or single-element list."
        )

    user = user.strip()

    if not user:

        raise ValueError(
            "User cannot be empty."
        )

    return user


def _get_user(
    access_token: str,
    user: str
) -> Dict[str, Any]:
    """
    Look up the Entra ID user and obtain the
    object ID required for sign-in filtering.
    """

    user_encoded = quote(
        user,
        safe=""
    )

    graph_url = (
        f"{GRAPH_BASE_URL}/users/"
        f"{user_encoded}"
        "?$select=id,userPrincipalName,"
        "displayName,accountEnabled"
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    try:

        response = requests.get(
            graph_url,
            headers=headers,
            timeout=60
        )

        if response.status_code >= 400:

            try:
                error_body = response.json()
            except ValueError:
                error_body = response.text

            raise Exception(
                "Microsoft Graph user lookup failed.\n"
                f"HTTP Status: {response.status_code}\n"
                f"URL: {graph_url}\n"
                f"Response: "
                f"{json.dumps(error_body, indent=2)}"
            )

        return response.json()

    except requests.exceptions.RequestException as e:

        error_body = ""

        if e.response is not None:

            try:
                error_body = e.response.json()
            except ValueError:
                error_body = e.response.text

        raise Exception(
            "Microsoft Graph user lookup request failed.\n"
            f"HTTP Status: "
            f"{e.response.status_code if e.response is not None else 'unknown'}\n"
            f"Error: {e}\n"
            f"Response: "
            f"{json.dumps(error_body, indent=2) if isinstance(error_body, dict) else error_body}"
        )


def _get_sign_ins(
    access_token: str,
    user_id: str,
    user_principal_name: str,
    count: int = DEFAULT_SIGNIN_COUNT
) -> Dict[str, Any]:
    """
    Retrieve recent Microsoft Entra ID sign-in events
    for the specified user.

    Uses:

        GET /auditLogs/signIns

    and filters by userId.

    The API returns the most recent events first.
    """

    # Keep the requested number within a reasonable range.
    if count < 1:
        count = DEFAULT_SIGNIN_COUNT

    if count > 100:
        count = 100

    # OData filter.
    #
    # Filtering by userId is preferable to filtering by
    # UPN because userId is the stable Entra object ID.
    filter_value = (
        f"userId eq '{user_id}'"
    )

    graph_url = (
        f"{GRAPH_BASE_URL}/auditLogs/signIns"
        f"?$filter={quote(filter_value, safe='')}"
        f"&$top={count}"
        f"&$orderby=createdDateTime desc"
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    try:

        response = requests.get(
            graph_url,
            headers=headers,
            timeout=60
        )

        if response.status_code >= 400:

            try:
                error_body = response.json()
            except ValueError:
                error_body = response.text

            raise Exception(
                "Microsoft Graph sign-in query failed.\n"
                f"HTTP Status: {response.status_code}\n"
                f"URL: {graph_url}\n"
                f"User: {user_principal_name}\n"
                f"Response: "
                f"{json.dumps(error_body, indent=2)}"
            )

        return response.json()

    except requests.exceptions.RequestException as e:

        error_body = ""

        if e.response is not None:

            try:
                error_body = e.response.json()
            except ValueError:
                error_body = e.response.text

        raise Exception(
            "Microsoft Graph sign-in request failed.\n"
            f"HTTP Status: "
            f"{e.response.status_code if e.response is not None else 'unknown'}\n"
            f"Error: {e}\n"
            f"Response: "
            f"{json.dumps(error_body, indent=2) if isinstance(error_body, dict) else error_body}"
        )


def _format_sign_in(
    sign_in: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Convert the Graph sign-in object into a
    SOC-friendly structure.

    The original Graph object is retained so that
    no investigation data is lost.
    """

    location = sign_in.get(
        "location"
    ) or {}

    device_detail = sign_in.get(
        "deviceDetail"
    ) or {}

    status = sign_in.get(
        "status"
    ) or {}

    applied_ca = sign_in.get(
        "appliedConditionalAccessPolicies"
    )

    return {
        "id": sign_in.get("id"),

        "timestamp": sign_in.get(
            "createdDateTime"
        ),

        "user": {
            "id": sign_in.get(
                "userId"
            ),
            "display_name": sign_in.get(
                "userDisplayName"
            ),
            "user_principal_name": sign_in.get(
                "userPrincipalName"
            )
        },

        "application": {
            "name": sign_in.get(
                "appDisplayName"
            ),
            "id": sign_in.get(
                "appId"
            ),
            "resource_display_name": sign_in.get(
                "resourceDisplayName"
            ),
            "resource_id": sign_in.get(
                "resourceId"
            )
        },

        "network": {
            "ip_address": sign_in.get(
                "ipAddress"
            ),
            "location": {
                "city": location.get(
                    "city"
                ),
                "state": location.get(
                    "state"
                ),
                "country_or_region": location.get(
                    "countryOrRegion"
                ),
                "geo_coordinates": location.get(
                    "geoCoordinates"
                )
            }
        },

        "authentication": {
            "status": status,
            "conditional_access_status": sign_in.get(
                "conditionalAccessStatus"
            ),
            "authentication_requirement": sign_in.get(
                "authenticationRequirement"
            ),
            "authentication_protocol": sign_in.get(
                "authenticationProtocol"
            ),
            "client_app_used": sign_in.get(
                "clientAppUsed"
            )
        },

        "device": {
            "display_name": device_detail.get(
                "displayName"
            ),
            "operating_system": device_detail.get(
                "operatingSystem"
            ),
            "browser": device_detail.get(
                "browser"
            ),
            "is_compliant": device_detail.get(
                "isCompliant"
            ),
            "is_managed": device_detail.get(
                "isManaged"
            ),
            "trust_type": device_detail.get(
                "trustType"
            )
        },

        "risk": {
            "risk_detail": sign_in.get(
                "riskDetail"
            ),
            "risk_level": sign_in.get(
                "riskLevelAggregated"
            ),
            "risk_state": sign_in.get(
                "riskState"
            ),
            "risk_event_types": sign_in.get(
                "riskEventTypes"
            )
        },

        "network_and_session": {
            "correlation_id": sign_in.get(
                "correlationId"
            ),
            "request_id": sign_in.get(
                "requestId"
            ),
            "session_id": sign_in.get(
                "sessionId"
            )
        },

        "conditional_access_policies": applied_ca,

        # Preserve complete original Graph event.
        "raw_graph_event": sign_in
    }


def main(
    user_id,
    tenant_id: str,
    client_id: str,
    client_secret: str
) -> Dict[str, Any]:
    """
    Exabeam AAM entry point.

    Retrieve recent Microsoft Entra ID sign-in
    information for a user.

    Parameters:

        tenant_id
            Microsoft Entra Tenant ID.

        client_id
            Microsoft Entra App Registration
            Application / Client ID.

        client_secret
            Microsoft Entra App Registration
            Client Secret.

        user_id
            User Principal Name or Entra Object ID.

            Supported:

                "user@company.com"

            or:

                ["user@company.com"]
    """

    # ---------------------------------------------------------
    # Validate required parameters
    # ---------------------------------------------------------

    if not tenant_id:
        raise ValueError(
            "tenant_id is required."
        )

    if not client_id:
        raise ValueError(
            "client_id is required."
        )

    if not client_secret:
        raise ValueError(
            "client_secret is required."
        )

    if not user_id:
        raise ValueError(
            "user_id is required."
        )

    # ---------------------------------------------------------
    # Normalize Exabeam input
    # ---------------------------------------------------------

    normalized_user = _normalize_user(
        user_id
    )

    # ---------------------------------------------------------
    # Get Microsoft Graph access token
    # ---------------------------------------------------------

    access_token = _get_access_token(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret
    )

    # ---------------------------------------------------------
    # Look up user
    # ---------------------------------------------------------

    user_details = _get_user(
        access_token=access_token,
        user=normalized_user
    )

    user_id = user_details.get(
        "id"
    )

    if not user_id:

        raise Exception(
            "Microsoft Graph returned the user "
            "but no user object ID was found."
        )

    user_principal_name = user_details.get(
        "userPrincipalName"
    ) or normalized_user

    # ---------------------------------------------------------
    # Get recent sign-ins
    # ---------------------------------------------------------

    sign_in_data = _get_sign_ins(
        access_token=access_token,
        user_id=user_id,
        user_principal_name=user_principal_name,
        count=DEFAULT_SIGNIN_COUNT
    )

    raw_sign_ins = sign_in_data.get(
        "value",
        []
    )

    formatted_sign_ins = [
        _format_sign_in(sign_in)
        for sign_in in raw_sign_ins
    ]

    # ---------------------------------------------------------
    # Calculate basic SOC summary
    # ---------------------------------------------------------

    successful_sign_ins = 0
    failed_sign_ins = 0

    unique_ips = set()
    unique_applications = set()
    unique_countries = set()

    for sign_in in raw_sign_ins:

        status = sign_in.get(
            "status"
        ) or {}

        error_code = status.get(
            "errorCode"
        )

        if error_code == 0:
            successful_sign_ins += 1
        else:
            failed_sign_ins += 1

        ip_address = sign_in.get(
            "ipAddress"
        )

        if ip_address:
            unique_ips.add(
                ip_address
            )

        application = sign_in.get(
            "appDisplayName"
        )

        if application:
            unique_applications.add(
                application
            )

        location = sign_in.get(
            "location"
        ) or {}

        country = location.get(
            "countryOrRegion"
        )

        if country:
            unique_countries.add(
                country
            )

    # ---------------------------------------------------------
    # Return SOC-friendly result
    # ---------------------------------------------------------

    return {
        "status": "success",

        "user": {
            "id": user_details.get(
                "id"
            ),
            "userPrincipalName": user_details.get(
                "userPrincipalName"
            ),
            "displayName": user_details.get(
                "displayName"
            ),
            "accountEnabled": user_details.get(
                "accountEnabled"
            )
        },

        "summary": {
            "sign_ins_returned": len(
                raw_sign_ins
            ),
            "successful_sign_ins": successful_sign_ins,
            "failed_sign_ins": failed_sign_ins,
            "unique_ip_count": len(
                unique_ips
            ),
            "unique_ips": sorted(
                unique_ips
            ),
            "unique_application_count": len(
                unique_applications
            ),
            "unique_applications": sorted(
                unique_applications
            ),
            "unique_country_count": len(
                unique_countries
            ),
            "unique_countries": sorted(
                unique_countries
            )
        },

        "sign_ins": formatted_sign_ins,

        "message": (
            f"Successfully retrieved "
            f"{len(raw_sign_ins)} recent sign-in events "
            f"for user '{user_principal_name}'."
        )
    }
