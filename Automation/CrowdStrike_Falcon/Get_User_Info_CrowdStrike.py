#Reference:  https://developer.crowdstrike.com/api-reference/collections/user-management/#queryuserv1

import json
import wmill
from html import escape
from falconpy import UserManagement # pin: crowdstrike-falconpy>=1.3.0


def get_falcon_client() -> UserManagement:
    """Initialize and return the FalconPy UserManagement client."""
    try:
        client_id = wmill.get_variable("f/exabeam/CrowdStrike_Falcon/Falcon_API/CLIENT_ID")
        client_secret = wmill.get_variable("f/exabeam/CrowdStrike_Falcon/Falcon_API/CLIENT_SECRET")
    except Exception as exc:
        raise RuntimeError(f"Failed to read CrowdStrike credentials: {exc}") from exc

    if not client_id or not client_secret:
        raise ValueError(
            "FALCON_CLIENT_ID and FALCON_CLIENT_SECRET must be provided via arguments or environment variables."
        )

    return UserManagement(
        client_id=client_id,
        client_secret=client_secret,
        cloud="us-1"
    )

def fetch_user_data(falcon: UserManagement, username: str, asHTML: bool) -> dict:
    try:
        # 1. Query user UUID using FQL filter
        # User's UID in Falcon is typically their email/username
        fql_filter = f"uid:*'{username}*'"
        query_resp = falcon.query_users(filter=fql_filter)
        query_status = query_resp.get("status_code", 500)

        # If no match by UID, try searching by UUID or name
        if query_status == 200 and not query_resp.get("body", {}).get("resources"):
            fql_filter = f"uuid:'{username}'"
            query_resp = falcon.query_users(filter=fql_filter)
            query_status = query_resp.get("status_code", 500)

        if query_status != 200:
            return {
                "error": "Failed to query user UUID",
                "status_code": query_status,
                "http_status_code": query_status,
                "details": query_resp,
            }

        resources = query_resp.get("body", {}).get("resources", [])
        if not resources:
            return {
                "error": f"No user found matching username/identifier: '{username}'",
                "status_code": 404,
                "http_status_code": 404,
                "query_filter": fql_filter,
            }

        user_uuid = resources[0]

        # 2. Retrieve detailed user profile
        user_details_resp = falcon.retrieve_users(ids=[user_uuid])
        user_details_status = user_details_resp.get("status_code", 500)

        if user_details_status != 200:
            return {
                "error": f"Failed to retrieve details for user UUID: {user_uuid}",
                "status_code": user_details_status,
                "http_status_code": user_details_status,
                "details": user_details_resp,
            }

        user_data = {}
        users_list = user_details_resp.get("body", {}).get("resources", [])
        if users_list:
            user_data = users_list[0]

        if asHTML:
            html_output = f"""<div>
            <h3>User Details: {escape(str(user_data.get('uid', '')))}</h3>
            <ul>
                <li><strong>Name:</strong> {escape(str(user_data.get('first_name', '')))} {escape(str(user_data.get('last_name', '')))}</li>
                <li><strong>User UUID:</strong> {escape(str(user_data.get('uuid', '')))}</li>
                <li><strong>Status:</strong> {escape(str(user_data.get('status', '')))}</li>
            </ul></div>"""
            return html_output.strip()

        return {
            "uid": user_data.get("uid"),
            "first_name": user_data.get("first_name"), "last_name": user_data.get("last_name"),
            "user_uuid": user_uuid,
            "status": user_data.get("status"),
        }
    except Exception as exc:
        return {
            "error": "Exception while retrieving CrowdStrike user data",
            "status_code": 500,
            "http_status_code": 500,
            "details": str(exc),
        }

def main(username, asHTML: bool):
    if not username:
        return {
            "error": "Username is required",
            "status_code": 400,
            "http_status_code": 400,
        }
    # Initialize client
    falcon = get_falcon_client()

    # Fetch user data
    result = fetch_user_data(falcon, username, asHTML)
    return result

