import requests
import wmill
from requests.auth import HTTPBasicAuth
from typing import List

def main(issue_ids: List[str]):
    base_url  = wmill.get_variable("f/exabeam/JIRA/JIRA/server_url")
    username  = wmill.get_variable("f/exabeam/JIRA/JIRA/username")
    api_token = wmill.get_variable("f/exabeam/JIRA/JIRA/api_key")

    auth = HTTPBasicAuth(username, api_token)
    if isinstance(issue_ids, str):
        issue_ids = [issue_ids]

    issues = []
    errors = []
    for issue_id in issue_ids:
        url = f"{base_url}/rest/api/3/issue/{issue_id}?fields=summary,project,assignee,status,issuetype"
        response = requests.get(url, auth=auth)
        if response.status_code == 200:
            f = response.json().get("fields", {})
            issues.append({
                "id":         issue_id,
                "summary":    f.get("summary"),
                "project":    f.get("project", {}).get("key"),
                "assignee":   f.get("assignee", {}).get("displayName") if f.get("assignee") else "Unassigned",
                "status":     f.get("status", {}).get("name"),
                "issue_type": f.get("issuetype", {}).get("name")
            })
        else:
            errors.append({"issue_id": issue_id,
                           "Response Status": response.status_code,
                           "Response": response.text})

    return {"issues": issues, "errors": errors} if errors else issues
