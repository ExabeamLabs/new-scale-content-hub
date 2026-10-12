import requests
import wmill
from requests.auth import HTTPBasicAuth

def main(jira_project, jira_summary):
    # URL for JIRA APIs
    base_url = wmill.get_variable("f/exabeam/JIRA/JIRA/server_url")
    url = f"{base_url}/rest/api/3/issue"

    # Information for authentication
    username = wmill.get_variable("f/exabeam/JIRA/JIRA/username")
    api_token = wmill.get_variable("f/exabeam/JIRA/JIRA/api_key")

    headers = {
        "Content-Type": "application/json"
    }

    payload = {
        "fields": {
            "issuetype": {"name": "Task"},
            "project": {"key": jira_project},
            "summary": jira_summary,
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {"type": "paragraph",
                        "content": [
                            {"type": "text", "text": jira_summary}
                        ]
                    }
                ]
            }
        }
    }

    # POST to the API
    response = requests.post(
        url,
        headers=headers,
        json=payload,
        auth=HTTPBasicAuth(username, api_token)
    )

    # Verify the reponse
    if response.status_code == 201:
        print("Issue created successfully!")
        return {
            "Issue reference": response.json()["key"]
            }
    else:
        print("Problem creating issue in JIRA.")
        return {
            "Response Status:", response.status_code,
            "Reponse :", response.text
            }
