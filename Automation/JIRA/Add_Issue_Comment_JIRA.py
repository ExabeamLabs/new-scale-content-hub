import requests
import wmill
from requests.auth import HTTPBasicAuth

def main(issue_id: str, comment: str):
    base_url  = wmill.get_variable("f/exabeam/JIRA/JIRA/server_url")
    username  = wmill.get_variable("f/exabeam/JIRA/JIRA/username")
    api_token = wmill.get_variable("f/exabeam/JIRA/JIRA/api_key")

    url = f"{base_url}/rest/api/3/issue/{issue_id}/comment"
    headers = {"Content-Type": "application/json"}
    payload = {
        "body": {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": comment}]
                }
            ]
        }
    }

    response = requests.post(url, headers=headers, json=payload,
                             auth=HTTPBasicAuth(username, api_token))

    if response.status_code == 201:
        return {"comment_id": response.json()["id"]}
    else:
        return {"Response Status": response.status_code, "Response": response.text}
