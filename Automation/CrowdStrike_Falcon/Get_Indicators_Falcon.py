# Reference:  https://developer.crowdstrike.com/api-reference/collections/ioc/#getindicatorsreport

import json
import ipaddress
import wmill
from falconpy import IOC # pin: crowdstrike-falconpy>=1.3.0

#TODO Test with bad IP  102.130.113.9
#TODO When no report is returned give a "No Indicatiors found" message


BASE_URL =  wmill.get_variable("f/exabeam/CrowdStrike_Falcon/Falcon_API/BASE_URL")

def get_ip_reputation(ip):
    falcon = IOC(
    client_id = wmill.get_variable("f/exabeam/CrowdStrike_Falcon/Falcon_API/CLIENT_ID"),
    client_secret = wmill.get_variable("f/exabeam/CrowdStrike_Falcon/Falcon_API/CLIENT_SECRET")
    )

    response = falcon.get_indicators_report(body={"filter": "type:'ipv4', value:'{ip}'"})
    query_status = response.get("status_code", 500)
    if query_status == 200 and not response.get("body", {}).get("resources"):
        return json.dumps(response, indent=4)
    
    if query_status != 200:
        print(f"No CrowdStrike intelligence found for {ip}")
        return {
                "error": f"No CrowdStrike intelligence found for {ip}",
                "status_code": 404,
                "http_status_code": 404,
            }

def main(ip):
    if isinstance(ip, list):
        if not ip:
            return "No IP address provided."
        ip = ip[0]

    ip = ip.strip()
    # Validate IP address
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return f"Invalid IP address provided: {ip}"

    report = get_ip_reputation(ip)
    return report