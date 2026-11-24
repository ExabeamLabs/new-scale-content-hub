# Exabeam Automation Management - Integration with GreyNoise

Description: Automation Management integration with the GreyNoise v3 API for IP reputation.<br>
Version: 1.0<br>
Author: Exabeam Labs<br>
Date updated: Oct 14 2026<br>

## Overview

GreyNoise tells you whether an IP address is mass-scanning the internet ("noise"), is a known business service such as a CDN, cloud provider, or SaaS vendor ("RIOT"), or hasn't been seen. Use it to triage alerts: a source IP that GreyNoise rates `benign` or `benign_service` is usually not a targeted attack.

| Action | Endpoint | Plan |
|---|---|---|
| GreyNoise_Get_IP_Reputation | `GET /v3/ip/{ip}` | Paid or trial (full context) |
| GreyNoise_Community_IP_Lookup | `GET /v3/community/{ip}` | Free community key (IPv4 only, daily limit) |
| GreyNoise_Test_Connection | `GET /ping` | Any |
| GreyNoise_Format_Report_HTML | n/a, local formatter | n/a |

## Setup Service

1. **Add Service**
   - Service name:  GreyNoise
   - Service Description:  GreyNoise IP reputation integration version 1.0
   - Click Import from File or URL
   - Paste URL to raw file...   `https://raw.githubusercontent.com/ExabeamLabs/new-scale-content-hub/refs/heads/main/Automation/GreyNoise/Exabeam_Service_Import-GreyNoise-Version_1.0.json` (or upload [Exabeam_Service_Import-GreyNoise-Version_1.0.json](Exabeam_Service_Import-GreyNoise-Version_1.0.json) if it isn't published there)
   - Click Confirm and Validate
   - Click Import and Next

2. **Configure Service Parameters**
   - Service configuration parameters
   - Edit service configuration parameters
   - Click JSON editor
   - Paste contents from [service_configuration_parameters.json](service_configuration_parameters.json)
   - Save

3. **Add Service Instance**
   - Click on Instances tab
   - Click + Add Instance
   - Provide instance name: GreyNoise
   - GN_API_KEY variable - Provide your GreyNoise API Key
   - Save

   The actions read the key from `f/exabeam/GreyNoise/GreyNoise/GN_API_KEY`. If you use a different service or instance name, change that path in each action.

4. **Edit Action**
   - Edit action name:  GreyNoise_Get_IP_Reputation
   - Description:  Retrieves GreyNoise reputation for a given IP address, including classification, actor, tags, and business service (RIOT) context.
   - Paste code contents from action file:  [GreyNoise_Get_IP_Reputation.py](GreyNoise_Get_IP_Reputation.py)
   - Deploy

5. **Edit Action**
   - Edit action name:  GreyNoise_Community_IP_Lookup
   - Description:  Retrieves free GreyNoise Community reputation for a given IPv4 address (noise, RIOT, classification, name, last seen).
   - Paste code contents from action file:  [GreyNoise_Community_IP_Lookup.py](GreyNoise_Community_IP_Lookup.py)
   - Deploy

6. **Edit Action**
   - Edit action name:  GreyNoise_Test_Connection
   - Description:  Makes a connection to GreyNoise and validates the API key.
   - Paste code contents from action file:  [GreyNoise_Test_Connection.py](GreyNoise_Test_Connection.py)
   - Deploy

7. **Add Action**
   - Edit action name:  GreyNoise_Format_Report_HTML
   - Description:  Format one or more GreyNoise IP reputation reports as HTML, including only fields with values.
   - Paste code contents from action file:  [GreyNoise_Format_Report_HTML.py](GreyNoise_Format_Report_HTML.py)
   - Deploy

## Action Results

Both lookup actions return a JSON object with a `status_code` and either `data` or `error`. `data.verdict` is the field to branch on:

| verdict | Meaning |
|---|---|
| `malicious` | Seen scanning or attacking with malicious intent |
| `benign` | Seen scanning, but by a known benign actor (e.g. a research scanner) |
| `unknown` | Seen scanning, intent not determined |
| `benign_service` | Not scanning, and part of a known business service (RIOT) |
| `not_observed` | GreyNoise has no record of this IP |

`GreyNoise_Get_IP_Reputation`:

```json
{
  "status_code": 200,
  "data": {
    "ip": "71.6.135.131",
    "verdict": "benign",
    "noise": true,
    "riot": false,
    "classification": "benign",
    "actor": "Shodan.io",
    "first_seen": "2019-01-01",
    "last_seen": "2026-10-13",
    "spoofable": false,
    "tor": false,
    "vpn": false,
    "vpn_service": "",
    "tags": ["Shodan.io", "Web Crawler"],
    "recommend_block_tags": [],
    "cves": [],
    "country": "United States",
    "organization": "CariNet, Inc.",
    "asn": "AS10439",
    "rdns": "census7.shodan.io",
    "network_category": "hosting",
    "business_service_name": "",
    "business_service_category": "",
    "business_service_trust_level": "",
    "link": "https://viz.greynoise.io/ip/71.6.135.131"
  }
}
```

`GreyNoise_Community_IP_Lookup` returns `ip`, `verdict`, `noise`, `riot`, `classification`, `name`, `last_seen`, `message`, and `link`. The Community API answers 404 for IPs it has never seen; the action reports that as `status_code: 200` with `verdict: "not_observed"`, so a branch can tell "no record" apart from a real failure.

Both actions return `status_code: 400` without calling GreyNoise when the input is missing, isn't a valid IP, or is private or otherwise non-routable. The Community action also rejects IPv6.

`GreyNoise_Format_Report_HTML` accepts a single report or an array of reports, such as the output of a For loop. It returns `{"status_code": 200, "html": "..."}`, with each IP in its own section separated by `<hr>`. Failed lookups appear in the HTML as error lines. `status_code` is 200 if at least one lookup succeeded; otherwise it is the first failure's code.

## Playbook Demonstration

1. **Create Playbook**
   - Name: GreyNoise IP Reputation
   - Add Step
   - Select  For loop
   - Iterator expression: flow_input.src_ips
   - Add Step
   - Select Action > GreyNoise > GreyNoise_Get_IP_Reputation
   - ip_to_check > plug-in > flow_input.iter.value
   - Add Step (after the loop)
   - Select Action > GreyNoise > GreyNoise_Format_Report_HTML
   - report > plug-in > results.a
   - Add Step
   - Select Action > Exabeam_Threat_Center > Create_a_note_for_a_case
   - CASE_UUID > plug-in > flow_input.case_id
   - NOTE_CONTENT > plug-in > results.c.html
   - Deploy

2. **Run Playbook from Threat Center**
   - Select a Case
   - Run a Playbook
   - Select GreyNoise IP Reputation
   - Run

See [playbook_outline.md](playbook_outline.md) for the branching version and variations.

## Reference Materials:

[GreyNoise API Documentation](https://docs.greynoise.io/)<br>
[GreyNoise IP Lookup API Reference](https://docs.greynoise.io/reference/v3ip)<br>
[GreyNoise Community API Reference](https://docs.greynoise.io/reference/getcommunityip)<br>
