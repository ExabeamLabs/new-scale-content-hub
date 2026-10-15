# Exabeam Automation Management - Integration with IPQualityScore

Description: Automation Management integration with IPQualityScore (IPQS) IP, URL, Email, and Phone reputation APIs.<br>
Version: 1.0<br>
Author: Exabeam Labs<br>
Date updated: Oct 12 2026<br>

## Setup Service

1. **Add Service**
   - Service name:  IPQualityScore
   - Service Description:  IPQualityScore integration version 1.0
   - Click Import from File or URL
   - Paste URL...   `https://raw.githubusercontent.com/ExabeamLabs/new-scale-content-hub/refs/heads/main/Automation/IPQualityScore/Exabeam_Service_Import-IPQualityScore-Version_1.0.json`
   - Click Confirm and Validate
   - Click Import and Next

2. **Configure Service Parameters**
   - Service configuration parameters
   - Edit service configuration parameters
   - Click JSON editor
   - Paste contents from [service_configuration_parameters.json](../IPQualityScore/service_configuration_parameters.json)
   - Save

3. **Add Service Instance**
   - Click on Instances tab
   - Click + Add Instance
   - Provide instance name: IPQualityScore
   - IPQS_API_KEY variable - Provide your IPQualityScore API Key
   - Save

   The action scripts read the key from `f/exabeam/IPQualityScore/IPQualityScore/IPQS_API_KEY`. If you use a different service or instance name, update that path in each action.

4. **Edit Action**
   - Edit action name:  IPQualityScore_Action_Get_IP_Reputation
   - Description:  Retrieves a fraud score and proxy, VPN, TOR, bot, and recent-abuse indicators for a given IP address.
   - Paste code contents from action file:  [IPQualityScore_Action_Get_IP_Reputation.py](../IPQualityScore/IPQualityScore_Action_Get_IP_Reputation.py)
   - Deploy

5. **Edit Action**
   - Edit action name:  IPQualityScore_Action_Get_URL_Reputation
   - Description:  Scans a URL or domain for phishing, malware, parking, and spam, and returns a risk score and domain details.
   - Paste code contents from action file:  [IPQualityScore_Action_Get_URL_Reputation.py](../IPQualityScore/IPQualityScore_Action_Get_URL_Reputation.py)
   - Deploy

6. **Edit Action**
   - Edit action name:  IPQualityScore_Action_Get_Email_Reputation
   - Description:  Validates an email address and returns a fraud score plus disposable, leaked, honeypot, and recent-abuse indicators.
   - Paste code contents from action file:  [IPQualityScore_Action_Get_Email_Reputation.py](../IPQualityScore/IPQualityScore_Action_Get_Email_Reputation.py)
   - Deploy

7. **Edit Action**
   - Edit action name:  IPQualityScore_Action_Get_Phone_Reputation
   - Description:  Validates a phone number and returns a fraud score, line type, carrier, and VOIP, prepaid, spammer, and recent-abuse indicators.
   - Paste code contents from action file:  [IPQualityScore_Action_Get_Phone_Reputation.py](../IPQualityScore/IPQualityScore_Action_Get_Phone_Reputation.py)
   - Deploy

8. **Add Action**
   - Edit action name:  IPQualityScore_Test_Connection
   - Description:  Makes a connection to IPQualityScore and validates API key.
   - Paste code contents from action file:  [IPQualityScore_Test_Connection.py](../IPQualityScore/IPQualityScore_Test_Connection.py)
   - Deploy

9. **Add Action**
   - Edit action name:  IPQualityScore_Format_Report_HTML
   - Description:  Format one or more IPQualityScore reports as HTML, including only fields with values.
   - Paste code contents from action file:  [IPQualityScore_Format_Report_HTML.py](../IPQualityScore/IPQualityScore_Format_Report_HTML.py)
   - Deploy

10. **Add Action**
    - Edit action name:  Extract_Public_IP_Addresses
    - Description:  Extract and return only public ip addresses.
    - Paste code contents from the shared helper:  [Extract_Public_IP_Addresses.py](../VirusTotal/Extract_Public_IP_Addresses.py)
    - Deploy

## Action Inputs

| Action | Required input | Optional inputs |
|---|---|---|
| IPQualityScore_Action_Get_IP_Reputation | `ip_to_check` (IPv4/IPv6, or a list — first item is used) | `strictness` 0-3 (default 0) |
| IPQualityScore_Action_Get_URL_Reputation | `url_to_check` (full URL or bare domain) | `strictness` 0-2 (default 0) |
| IPQualityScore_Action_Get_Email_Reputation | `email_to_check` | `timeout` 1-60 seconds (default 7), `abuse_strictness` 0-2 (default 0) |
| IPQualityScore_Action_Get_Phone_Reputation | `phone_to_check` (formatting is stripped) | `countries` e.g. `["US","CA"]` or `"US,CA"`, `strictness` (default 0) |
| IPQualityScore_Test_Connection | none | none |
| IPQualityScore_Format_Report_HTML | `report` (one report object, or an array of them) | none |

## Action Results

The IP, URL, email, and phone actions return a JSON object with a `status_code` and either `data` or `error`:

```json
{
   "status_code": 200,
   "data": {
      "ip": "185.220.101.1",
      "is_public": true,
      "fraud_score": 100,
      "proxy": true,
      "vpn": true,
      "tor": true,
      "recent_abuse": true,
      "country_code": "DE",
      "isp": "Example ISP",
      "request_id": "4OTORR352FU0p"
   }
}
```

```json
{
   "status_code": 400,
   "error": "IPQualityScore request failed: You have insufficient credits to make this query..."
}
```

IPQualityScore returns HTTP 200 even when a lookup fails (invalid key, no credits, invalid input) and reports the failure with `"success": false`. The actions turn that into a non-200 `status_code`, so a playbook branch can always test `results.<step>.status_code == 200`. Use `fraud_score` (IP, email, phone) or `risk_score` (URL) for risk-based branching, e.g. `results.c.data.fraud_score >= 85`.

## Report HTML Formatting

Use [IPQualityScore_Format_Report_HTML.py](../IPQualityScore/IPQualityScore_Format_Report_HTML.py) as a separate formatter action. Pass it one report object, or an array of report objects from any mix of the IP, URL, email, and phone actions (e.g. the output of a For loop). It checks every block's `status_code`:

- Each successful report becomes its own section, showing only fields with values.
- Each failed lookup becomes an error line. It does not stop the other reports from rendering.
- Sections are separated with `<hr>`.

It returns `status_code` (200 if at least one report succeeded), `html`, and `failed_count`. Pass `html` to `Exabeam_Threat_Center > Create_a_note_for_a_case` to post it to a case. It can also be run standalone with the report JSON as a command-line argument or through standard input.

## Playbook Demonstration

See [IPQualityScore_Playbook_Outline.md](../IPQualityScore/IPQualityScore_Playbook_Outline.md) for the full version, including the case-note branch. Short version:

1. **Create Playbook**
   - Name: IPQualityScore Playbook
   - Add Step
   - Select Action > IPQualityScore > Extract_Public_IP_Addresses
   - src_ips > plug-in > flow_input.src_ips
   - dest_ips > plug-in > flow_input.dest_ips
   - Add Step
   - Select  For loop
   - Iterator expression: results.a
   - Add Step
   - Select Action > IPQualityScore > IPQualityScore_Action_Get_IP_Reputation
   - ip_to_check > plug-in > flow_input.iter.value
   - Add Step (after the loop)
   - Select Action > IPQualityScore > IPQualityScore_Format_Report_HTML
   - report > plug-in > results.b
   - Deploy

2. **Run Playbook from Threat Center**
   - Select a Case
   - Run a Playbook
   - Select IPQualityScore Playbook
   - Run

## Notes

- Every lookup, including `IPQualityScore_Test_Connection`, uses one IPQS credit.
- IPQS passes the API key in the request path (`/api/json/{type}/{API_KEY}/{value}`). The actions URL-encode the key and the lookup value, and never include the request URL in error messages.

## Reference Materials:

[IPQualityScore API Documentation](https://www.ipqualityscore.com/documentation/overview)<br>
[IPQualityScore Proxy Detection (IP) API](https://www.ipqualityscore.com/documentation/proxy-detection-api/overview)<br>
[IPQualityScore Malicious URL Scanner API](https://www.ipqualityscore.com/documentation/malicious-url-scanner-api/overview)<br>
[IPQualityScore Email Validation API](https://www.ipqualityscore.com/documentation/email-validation-api/overview)<br>
[IPQualityScore Phone Number Validation API](https://www.ipqualityscore.com/documentation/phone-number-validation-api/overview)<br>
