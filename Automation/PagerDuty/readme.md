# Exabeam Automation Management - Integration with PagerDuty 

Description: This Automation Management integration with PagerDuty currently supports the Action of **Create an Incident**<br>
Version: 1.0<br>
Author: Nick Oneill US TAM - Sept 2025 - Reach out with any questions<br>


## Setup Service
1. **Add Service**
   - Service name:  PagerDuty
   - Service Description:  PagerDuty integration version 1.0
   - Click Import from File or URL  
   - Paste URL...   `https://github.com/ExabeamLabs/new-scale-content-hub/blob/main/Automation/PagerDuty/Exabeam_Service_Import-PagerDuty-Version_1.0.json`
   - Click Import and Next

2. **Configure Service**
   - Service configuration parameters
   - Edit service configuration parameters
   - Click JSON editor
   - Paste contents from [service_configuration_parameters.json](../PagerDuty/service_configuration_parameters.json)

3. **Add Action**
   - Action name:  Create an Incident
   - Description:  Create an incident synchronously without a corresponding event from a monitoring service. An incident represents a problem or an issue that needs to be addressed and resolved.
   - Paste code contents from action file:  [pagerduty_create_an_incident.py](../PagerDuty/pagerduty_create_an_incident.py)
   - Deploy

## Playbook to demonstrate usage
PLACEHOLDER

## Reference Materials:
[PagerDuty API Documenation](https://developer.pagerduty.com/api-reference/e65c5833eeb07-pager-duty-api)<br>
[Postman Collection for PagerDuty API](https://www.postman.com/pagerduty/pagerduty-public-api-collection/collection/mfb3pn8/pagerduty-api)
