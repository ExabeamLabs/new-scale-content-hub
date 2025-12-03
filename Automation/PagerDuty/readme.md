# Exabeam Automation Management - Integration with PagerDuty 
Description: This Automation Management integration with PagerDuty currently supports the Action of **Create an Incident**<br>
Version: 1.0<br>
Author: Nick Oneill US TAM - Sept 2025 - Reach out with any questions<br>


### Install Service
1. Add Service
2. Service name:  PagerDuty
3. Service Description:  PagerDuty integration version 1.0
4. Click Import from File or URL  
5. Paste URL...   `https://github.com/ExabeamLabs/new-scale-content-hub/blob/main/Automation/PagerDuty/Exabeam_Service_Import-PagerDuty-Version_1.0.json`
6. Click Import and Next

### Configure Service
1. Service configuration parameters
2. Edit service configuration parameters
3. Click JSON editor
4. Paste contents from [service_configuration_parameters.json](../service_configuration_parameters.json)

### Add Action
1. Action name:  Create an Incident
2. Description:  Create an incident synchronously without a corresponding event from a monitoring service. An incident represents a problem or an issue that needs to be addressed and resolved.
3. Paste code contents from action file:  [pagerduty_create_an_incident.py](../pagerduty_create_an_incident.py)
4. Deploy

### Playbook to demonstrate usage
PLACEHOLDER

### Reference Materials:
[PagerDuty API Documenation](https://developer.pagerduty.com/api-reference/e65c5833eeb07-pager-duty-api)
[Postman Collection for PagerDuty API](https://www.postman.com/pagerduty/pagerduty-public-api-collection/collection/mfb3pn8/pagerduty-api)
