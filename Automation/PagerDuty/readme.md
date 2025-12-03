# Exabeam Automation Management - Integration with PagerDuty 
Version: 1.0
Author: Nick Oneill US TAM - Sept 2025 - Reach out with any questions



### Installation steps
1. Add Service
  1.1. Service name:  PagerDuty
  1.2. Service Description:  PagerDuty integration version 1.0
  1.3. Click Import from File or URL  
  4. Paste URL...   https://github.com/ExabeamLabs/new-scale-content-hub/blob/main/Automation/PagerDuty/Exabeam_Service_Import-PagerDuty-Version_1.0.json
  5. Click Import and Next
2. Service configuration parameters
  1. Edit service configuration parameters
  2. Click JSON editor
  3. Paste contents from ~/PagerDuty/service_configuration_parameters.json
3. Add Action
  1. Action name:  Create an Incident
  2. Description:  Create an incident synchronously without a corresponding event from a monitoring service. An incident represents a problem or an issue that needs to be addressed and resolved.
  3. Paste code contents from action file:  ~/PagerDuty/pagerduty_create_an_incident.py
  4. Deploy

### Playbook to demonstrate usage

### Reference Materials:
[PagerDuty API Documenation][https://developer.pagerduty.com/api-reference/e65c5833eeb07-pager-duty-api]
[Postman Collection for PagerDuty API][https://www.postman.com/pagerduty/pagerduty-public-api-collection/collection/mfb3pn8/pagerduty-api]
