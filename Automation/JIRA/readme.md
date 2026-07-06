# Exabeam Automation Management - Integration with JIRA

Description: Automation Management integration with JIRA.<br>
Version: 1.0<br>
Author: US Services Consultant - July 2026 - Initial<br>

## Setup Service

1. **Add Service**
   - Service name:  JIRA
   - Service Description:  JIRA integration version 1.0
   - Click Create Manually
   - Click Next

2. **Configure Service Parameters**
   - Service configuration parameters
   - Edit service configuration parameters
   - Click JSON editor
   - Paste contents from [service_configuration_parameters.json](../JIRA/service_configuration_parameters.json)
   - Save

3. **Add Service Instance**
   - Click on Instances tab
   - Click + Add Instance
   - Provide instance name: JIRA
   - api_key variable - Provide your JIRA API Key
   - Save
     
4. **Edit Action**
   - Edit action name:  Create External Ticket - JIRA
   - Description:  Creates a ticket in JIRA.
   - Paste code contents from action file:  [Create_External_Ticket-JIRA.py](../JIRA/Create_External_Ticket-JIRA.py)
   - Deploy
     

## Playbook Demonstration
1. **Create Playbook**
   - Name: Create External Ticket - JIRA
   - Description: Creates a ticket in JIRA.
   - Trigger: No Trigger
   - Add Step
   - Select Action > Exabeam > Create External Ticket - JIRA
   - Deploy

## Reference Materials:

<br>
