# Exabeam Automation Management - Integration with JIRA

Description: Automation Management integration with JIRA.<br>
Version: 1.0<br>
Author: US Services Consultant - July 2026 - Initial<br>

## Setup Service

1. **Add Service**
   - Service name:  JIRA
   - Service Description:  JIRA integration version 1.0
   - Click Import from File or URL
   - Paste URL... `https://raw.githubusercontent.com/ExabeamLabs/new-scale-content-hub/refs/heads/main/Automation/JIRA/Exabeam_Service_Import-JIRA.json`
   - Click Confirm and Validate
   - Click Import and Next

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
   - Edit action name:  Create Issue in JIRA
   - Paste code contents from action file:  [Create_Issue_JIRA.py](../JIRA/Create_Issue_JIRA.py)
   - Deploy
  
5. **Edit Action**
   - Edit action name:  Add Comment to Issue in JIRA
   - Paste code contents from action file:  [Add_Issue_Comment_JIRA.py](../JIRA/Add_Issue_Comment_JIRA.py)
   - Deploy

6. **Edit Action**
   - Edit action name:  Get Issue Details from JiRA
   - Paste code contents from action file:  [Get_Issue_Details_JIRA.py](../JIRA/Get_Issue_Details_JIRA.py)
   - Deploy

## Playbook Demonstration
1. **Create Playbook**
   - Name: Create Issue in JIRA
   - Description: Creates an Issue in JIRA.
   - Trigger: No Trigger
   - Add Step   - Select Action > Threat Center > GetCaseDetails
     - case_id = flow_input.case_id
   - Add Step   - Select Action > Exabeam > Create Issue in JIRA
     - jira_project = "KAN"
     - jira_summary = results.a.alertName
   - Add Step   - Run one Branch
   - Edit Branch 1
     - Predicate expression = results.b
     - Add Step   - Selection Action > Exabeam > Create_a_note_for_a_case
       - CASE_UUID = flow_input.case_id
       - NOTE_CONTENT = results.b
   - Deploy

## Reference Materials:
https://developer.atlassian.com/server/jira/platform/jira-rest-api-examples/
<br>
