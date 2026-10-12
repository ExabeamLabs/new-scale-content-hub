# Exabeam Automation Management - Integration with Exabeam Threat Center

Description: Automation Management integration with Exabeam Threat Center<br>
Version: 1.0<br>
Author: Mark Ulmer - US Services Consultant - May 2026 - Created inital version<br>

## Setup Service

1. **Add Service**
   - Service name:  Exabeam_Threat_Center 
   - Service Description:  Integration with Exabeam Threat Center APIs.
   - Click Import from File or URL
   - Paste URL...   `https://raw.githubusercontent.com/ExabeamLabs/new-scale-content-hub/refs/heads/main/Automation/Exabeam/Threat-Center/Exabeam_Service_Import-ThreatCenter-Version_1.0.json`
   - Click Confirm and Validate
   - Click Import and Next

3. **Configure Service Parameters**
   - Service configuration parameters
   - Edit service configuration parameters
   - Click JSON editor
   - Paste contents from [service_configuration_parameters.json](../Context-Management/service_configuration_parameters.json)
   - Save

4. **Add Action**
   - Action name:  Create_a_note_for_a_case
   - Description:  Create a note for a case
   - Paste code contents from action file:  [Create_a_note_for_a_case.py](../Context-Management/Create_a_note_for_a_case.py)
   - Deploy
  
5. **Add Service Instance**
   - Click on Instances tab
   - Click + Add Instance
   - Instance name: Exabeam_Threat_Center
   - Select your deployment region
   - Provide your API Key ID
   - Provide your API Key Secret
   - Save


## Reference Materials:

[Exabeam API Documenation](https://developers.exabeam.com/exabeam/reference/threat-center-create-case-note)<br>
