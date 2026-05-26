# Exabeam Automation Management - Integration with CrowdStrike Falcon APIs

Description: Automation Management integration with CrowdStrike Falcon APIs.<br>
Version: 1.0<br>
Author: Mark Ulmer US Service Consultant - May 2026 - Initial<br>

## Setup Service

1. **Add Service**
   - Service name:  CrowdStrikeFalcon
   - Service Description:  CrowdStrike Falcon integration version 1.0
   - Click Import from File or URL
   - Paste URL...   `https://raw.githubusercontent.com/ExabeamLabs/new-scale-content-hub/refs/heads/main/Automation/CrowdStrikeFalcon/Exabeam_Service_Import-CrowdStrikeFalcon-Version_1.0.json`
   - Click Confirm and Validate
   - Click Import and Next

3. **Configure Service Parameters**
   - Service configuration parameters
   - Edit service configuration parameters
   - Click JSON editor
   - Paste contents from [service_configuration_parameters.json](../CrowdStrikeFalcon/service_configuration_parameters.json)
   - Save

4. **Edit Action**
   - Edit action name:  Test Connection
   - Description:  Tests if the service credentials could establish a connection.
   - Paste code contents from action file:  [Test_Connection.py](../CrowdStrikeFalcon/Test_Connection.py)
   - Deploy
     
7. **Add Service Instance**
   - Click on Instances tab
   - Click + Add Instance
   - Provide instance name
   - BASE_URL variable - Provide your CrowdStrike Falcon Base URL
   - CLIENT_ID variable - Provide your CrowdStrike Falcon CLIENT_ID
   - CLIENT_SECRET variable - Provide your CrowdStrike Falcon CLIENT_SECRET
   - Save


## Playbook Demonstration
1. **Create Playbook**
   - Name: CrowdStrikeFalcon
   - Add Step
   - Select Action > Exabeam > Test_Connection
   - BASE_URL > plug-in > "$var:f/exabeam/CrowdStrikeFalcon/{instance}/BASE_URL"
   - CLIENT_ID > plug-in > "$var:f/exabeam/CrowdStrikeFalcon/{instance}/CLIENT_ID"
   - CLIENT_SECRET > plug-in > "$var:f/exabeam/CrowdStrikeFalcon/{instance}/CLIENT_SECRET"
   - Deploy

## Reference Materials:

[CrowdStrike OpenAPI Documenation](https://developer.crowdstrike.com/docs/openapi/)  This requires a CrowdStrike portal login.<br>
