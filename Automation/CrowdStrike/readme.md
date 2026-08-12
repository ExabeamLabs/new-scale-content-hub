# Exabeam Automation Management - Integration with CrowdStrike Falcon

Description: Automation Management integration with CrowdStrike Falcon APIs.<br>
Version: 1.0<br>
Author: Nick O'Neill US Service Consultant - August 2026 - Added to GitHub<br>

## Setup Service

1. **Add Service**
   - Service name:  CrowdStrike_Falcon
   - Service Description:  CrowdStrike Falcon API integration version 1.0
   - Click Create Manually
   - Click Next
   - Click JSON editor
   - Paste contents from [service_configuration_parameters.json](../CrowdStrike/service_configuration_parameters.json)
   - Save

3. **Add Service Instance**
   - Click on Instances tab
   - Click + Add Instance
   - Provide instance name: Falcon_API
   - CLIENT_ID variable - Provide your CrowdStrike Falcon API Client ID
   - CLIENT_SECRET variable - Provide your CrowdStrike Falcon API Client Secret
   - BASE_URL variable - Provide your CrowdStrike Falcon Base URL.
   - Save
  
4. **Edit Action**
   - Edit action name:  Get IP Reputation
   - Description:  Retrieves the reputation of a given IP address.
   - Paste code contents from action file:  [Get_IP_Reputation-CrowdStrike.py](../CrowdStrike/Get_IP_Reputation-CrowdStrike.py)
   - Deploy
     
5. **Edit Action**
   - Edit action name:  Get Domain Reputation
   - Description:  Retrieves the Reputation for a given Domain. 
   - Paste code contents from action file:  [Get_Domain_Reputation-CrowdStrike.py](../CrowdStrike/Get_Domain_Reputation-CrowdStrike.py)
   - Deploy
     
6. **Edit Action**
   - Edit action name:  Get Device details
   - Description:  Get Device details
   - Paste code contents from action file:  [Get_Device_Details-CrowdStrike.py](../CrowdStrike/Get_Device_Details-CrowdStrike.py)
   - Deploy
     
7. **Add Action**
   - Edit action name:  Contain Device
   - Description:  Contain Device
   - Paste code contents from action file:  [Contain Device-CrowdStrike.py](../CrowdStrike/Contain Device-CrowdStrike.py)
   - Deploy   



## Playbook Demonstration
1. **Create Playbook**
   - Name: CrowdStrike IP Reputation Lookup
   - Add Step
   - Select Action > Exabeam > Get IP Reputation CrowdStrike
   - ip_to_check > plug-in > flow_input.dest_ips
   - Deploy

## Reference Materials:
