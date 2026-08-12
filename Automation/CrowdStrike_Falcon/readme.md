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

2. **Add Service Instance**
   - Click on Instances tab
   - Click + Add Instance
   - Provide instance name: Falcon_API
   - CLIENT_ID variable - Provide your CrowdStrike Falcon API Client ID
   - CLIENT_SECRET variable - Provide your CrowdStrike Falcon API Client Secret
   - BASE_URL variable - Provide your CrowdStrike Falcon Base URL.
   - Save
  
3. **Edit Action**
   - Edit action name:  Get_IP_Reputation_CrowdStrike
   - Description:  Retrieves the reputation of a given IP address.
   - Paste code contents from action file:  [Get_IP_Reputation_CrowdStrike.py](../CrowdStrike_Falcon/Get_IP_Reputation_CrowdStrike.py)
   - Deploy
     
4. **Edit Action**
   - Edit action name:  Get_Domain_Reputation_CrowdStrike
   - Description:  Retrieves the Reputation for a given Domain. 
   - Paste code contents from action file:  [Get_Domain_Reputation_CrowdStrike.py](../CrowdStrike_Falcon/Get_Domain_Reputation_CrowdStrike.py)
   - Deploy
     
5. **Edit Action**
   - Edit action name:  Get_Device_Details_CrowdStrike
   - Description:  Get Device details
   - Paste code contents from action file:  [Get_Device_Details_CrowdStrike.py](../CrowdStrike_Falcon/Get_Device_Details_CrowdStrike.py)
   - Deploy
     
6. **Add Action**
   - Edit action name:  Get_Device_Processes_CrowdStrike
   - Description:  Get the processes from a device.
   - Paste code contents from action file:  [Contain_Device_CrowdStrike.py](../CrowdStrike_Falcon/Get_Device_Processes_CrowdStrike.py)
   - Deploy   

7. **Add Action**
   - Edit action name:  Get_Process_Info_CrowdStrike
   - Description:  Get the process information.
   - Paste code contents from action file:  [Contain_Device_CrowdStrike.py](../CrowdStrike_Falcon/Contain_Device_CrowdStrike.py)
   - Deploy   

8. **Add Action**
   - Edit action name:  Get_User_Info_CrowdStrike
   - Description:  Get the user information.
   - Paste code contents from action file:  [Contain_Device_CrowdStrike.py](../CrowdStrike_Falcon/Get_User_Info_CrowdStrike.py)
   - Deploy 

8. **Add Action**
   - Edit action name:  Contain_Device_CrowdStrike
   - Description:  Contain a sevice.
   - Paste code contents from action file:  [Contain_Device_CrowdStrike.py](../CrowdStrike_Falcon/Contain_Device_CrowdStrike.py)
   - Deploy   

## Playbook Demonstrations
1. **Create Playbook**
   - Name: CrowdStrike IP Reputation Lookup
   - Add Step
   - Select Action > Exabeam > Get_IP_Reputation_CrowdStrike
   - ip > plug-in > flow_input.dest_ips
   - Deploy

2. **Create Playbook**
   - Name: CrowdStrike Contain a Device
   - Add Step
   - Select Action > Exabeam > Get_Device_Details_CrowdStrike
   - hostname > plug-in > flow_input.??????
   - Add Step
   - Select Action > Exabeam > Contain_Device_CrowdStrike
   - hostname > plug-in > flow_input.??????
   - Deploy

## Reference Materials:
