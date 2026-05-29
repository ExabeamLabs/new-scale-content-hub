# Exabeam Automation Management - Integration with urlscan.io

Description: Automation Management integration with urlscan.io.<br>
Version: 1.0<br>
Author: US Services Consultant - May 2026 - Initial<br>

## Setup Service

1. **Add Service**
   - Service name:  urlscan.io
   - Service Description:  urlscan.io integration version 1.0
   - Click Create Manually
   - Click Next

2. **Configure Service Parameters**
   - Service configuration parameters
   - Edit service configuration parameters
   - Click JSON editor
   - Paste contents from [service_configuration_parameters.json](../urlscan.io/service_configuration_parameters.json)
   - Save

3. **Add Service Instance**
   - Click on Instances tab
   - Click + Add Instance
   - Provide instance name: urlscan_io
   - api_key variable - Provide your urlscan.io API Key
   - Save
     
4. **Edit Action**
   - Edit action name:  Domain_Reputation_Lookup
   - Description:  Retrieves a report for a given Domain.
   - Paste code contents from action file:  [Domain_Reputation_Lookup.py](../urlscan.io/Domain_Reputation_Lookup.py)
   - Deploy
     

## Playbook Demonstration
1. **Create Playbook**
   - Name: urlscan.io Domain Reputation Lookup
   - Add Step
   - Select Action > Exabeam > Domain Reputation Lookup
   - domain > plug-in > flow_input.dest_ips
   - Deploy

## Reference Materials:

[urlscan.ip API v1 Documenation](https://urlscan.io/docs/api/)<br>
