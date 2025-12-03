# Exabeam Automation Management - Integration with VirusTotal

Description: This Automation Management integration with VirusTotal currently supports the Action of **Get an IP address report**<br>
Version: 1.0<br>
Author: Charlie Mac UK TAM - May 2025 - Email If Stuck<br>

## Setup Service

1. **Add Service**
   - Service name:  VirusTotal
   - Service Description:  VirusTotal integration version 1.0
   - Click Import from File or URL
   - Paste URL...   `https://github.com/ExabeamLabs/new-scale-content-hub/blob/main/Automation/VirusTotal/Exabeam_Service_Import-VirusTotal-Version_1.0.yaml`
   - Click Import and Next

2. **Configure Service Parameters**
   - Service configuration parameters
   - Edit service configuration parameters
   - Click JSON editor
   - Paste contents from [service_configuration_parameters.json](../service_configuration_parameters.json)

3. **Add Service Instance**
   - Provide instance name
   - VT_API_KEY variable - Provide your VirusTotal API Key
   - Save
  
4. **Add Action**
   - Action name:  Get an IP address report
   - Description:  Get an IP address report
   - Paste code contents from action file:  [VirusTotal_Action_IPLookup.py](../VirusTotal_Action_IPLookup.py)
   - Deploy

## Playbook Demonstration
5. **Create Playbook**
   - Name: VirusTotal IP Lookup
   - Add Step
   - Select Action > Exabeam > Get Information about an IP address
   - ip_to_check > plug-in > flow_input.dest_ips
   - VT_API_KEY > plug-in > "$var:f/exabeam/VirusTotal/{instance}/VT_API_KEY"
   - Deploy

6. **Run Playbook from Threat Center"
   - Select a Case
   - Run a Playbook
   - Select VirusTotal IP Lookup
   - Run


## Reference Materials:

[VirusTotal API Documenation](https://docs.virustotal.com/docs/api-overview)<br>
[VirusTotal API - ip-info](https://docs.virustotal.com/reference/ip-info)<br>
