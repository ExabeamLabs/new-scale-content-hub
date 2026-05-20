# Exabeam Automation Management - Integration with VirusTotal

Description: This Automation Management integration with VirusTotal currently supports the Action of **Get an IP address report**<br>
Version: 1.1<br>
Author: Charlie Mac UK TAM - May 2025 - Email If Stuck<br>
Author: Mark Ulmer US Service Consultant - December 2025 - Moved api_key to instance variable<br>
Author: Mark Ulmer US Service Consultant - May 2026 - Added Get Domain Report<br>

## Setup Service

1. **Add Service**
   - Service name:  VirusTotal
   - Service Description:  VirusTotal integration version 1.1
   - Click Import from File or URL
   - Paste URL...   `https://raw.githubusercontent.com/ExabeamLabs/new-scale-content-hub/refs/heads/main/Automation/VirusTotal/Exabeam_Service_Import-VirusTotal-Version_1.1.json`
   - Click Confirm and Validate
   - Click Import and Next

3. **Configure Service Parameters**
   - Service configuration parameters
   - Edit service configuration parameters
   - Click JSON editor
   - Paste contents from [service_configuration_parameters.json](../VirusTotal/service_configuration_parameters.json)
   - Save

4. **Edit Action**
   - Edit action name:  Get an IP address report
   - Description:  Get an IP address report
   - Paste code contents from action file:  [VirusTotal_Action_Get_IP_Report.py](../VirusTotal/VirusTotal_Action_Get_IP_Report.py)
   - Deploy
     
5. **Edit Action**
   - Edit action name:  Get a Domain report
   - Description:  Get a Domain report
   - Paste code contents from action file:  [VirusTotal_Action_Get_Domain_Report.py](../VirusTotal/VirusTotal_Action_Get_Domain_Report.py)
   - Deploy
     
6. **Add Service Instance**
   - Click on Instances tab
   - Click + Add Instance
   - Provide instance name
   - VT_API_KEY variable - Provide your VirusTotal API Key
   - Save


## Playbook Demonstration
1. **Create Playbook**
   - Name: VirusTotal IP Lookup
   - Add Step
   - Select Action > Exabeam > Get an IP address report
   - ip_to_check > plug-in > flow_input.dest_ips
   - VT_API_KEY > plug-in > "$var:f/exabeam/VirusTotal/{instance}/VT_API_KEY"
   - Deploy

2. **Run Playbook from Threat Center**
   - Select a Case
   - Run a Playbook
   - Select VirusTotal IP Lookup
   - Run


## Reference Materials:

[VirusTotal API Documenation](https://docs.virustotal.com/docs/api-overview)<br>
[VirusTotal API - ip-info](https://docs.virustotal.com/reference/ip-info)<br>
[VirusTotal API - domain-info](https://docs.virustotal.com/reference/domain-info)<br>
