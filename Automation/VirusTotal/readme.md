# Exabeam Automation Management - Integration with VirusTotal

Description: Automation Management integration with VirusTotal V3 APIs.<br>
Version: 1.2<br>
Author: Exabeam Labs<br>
Date updated: Sept 21 2026<br>

## Setup Service

1. **Add Service**
   - Service name:  VirusTotal
   - Service Description:  VirusTotal integration version 1.2
   - Click Import from File or URL
   - Paste URL...   `https://raw.githubusercontent.com/ExabeamLabs/new-scale-content-hub/refs/heads/main/Automation/VirusTotal/Exabeam_Service_Import-VirusTotal-Version_1.2.json`
   - Click Confirm and Validate
   - Click Import and Next

2. **Configure Service Parameters**
   - Service configuration parameters
   - Edit service configuration parameters
   - Click JSON editor
   - Paste contents from [service_configuration_parameters.json](../VirusTotal/service_configuration_parameters.json)
   - Save

3. **Add Service Instance**
   - Click on Instances tab
   - Click + Add Instance
   - Provide instance name: VirusTotal
   - VT_API_KEY variable - Provide your VirusTotal API Key
   - Save
  
4. **Edit Action**
   - Edit action name:  VirusTotal_Action_Get_IP_Report
   - Description:  Retrieves a report for a given IP address. The report includes threat reputation from various antivirus engines.
   - Paste code contents from action file:  [VirusTotal_Action_Get_IP_Report.py](../VirusTotal/VirusTotal_Action_Get_IP_Report.py)
   - Deploy
     
5. **Edit Action**
   - Edit action name:  VirusTotal_Action_Get_Domain_Report
   - Description:  Retrieves a report for a given Domain. The report includes threat reputation from various antivirus engines.
   - Paste code contents from action file:  [VirusTotal_Action_Get_Domain_Report.py](../VirusTotal/VirusTotal_Action_Get_Domain_Report.py)
   - Deploy
     
6. **Edit Action**
   - Edit action name:  VirusTotal_Action_Get_URL_Report
   - Description:  Retrieves a report for a given URL. The report includes threat reputation from various antivirus engines.
   - Paste code contents from action file:  [VirusTotal_Action_Get_URL_Report.py](../VirusTotal/VirusTotal_Action_Get_URL_Report.py)
   - Deploy
     
7. **Add Action**
   - Edit action name:  Extract_Public_IP_Addresses
   - Description:  Extract and return only public ip addresses.
   - Paste code contents from action file:  [Extract_Public_IP_Addresses.py](../VirusTotal/Extract_Public_IP_Addresses.py)
   - Deploy   

8. **Add Action**
   - Edit action name:  Format_Report_HTML
   - Description:  Format a VirusTotal report as HTML, including only fields with values.
   - Paste code contents from action file:  [Format_Report_HTML.py](../VirusTotal/Format_Report_HTML.py)
   - Deploy

## Report HTML Formatting

The IP, domain, and URL report actions return a JSON object with a `status_code` and either `data` or `error`:

```json
{
   "status_code": 200,
   "data": {
      "ip": "8.8.8.8"
   }
}
```

Use [Format_Report_HTML.py](../VirusTotal/Format_Report_HTML.py) as a separate formatter action, passing it either one report object or an array of report objects from the three report actions. It returns a JSON object with `status_code` and an `html` block containing only fields with values. It can also be run standalone with the report JSON as a command-line argument or through standard input.



## Playbook Demonstration
1. **Create Playbook**
   - Name: VirusTotal Playbook
   - Add Step
   - Select Action > Exabeam > Extract_Public_IP_Addresses
   - src_ips > plug-in > flow_input.src_ips
   - dest_ips > plug-in > flow_input.dest_ips
   - Add Step
   - Select  For loop 
   - Iterator expression: results.a
   - Add Step
   - Select Action > Exabeam > VirusTotal_Action_Get_IP_Report
   - ip_to_check > plug-in > flow_input.iter.value
   - Deploy

2. **Run Playbook from Threat Center**
   - Select a Case
   - Run a Playbook
   - Select VirusTotal Playbook
   - Run


## Reference Materials:

[VirusTotal API Documenation](https://docs.virustotal.com/docs/api-overview)<br>
[VirusTotal API Reference](https://docs.virustotal.com/reference/overview)<br>
