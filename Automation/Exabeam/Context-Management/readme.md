# Exabeam Automation Management - Integration with Exabeam Context Management Tables

Description: This Automation Management integration with Exabeam currently supports Context Management Actions of **Add Context Records, Delete Context Records and Get Context Record**<br>
Version: 1.0<br>
Author: Michael McGilton - US Service Consultant  - October 2025<br>
Author: Mark Ulmer - US Service Consultant - December 2025 - Added to GitHub and created readme<br>

## Setup Service

1. **Add Service**
   - Service name:  ExabeamContextManagement 
   - Service Description:  ExabeamContextManagement integration version 1.0
   - Click Import from File or URL
   - Paste URL...   `https://raw.githubusercontent.com/ExabeamLabs/new-scale-content-hub/refs/heads/main/Automation/.Exabeam/Context-Management/Exabeam_Service_Import-ContextManagement-Version_1.0.json`
   - Click Confirm and Validate
   - Click Import and Next

3. **Configure Service Parameters**
   - Service configuration parameters
   - Edit service configuration parameters
   - Click JSON editor
   - Paste contents from [service_configuration_parameters.json](../Context-Management/service_configuration_parameters.json)
   - Save

4. **Edit Action**
   - Edit action name:  Add context records to an existing table
   - Paste code contents from action file:  [Add_context_records.py](../Context-Management/Add_context_records.py)
   - Deploy
  
   **Edit Action**
   - Edit action name:  Delete records from an existing custom context table
   - Paste code contents from action file:  [Delete_context_records.py](../Context-Management/Delete_context_records.py)
   - Deploy
  
   **Edit Action**
   - Edit action name:  Get table records by ID
   - Paste code contents from action file:  [Get_context_record.py](../Context-Management/Get_context_record.py)
   - Deploy

5. **Add Service Instance**
   - Click on Instances tab
   - Click + Add Instance
   - Provide instance name
   - Select your deployment region
   - Provide your API Key ID
   - Provide your API Key Secret
   - Save


## Reference Materials:

[Exabeam API Documenation](https://developers.exabeam.com/exabeam/reference/getcontext-managementv1tables)<br>
