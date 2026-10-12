# Exabeam Automation Management - Integration with ServiceNow

Description: This Automation Management integration with ServiceNow exposes the Table API actions to create, retrieve, modify, update, and delete records on tables available to the configured account.<br>
Version: 1.0<br>
Author: US Services Consultants - Oct 2026<br>

## Setup Service

1. **Add Service**
   - Service name:  ServiceNow
   - Service Description:  ServiceNow integration version 1.0
   - Click Import from File or URL
   - Paste URL...   `https://raw.githubusercontent.com/ExabeamLabs/new-scale-content-hub/refs/heads/main/Automation/ServiceNow/Exabeam_Service_Import-SNOW_ITSM_IncidentTable.json`
   - Click Confirm and Validate
   - Click Import and Next

## Supported Actions

- **Create a record**: Create a record in a table.
- **Retrieve a record**: Retrieve a record by its `sys_id`.
- **Retrieve records from a table**: Retrieve table records, with optional query and field filters.
- **Modify a record**: Replace a record using the Table API `PUT` operation.
- **Update a record**: Update fields using the Table API `PATCH` operation.
- **Delete a record**: Delete a record by its `sys_id`.

The configured ServiceNow account must have the required access to the target table and operation.


## Python Actions

- `Create_Record.py` creates a new record using the Table API `POST` operation.
- `Delete_Record.py` deletes a record by `sys_id`.
- `Modify_Record.py` replaces a record with the supplied JSON object using `PUT`.
- `Retrieve_Records_From_Table.py` retrieves table records using optional `sysparm_*` filters.
- `Retrieve_Record.py` retrieves one record by `sys_id`.
- `Update_Record.py` updates supplied fields using `PATCH`.

These scripts read the ServiceNow username, password, and tenant from the existing Windmill variables under `f/exabeam/ServiceNow/ServiceNow/`.
  
## ServiceNow API Reference

This integration uses the [ServiceNow REST Table API](https://docs.servicenow.com/?context=CSHelp:REST-Table-API) for Incident records:

- Collection: `/api/now/v2/table/incident`
- Individual record: `/api/now/v2/table/incident/{sys_id}`