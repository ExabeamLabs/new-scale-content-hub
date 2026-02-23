# Log Stream Enrichment - Source MAC Address to OUI Vendor

Description: Here is an old SIEM technique; enrich your logs with the Vendor name from the organizationally unique identifier (OUI).<br>
Version: 1.0<br>
Author: Mark Ulmer US Service Consultant - February 2026<br>

## Setup Service

1. **Add Context Table**
   - Navigate to Context Management then select "New Context Table"
   - Select "Add Custom"
   - Context Table Name: OUI_Lookup
   - Context Table Type: Other
   - Next
   - Add Attributes: Key and Value
   - Create
   
2. **Upload full OUI list from CSV**
   - Navigate to OUI_Lookup
   - Download this file [OUI_Lookup_Full_List_OUI_Lowercase.csv](../OUI_Vendor_Enrichment/OUI_Lookup_Full_List_OUI_Lowercase.csv)
   - Upload CSV
   - Append Data
   
3. **Log Stream | Enrichments **
   - Navigate to Log Stream, then select Enrichments
   - Download this Enrichment config file [Enrichment-Source_MAC_Address_to_OUI_Vendor.conf](../OUI_Vendor_Enrichment/Enrichment-Source_MAC_Address_to_OUI_Vendor.conf)
   - Import and select file

## Here is what an Enrichment looks like:
<img width="606" height="330" alt="image" src="../OUI_Vendor_Enrichment/Screenshot_Enrichment-Source_MAC_Address_to_OUI_Vendor.png" />

<br>
There is also a [Dashboard.config](../../Dashboards/Devices_by_MAC_Vendor_v1.config)
<br>
   
## Reference Materials:
[YouTube video - Using MAC Address To Determine Manufacturer](https://youtu.be/gCXLO5cCTzM?si=bfloCcdNSrLy6EPQ)<br>
[Wikipedia - What is Organizationally unique identifier](https://en.wikipedia.org/wiki/Organizationally_unique_identifier)<br>
[Source Database of All MAC OUI](https://maclookup.app/downloads/csv-database)<br>

