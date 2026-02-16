# Exabeam Log Stream Enrichment - Source MAC Address to OUI Vendor

Description: Here is an old SIEM technique; enrich your logs with the Vendor name from the organizationally unique identifier (OUI).<br>
Version: 1.0<br>
Author: Mark Ulmer US Service Consultant - February 2026<br>

## Setup Service

1. **Add Context Table**
   - Context Table Name: OUI_Lookup
   - Custom Table
   - Select attributes: Key and Value
   - Save
   
2. **Upload a Suspicious list from CSV**
   - Upload [OUI_Lookup_Suspicious.csv](../OUI_Vendor_Enrichment/OUI_Lookup_Suspicious.csv)
   
3. **Upload a Common list from CSV**
   - Upload [OUI_Lookup_Common.csv](../OUI_Vendor_Enrichment/OUI_Lookup_Common.csv)
   
4. **LogStream | Enrichments **
   - Import Enrichment config file [Enrichment-Source_MAC_Address_to_OUI_Vendor.conf](../OUI_Vendor_Enrichment/Enrichment-Source_MAC_Address_to_OUI_Vendor.conf)

## Here is what is looks like:
<img width="606" height="330" alt="image" src="../OUI_Vendor_Enrichment/Screenshot_Enrichment-Source_MAC_Address_to_OUI_Vendor.png" />
   
   
## Reference Materials:

[Organizationally unique identifier](https://en.wikipedia.org/wiki/Organizationally_unique_identifier)
[Cisco Quick Tip - Using MAC Address To Determine Manufacturer](https://youtu.be/gCXLO5cCTzM?si=bfloCcdNSrLy6EPQ)<br>
