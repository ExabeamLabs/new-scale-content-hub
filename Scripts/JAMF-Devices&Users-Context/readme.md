# JAMF to Exabeam Context Management Tool

This repository contains a set of Python scripts and shell wrappers used to synchronise device and asset context from **JAMF** into **Exabeam** using Exabeam Context Tables.

The tool is designed for SIEM engineering and security operations teams who need reliable, repeatable enrichment of Exabeam data with JAMF-managed device information to support detections, investigations, and automation workflows.

---

## Overview

The tool performs the following functions:

* Extracts device and user data from the JAMF API
* Normalises and maps JAMF fields to Exabeam Context Table column IDs
* Updates Exabeam Context Tables via the Exabeam REST API
* Supports automated execution via shell scripts and cron
* Keeps data export, field mapping, and context updates logically separated

This allows Exabeam to enrich events with authoritative JAMF context such as device ownership, user associations, host identifiers, and asset metadata.

---

## Repository Structure

```
.
├── ContextTableUpdate.py              # Updates Exabeam context tables via API
├── jamf_devices_export.py             # Exports device data from the JAMF API
├── map_csv_headers_to_exabeam_ids.py  # Maps CSV headers to Exabeam context column IDs
│
├── run_jamf_to_exabeam.sh             # End-to-end JAMF to Exabeam execution
├── run_context_update.sh              # Runs context updates only
├── cron_jamf_to_exabeam.sh            # Cron-friendly execution wrapper
├── backup_jamf_exabeam.sh             # Optional backup of exported/context data
│
├── requirements.txt                   # Python dependencies
└── __pycache__/                       # Python cache (not committed)
```

---

## Data Flow

1. **JAMF Export**
   `jamf_devices_export.py` connects to the JAMF API and exports device and user data, typically as CSV.

2. **Field Mapping**
   `map_csv_headers_to_exabeam_ids.py` maps JAMF CSV fields to Exabeam Context Table column IDs.

3. **Context Update**
   `ContextTableUpdate.py` submits the normalised data to Exabeam using the REST API.

4. **Automation**
   Shell scripts allow the process to be chained, scheduled, and operated via cron.

---

## Prerequisites

### Python

* Python 3.9 or later

### Dependencies

Install required modules using:

```bash
pip install -r requirements.txt
```

### API Access

The following access is required:

* JAMF API credentials
* Exabeam API token with permission to manage context tables

Credentials should not be hard-coded. Environment variables or a secure secrets mechanism should be used.

---

## Configuration

Recommended environment variables:

```bash
export JAMF_URL="https://your-jamf-instance"
export JAMF_USERNAME="api_user"
export JAMF_PASSWORD="********"

export EXABEAM_BASE_URL="https://your-exabeam-instance"
export EXABEAM_API_TOKEN="********"
```

Shell wrappers can be updated to source these variables as required.

---

## Running the Tool

### Full JAMF to Exabeam Sync

```bash
./run_jamf_to_exabeam.sh
```

### Context Update Only

```bash
./run_context_update.sh
```

### Scheduled Execution

Example cron entry:

```bash
0 2 * * * /path/to/cron_jamf_to_exabeam.sh >> /var/log/jamf_exabeam.log 2>&1
```

---

## Typical Use Cases

* Enriching Exabeam detections with JAMF-managed device context
* Improving investigations through accurate user-to-device mapping
* Maintaining consistent and up-to-date Exabeam context tables
* Supporting SOAR and response workflows that depend on asset context

---

## Operational Notes

* Validate mappings against non-production context tables before live use
* Monitor JAMF API rate limits
* Retain exported data for troubleshooting and audit purposes
* Consider change control and versioning in regulated environments

---

## Contributions

Improvements are welcome, particularly around:

* Additional JAMF endpoints
* Field mapping enhancements
* Error handling and retries
* Logging and operational resilience

---

## Disclaimer

This project is provided as-is. It should be reviewed and tested in line with organisational security, compliance, and change management requirements before use in production environments.
