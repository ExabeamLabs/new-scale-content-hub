#!/bin/sh
set -e

# Cron-safe PATH
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

echo "=== $(date -u) Starting Jamf -> Exabeam pipeline ==="

# Hard-coded Jamf URL (non-secret)
export JAMF_BASE_URL="https://alphasights.jamfcloud.com"

# Load Exabeam config (non-secrets)
if [ ! -f /app/config/exabeam.env ]; then
  echo "[ERROR] /app/config/exabeam.env not found"
  exit 1
fi
set -a
. /app/config/exabeam.env
set +a

# Secrets must exist (either container env or sourced by cron wrapper)
: "${JAMF_CLIENT_ID:?JAMF_CLIENT_ID is not set}"
: "${JAMF_CLIENT_SECRET:?JAMF_CLIENT_SECRET is not set}"
: "${EXABEAM_API_KEY:?EXABEAM_API_KEY is not set}"
: "${EXABEAM_API_SECRET:?EXABEAM_API_SECRET is not set}"
: "${EXABEAM_URL:?EXABEAM_URL is not set}"
: "${CONTEXT_TABLE_NAME:?CONTEXT_TABLE_NAME is not set}"

PY="/usr/local/bin/python3"
if [ ! -x "$PY" ]; then
  PY="$(command -v python3 || true)"
fi
if [ -z "$PY" ]; then
  echo "[ERROR] python3 not found in PATH"
  exit 127
fi

FRIENDLY_CSV="/app/data/jamf_devices_friendly.csv"
MAPPED_CSV="/app/data/jamf_devices.csv"

# 1) Export Jamf devices (friendly headers)
"$PY" /app/scripts/jamf_devices_export.py

# 2) Map friendly headers -> Exabeam attribute IDs
export EXABEAM_TABLE_ID="PiF5EQaKIE"
export JAMF_CSV_FRIENDLY="$FRIENDLY_CSV"
export JAMF_CSV_EXABEAM="$MAPPED_CSV"
"$PY" /app/scripts/map_csv_headers_to_exabeam_ids.py

# 3) Upload mapped CSV to Exabeam
export CSV_FILENAME="$MAPPED_CSV"
sh /app/scripts/run_context_update.sh

echo "=== $(date -u) Finished Jamf -> Exabeam pipeline ==="

# Health marker – last successful run
[ "$?" -eq 0 ] && date -u > /app/logs/last_success_utc.txt
