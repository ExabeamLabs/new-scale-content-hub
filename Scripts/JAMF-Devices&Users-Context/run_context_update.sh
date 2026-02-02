#!/bin/sh
set -e

# Load configuration
. /app/config/exabeam.env

python /app/scripts/ContextTableUpdate.py \
  --exabeam-url "$EXABEAM_URL" \
  --context-table-name "$CONTEXT_TABLE_NAME" \
  --csv-filename "$CSV_FILENAME"
