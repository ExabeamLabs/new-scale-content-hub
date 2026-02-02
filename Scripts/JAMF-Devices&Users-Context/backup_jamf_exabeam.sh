#!/bin/sh
set -e

BASE="/app/backups"
DATE="$(date -u +%Y%m%d)"
DOW="$(date -u +%u)"   # 1=Mon .. 7=Sun
DOM="$(date -u +%d)"   # 01..31
HOST="$(hostname | tr -cd 'A-Za-z0-9._-' | cut -c1-40)"

mkdir -p "$BASE/daily" "$BASE/weekly" "$BASE/monthly"

backup() {
  dest="$1"
  name="$2"
  # Use relative paths to avoid leading '/' warnings
  tar -C /app -czf "$dest/$name.tgz" scripts config
}

# DAILY (keep 7)
backup "$BASE/daily" "jamf_exabeam_${HOST}_daily_${DATE}"
ls -1t "$BASE/daily"/*.tgz | tail -n +8 | xargs -r rm -f

# WEEKLY (Sunday, keep 4)
if [ "$DOW" = "7" ]; then
  backup "$BASE/weekly" "jamf_exabeam_${HOST}_weekly_${DATE}"
  ls -1t "$BASE/weekly"/*.tgz | tail -n +5 | xargs -r rm -f
fi

# MONTHLY (1st, keep 1)
if [ "$DOM" = "01" ]; then
  backup "$BASE/monthly" "jamf_exabeam_${HOST}_monthly_${DATE}"
  ls -1t "$BASE/monthly"/*.tgz | tail -n +2 | xargs -r rm -f
fi
