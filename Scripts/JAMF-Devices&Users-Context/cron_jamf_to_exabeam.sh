#!/bin/sh
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
set -e

LOCKDIR="/app/logs/jamf_to_exabeam.lock"
LOG="/app/logs/jamf_to_exabeam.log"

mkdir -p /app/logs

if ! mkdir "$LOCKDIR" 2>/dev/null; then
  echo "=== $(date -u) Skipping: previous run still active ===" >> "$LOG"
  exit 0
fi
cleanup() { rmdir "$LOCKDIR" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# Load non-secret config
if [ -f /app/config/exabeam.env ]; then
  set -a
  . /app/config/exabeam.env
  set +a
fi

# Load secrets for cron
if [ -f /app/config/cron_secrets.env ]; then
  set -a
  . /app/config/cron_secrets.env
  set +a
fi

echo "=== $(date -u) Cron run started ===" >> "$LOG"
sh /app/scripts/run_jamf_to_exabeam.sh >> "$LOG" 2>&1
rc=$?
echo "=== $(date -u) Cron run finished (exit=$rc) ===" >> "$LOG"
exit $rc
