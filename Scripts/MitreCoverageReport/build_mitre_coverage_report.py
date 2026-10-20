"""
Exabeam MITRE Coverage Report

Pulls MITRE technique metadata and correlation rules from Exabeam, then writes:
  - CSVs (all techniques, coverage, gaps, rule health)
  - a single self-contained HTML dashboard
  - an ATT&CK Navigator layer
  - a snapshot.json used to show changes between runs

Credentials are read (in order) from: command-line flags, the EXABEAM_CLIENT_ID /
EXABEAM_CLIENT_SECRET environment variables, the constants below, or an interactive prompt.

Run with --help for all options.
"""
import argparse
import csv
import getpass
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

try:  # optional: the Word executive briefing needs python-docx
    from executive_report import build_executive_report
except ImportError as _docx_error:
    build_executive_report = None
    DOCX_IMPORT_ERROR = str(_docx_error)

# -----------------------------
# ANSI colour codes (terminal)
# -----------------------------
if os.name == "nt":
    os.system("")  # enables ANSI colour handling in older Windows consoles (PowerShell 5.1, cmd)
_COLOUR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
ANSI_GREEN = "\033[92m" if _COLOUR else ""
ANSI_YELLOW = "\033[93m" if _COLOUR else ""
ANSI_RESET = "\033[0m" if _COLOUR else ""

# =========================================================
# 1) DEFAULT CONFIGURATION (all overridable from the command line)
# =========================================================
REGION = "eu"

# Keep placeholders in public repos - prefer env vars or --client-id / --client-secret
CLIENT_ID = "XYZ"
CLIENT_SECRET = "XYZ"

TOKEN_TIMEOUT_SECONDS = 30

# Retries for rate limits and brief outages (HTTP 429 / 502 / 503 / 504, dropped connections, timeouts)
RETRY_STATUSES = {429, 502, 503, 504}
MAX_RETRIES = 3
RETRY_BASE_SECONDS = 2
API_TIMEOUT_SECONDS = 60

# Optional MITRE filter ("" = everything)
NAME_CONTAINS = ""

# Export endpoint max 50 ruleIds per call
EXPORT_CHUNK_SIZE = 50

# A rule that has fired before but not within this many days is flagged as "Quiet"
STALE_DAYS = 90

__version__ = "2.0.0"

# Exabeam New-Scale API regions (api.<region>.exabeam.cloud)
KNOWN_REGIONS = ["us-west", "us-east", "eu", "uk", "ca", "au", "sg", "jp", "ch", "sa"]

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Never crash on characters the console (or a redirected log file) cannot display
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass
PLACEHOLDER = "XYZ"

# Rule health statuses
RS_ACTIVE = "Active"
RS_QUIET = "Quiet"
RS_NEVER = "NeverFired"
RS_UNKNOWN = "Unknown"
RS_DISABLED = "Disabled"
RS_AUTO_DISABLED = "AutoDisabled"

# Technique statuses (best rule status wins)
TS_VALIDATED = "validated"      # at least one mapped rule fired within STALE_DAYS
TS_QUIET = "quiet"              # mapped rules have fired before, but none recently
TS_UNVALIDATED = "unvalidated"  # mapped rules have never fired (or trigger data unavailable)
TS_NONE = "none"                # no enabled rule maps to it

TS_RANK = {TS_NONE: 0, TS_UNVALIDATED: 1, TS_QUIET: 2, TS_VALIDATED: 3}
RULE_TO_TECH_STATUS = {
    RS_ACTIVE: TS_VALIDATED,
    RS_QUIET: TS_QUIET,
    RS_NEVER: TS_UNVALIDATED,
    RS_UNKNOWN: TS_UNVALIDATED,
}
TS_LABEL = {
    TS_VALIDATED: "Validated",
    TS_QUIET: "Quiet",
    TS_UNVALIDATED: "Unvalidated",
    TS_NONE: "Not covered",
}

# Enterprise ATT&CK tactic order for the matrix. Unknown tactics are appended at the end.
TACTIC_ORDER = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Stealth"),  # named "Defense Evasion" before ATT&CK v19
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
    ("TA0112", "Defense Impairment"),  # added in ATT&CK v19 (absorbed Impair Defenses, T1562)
]


def info(msg: str) -> None:
    print(f"{ANSI_GREEN}[INFO]{ANSI_RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{ANSI_YELLOW}[WARN]{ANSI_RESET} {msg}")


def fail(msg: str, resp: requests.Response | None = None) -> None:
    print(f"[ERROR] {msg}")
    if resp is not None:
        print(f"Status: {resp.status_code}")
        print(resp.text[:2000])
    sys.exit(1)


def explain_http_error(what: str, resp: requests.Response) -> str:
    """A plain-English reason for a failed API call."""
    hints = {
        400: "the request was rejected - check --region and that the client ID and secret were pasted correctly",
        401: "authentication failed - check the client ID and secret, and that the key has not expired or been revoked",
        403: "the API key does not have permission for this - ask your Exabeam administrator to grant read access",
        404: "the endpoint was not found - check --region matches your tenant",
        429: "the API rate limit was hit - wait a few minutes and run again",
    }
    hint = hints.get(resp.status_code, "the Exabeam API returned an error" if resp.status_code >= 500 else "unexpected response")
    return f"{what} failed (HTTP {resp.status_code}): {hint}."


def explain_network_error(what: str, base_url: str, err: Exception) -> str:
    if isinstance(err, requests.exceptions.SSLError) and ("hostname mismatch" in str(err).lower() or "not valid for" in str(err).lower()):
        return (f"{what} failed: {base_url} is not a valid Exabeam API address. Check --region - it must be one of "
                f"{', '.join(KNOWN_REGIONS)}.")
    if isinstance(err, requests.exceptions.SSLError):
        return (f"{what} failed: the TLS certificate could not be verified ({err}). If your network inspects HTTPS traffic, "
                "set the REQUESTS_CA_BUNDLE environment variable to your organisation's CA certificate file.")
    if isinstance(err, requests.exceptions.Timeout):
        return f"{what} timed out contacting {base_url}. Check your connection and try again."
    if isinstance(err, requests.exceptions.ConnectionError):
        return (f"{what} failed: could not reach {base_url}. Check that --region is correct, that you are online, and - on "
                "a corporate network - that the HTTPS_PROXY environment variable is set if a proxy is required.")
    return f"{what} failed: {type(err).__name__}: {err}"


# =========================================================
# 2) ARGUMENTS
# =========================================================
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build an Exabeam MITRE ATT&CK coverage report.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--region", default=os.environ.get("EXABEAM_REGION", REGION),
                   help=f"Exabeam API region, e.g. eu, us-west, us-east (default: {REGION})")
    p.add_argument("--base-url", default=os.environ.get("EXABEAM_BASE_URL", ""),
                   help="Override the API base URL entirely (default: https://api.<region>.exabeam.cloud)")
    p.add_argument("--client-id", default=os.environ.get("EXABEAM_CLIENT_ID", CLIENT_ID))
    p.add_argument("--client-secret", default=os.environ.get("EXABEAM_CLIENT_SECRET", CLIENT_SECRET))
    p.add_argument("--out-dir", default=os.path.join(os.getcwd(), "output"),
                   help="Root folder for output; each run gets a timestamped subfolder (default: ./output)")
    p.add_argument("--stale-days", type=int, default=STALE_DAYS,
                   help=f"Rules that have fired before but not within this many days are 'Quiet' (default: {STALE_DAYS})")
    p.add_argument("--include-disabled", action="store_true",
                   help="Count disabled rules towards coverage (default: enabled rules only)")
    p.add_argument("--name-contains", default=NAME_CONTAINS,
                   help="Only include MITRE techniques whose name contains this text")
    p.add_argument("--priority-file", default="",
                   help="Optional CSV with columns techniqueId,priority[,source] used to rank gaps")
    p.add_argument("--compare", default="",
                   help="Snapshot.json (or run folder) to compare against (default: latest previous run for this region)")
    p.add_argument("--no-compare", action="store_true", help="Do not compare against a previous run")
    p.add_argument("--save-raw", action="store_true",
                   help="Save raw API responses into the run folder (useful for troubleshooting)")
    p.add_argument("--sector", default="",
                   help="Sector for the Word briefing's threat section, e.g. \"Healthcare\" (the HTML report lets each viewer choose)")
    p.add_argument("--no-word", action="store_true", help="Do not generate the Word executive briefing")
    p.add_argument("--no-surface", action="store_true", help="Skip the Attack Surface queries (data sources, collectors)")
    p.add_argument("--surface-days", type=int, default=7, help="Days of events used for the Attack Surface tab (default: 7)")
    p.add_argument("--no-surface-deep", action="store_true",
                   help="Do not run each rule's query against Search to find the data sources that feed it")
    p.add_argument("--surface-workers", type=int, default=4,
                   help="How many per-rule Attack Surface searches run at once (default: 4; 1 = one at a time)")
    p.add_argument("--surface-max-seconds", type=int, default=900,
                   help="Time budget for the per-rule Attack Surface queries (default: 900)")
    p.add_argument("--attack-data", choices=["auto", "refresh", "off"], default="auto",
                   help="MITRE ATT&CK platform/threat-group data for the report filters: 'auto' downloads it when the cache "
                        "is older than 30 days, 'refresh' always downloads, 'off' skips it (default: auto)")
    p.add_argument("--attack-cache", default=os.path.join(SCRIPT_DIR, ".cache", "attack_context.json"),
                   help="Where to cache the MITRE ATT&CK data (default: .cache/attack_context.json next to the script)")
    p.add_argument("--replay", default="",
                   help="Build the report from raw_*.json files in this folder instead of calling the API")
    return p.parse_args()


# =========================================================
# 3) API CLIENT
# =========================================================
class ExabeamApi:
    def __init__(self, base_url: str, client_id: str, client_secret: str):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = ""

    def _headers(self) -> dict:
        return {"accept": "application/json", "authorization": f"Bearer {self.token}"}

    def _send(self, method: str, path: str, **kwargs) -> requests.Response:
        """One HTTP call, retried with back-off on rate limits and brief outages. Raises the last network error."""
        import time
        for attempt in range(MAX_RETRIES + 1):
            wait = RETRY_BASE_SECONDS * 2 ** attempt
            try:
                resp = requests.request(method, f"{self.base_url}{path}", **kwargs)
            except requests.exceptions.SSLError:
                raise                                   # certificate problems will not fix themselves
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                if attempt == MAX_RETRIES:
                    raise
                time.sleep(wait)
                continue
            if resp.status_code in RETRY_STATUSES and attempt < MAX_RETRIES:
                retry_after = resp.headers.get("Retry-After", "")
                time.sleep(min(int(retry_after), 60) if retry_after.isdigit() else wait)
                continue
            return resp
        raise RuntimeError("unreachable")

    def _request(self, what: str, method: str, path: str, **kwargs) -> Any:
        """Call a core endpoint; exit with a plain-English message on any failure."""
        try:
            resp = self._send(method, path, **kwargs)
        except requests.RequestException as e:
            fail(explain_network_error(what, self.base_url, e))
        if not resp.ok:
            fail(explain_http_error(what, resp), resp)
        try:
            return resp.json()
        except ValueError:
            fail(f"{what} returned a response that was not JSON - check --region and --base-url.", resp)

    def authenticate(self) -> None:
        payload = self._request(
            "Signing in to Exabeam", "POST", "/auth/v1/token",
            data={"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.client_secret},
            headers={"accept": "application/json", "content-type": "application/x-www-form-urlencoded"},
            timeout=TOKEN_TIMEOUT_SECONDS,
        )
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not token:
            fail("Token response missing access_token")
        self.token = token

    def get_mitre_techniques(self, name_contains: str) -> dict:
        params = {"nameContains": name_contains} if name_contains else None
        return self._request("Reading the MITRE technique list", "GET", "/mitre/v1/techniques",
                             headers=self._headers(), params=params, timeout=API_TIMEOUT_SECONDS)

    def list_correlation_rules(self) -> Any:
        return self._request("Reading the correlation rules", "GET", "/correlation-rules/v2/rules",
                             headers=self._headers(), timeout=API_TIMEOUT_SECONDS)

    def search_events(self, body: dict) -> tuple[bool, Any]:
        """POST /search/v2/events. Returns (ok, json) or (False, error text) - never exits."""
        try:
            resp = self._send("POST", "/search/v2/events", timeout=API_TIMEOUT_SECONDS * 3,
                              headers={**self._headers(), "content-type": "application/json"}, json=body)
        except requests.RequestException as e:
            return False, f"{type(e).__name__}: {e}"
        if not resp.ok:
            return False, f"HTTP {resp.status_code}: {resp.text[:500]}"
        try:
            return True, resp.json()
        except ValueError:
            return False, f"Non-JSON response: {resp.text[:200]}"

    def get_cloud_collectors(self) -> tuple[bool, Any]:
        try:
            resp = self._send("GET", "/cloud-collectors/v1/configs", headers=self._headers(),
                              timeout=API_TIMEOUT_SECONDS)
        except requests.RequestException as e:
            return False, f"{type(e).__name__}: {e}"
        if not resp.ok:
            return False, f"HTTP {resp.status_code}: {resp.text[:500]}"
        try:
            return True, resp.json()
        except ValueError:
            return False, f"Non-JSON response: {resp.text[:200]}"

    def export_rule_definitions(self, rule_ids: list[str]) -> list[dict]:
        headers = {**self._headers(), "content-type": "application/json"}
        all_defs: list[dict] = []
        for i in range(0, len(rule_ids), EXPORT_CHUNK_SIZE):
            batch = rule_ids[i:i + EXPORT_CHUNK_SIZE]
            payload = self._request("Exporting correlation rule definitions", "POST", "/correlation-rules/v2/rules/export",
                                    headers=headers, json={"ruleIds": batch}, timeout=API_TIMEOUT_SECONDS)
            defs = payload.get("ruleDefinitions", []) if isinstance(payload, dict) else []
            if isinstance(defs, list):
                all_defs.extend(d for d in defs if isinstance(d, dict))
        return all_defs


# =========================================================
# 4) MITRE: FLATTEN
# =========================================================
def flatten_mitre(data: dict) -> list[dict]:
    """One row per technique; sub-techniques become their own rows."""
    rows: list[dict] = []
    if not isinstance(data, dict):
        return rows

    for tech_id, tech in data.items():
        if not isinstance(tech, dict):
            continue
        tactics = ",".join(tech.get("tactics", []) or [])
        rows.append({
            "techniqueId": tech_id,
            "name": tech.get("name", ""),
            "isSubtechnique": False,
            "parentTechniqueId": "",
            "tactics": tactics,
            "externalLink": tech.get("externalLink", ""),
        })
        for sub in tech.get("subTechniques", []) or []:
            if not isinstance(sub, dict):
                continue
            rows.append({
                "techniqueId": sub.get("id", ""),
                "name": sub.get("name", ""),
                "isSubtechnique": True,
                "parentTechniqueId": tech_id,
                "tactics": tactics,
                "externalLink": sub.get("externalLink", ""),
            })

    rows = [r for r in rows if r["techniqueId"]]
    rows.sort(key=lambda r: (r["parentTechniqueId"] or r["techniqueId"], r["isSubtechnique"], r["techniqueId"]))
    return rows


# =========================================================
# 5) CORRELATION RULES: NORMALISE + HEALTH
# =========================================================
def normalize_rules_list(payload: Any) -> list[dict]:
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        for k in ("rules", "items", "data", "results"):
            v = payload.get(k)
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]
    return []


def dedupe_rules(rules: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for r in rules:
        rid = get_rule_id(r) or id(r)
        if rid in seen:
            continue
        seen.add(rid)
        out.append(r)
    return out


def is_rule_enabled(rule: dict) -> bool:
    if isinstance(rule.get("enabled"), bool):
        return rule["enabled"]
    status = (rule.get("status") or rule.get("state") or rule.get("ruleStatus") or "").strip().lower()
    if "disabled" in status or "stopped" in status:
        return False
    return "enabled" in status


def get_rule_id(rule: dict | None) -> str:
    if not rule:
        return ""
    for k in ("id", "ruleId", "uuid"):
        v = rule.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def get_rule_name(rule: dict | None) -> str:
    if not rule:
        return ""
    for k in ("name", "ruleName", "title"):
        v = rule.get(k)
        if isinstance(v, str) and v:
            return v.strip()
    return ""


def parse_ts(value: Any) -> datetime | None:
    """Parse ISO-8601 strings or epoch seconds/milliseconds into an aware UTC datetime."""
    if value is None or value == "":
        return None
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().isdigit()):
            n = float(value)
            if n <= 0:
                return None
            if n > 1e11:  # milliseconds
                n /= 1000
            return datetime.fromtimestamp(n, tz=timezone.utc)
        s = str(value).strip().replace("Z", "+00:00")
        # Python 3.10 only accepts 3 or 6 fractional digits
        s = re.sub(r"\.(\d+)", lambda m: "." + (m.group(1) + "000000")[:6], s, count=1)
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def fmt_dt(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%SZ") if dt else ""


def build_rule_health(rule: dict, now: datetime, stale_days: int) -> dict:
    enabled = is_rule_enabled(rule)
    auto_disabled = rule.get("autoDisabled") is True
    last = parse_ts(rule.get("lastTriggeredAt"))
    created = parse_ts(rule.get("createdAt"))
    times = as_int(rule.get("timesTriggered"))
    suppressed = as_int(rule.get("timesSuppressed"))

    days_since_last = (now - last).days if last else None
    age_days = (now - created).days if created else None

    if auto_disabled:
        status = RS_AUTO_DISABLED
    elif not enabled:
        status = RS_DISABLED
    elif last:
        status = RS_ACTIVE if days_since_last <= stale_days else RS_QUIET
    elif times == 0:
        status = RS_NEVER
    else:
        # Fired but no timestamp, or the API did not return trigger fields at all
        status = RS_UNKNOWN

    avg_per_day = ""
    if times is not None and age_days is not None:
        avg_per_day = round(times / max(age_days, 1), 2)

    suppressed_pct = ""
    if times is not None and suppressed is not None and (times + suppressed) > 0:
        suppressed_pct = round(suppressed / (times + suppressed) * 100, 1)

    return {
        "ruleId": get_rule_id(rule),
        "ruleName": get_rule_name(rule),
        "enabled": enabled,
        "status": status,
        "testMode": rule.get("testMode") is True,
        "autoDisabled": auto_disabled,
        "severity": rule.get("severity", "") or "",
        "lastTriggeredAt": fmt_dt(last),
        "daysSinceLastTrigger": "" if days_since_last is None else days_since_last,
        "timesTriggered": "" if times is None else times,
        "timesSuppressed": "" if suppressed is None else suppressed,
        "suppressedPct": suppressed_pct,
        "createdAt": fmt_dt(created),
        "ruleAgeDays": "" if age_days is None else age_days,
        "avgTriggersPerDay": avg_per_day,
        "mitreMappings": 0,  # filled in once definitions are exported
        "author": rule.get("author", "") or "",
    }


# =========================================================
# 6) COVERAGE + GAPS
# =========================================================
def match_definitions(rules: list[dict], defs: list[dict]) -> tuple[list[tuple[dict, dict]], list[dict]]:
    """Pair each exported definition with its source rule (by id, falling back to name).
    Returns (pairs, rules_missing_from_export)."""
    by_id = {get_rule_id(r): r for r in rules if get_rule_id(r)}
    by_name: dict[str, list[dict]] = {}
    for r in rules:
        by_name.setdefault(get_rule_name(r), []).append(r)

    pairs = []
    matched_ids = set()
    for d in defs:
        src = by_id.get(get_rule_id(d))
        if src is None:
            candidates = [r for r in by_name.get(get_rule_name(d), []) if get_rule_id(r) not in matched_ids]
            src = candidates[0] if candidates else None
        if src is None:
            continue
        matched_ids.add(get_rule_id(src))
        pairs.append((src, d))

    missing = [r for r in rules if get_rule_id(r) not in matched_ids]
    return pairs, missing


def rule_query_products(defs: list[dict], fields: tuple[str, ...] = ("product", "vendor")) -> dict[str, list[str]]:
    """Values of the given fields named in each rule's sequence queries (product:"X" / product:("X","Y"))."""
    pattern = re.compile(r'\b(' + "|".join(fields) + r')\s*:\s*(\(([^)]*)\)|"([^"]*)")', re.I)
    out: dict[str, list[str]] = {}
    for d in defs:
        query = " ".join(s.get("query", "") for s in ((d.get("sequencesConfig") or {}).get("sequences") or [])
                         if isinstance(s, dict))
        found: list[str] = []
        for m in pattern.finditer(query):
            values = re.findall(r'"([^"]+)"', m.group(3)) if m.group(3) is not None else [m.group(4)]
            for v in values:
                if v and v.lower() not in {x.lower() for x in found}:
                    found.append(v)
        if found:
            out[get_rule_name(d)] = found
    return out


def build_coverage_and_rule_gaps(
    pairs: list[tuple[dict, dict]],
    missing: list[dict],
    health_by_id: dict[str, dict],
) -> tuple[list[dict], list[dict]]:
    coverage_rows: list[dict] = []
    rule_gap_rows: list[dict] = []

    for src, d in pairs:
        rule_id = get_rule_id(src)
        rule_name = get_rule_name(d) or get_rule_name(src)
        h = health_by_id.get(rule_id, {})

        mitre_list = d.get("mitre", [])
        if not mitre_list:
            rule_gap_rows.append({"issueType": "NoMitreTag", "ruleId": rule_id, "ruleName": rule_name,
                                  "notes": "Enabled rule has no mitre[] mappings"})
            continue
        if not isinstance(mitre_list, list):
            rule_gap_rows.append({"issueType": "InvalidMitreFormat", "ruleId": rule_id, "ruleName": rule_name,
                                  "notes": "mitre field was not a list"})
            continue

        for m in mitre_list:
            if not isinstance(m, dict):
                continue
            coverage_rows.append({
                "ruleId": rule_id,
                "ruleName": rule_name,
                "enabled": str(is_rule_enabled(src)),
                "tacticKey": m.get("tacticKey", "") or "",
                "tactic": m.get("tactic", "") or "",
                "techniqueKey": (m.get("techniqueKey", "") or "").strip(),
                "technique": m.get("technique", "") or "",
                "ruleStatus": h.get("status", ""),
                "lastTriggeredAt": h.get("lastTriggeredAt", ""),
                "timesTriggered": h.get("timesTriggered", ""),
                "testMode": str(h.get("testMode", "")),
            })
        if rule_id in health_by_id:
            health_by_id[rule_id]["mitreMappings"] = sum(1 for m in mitre_list if isinstance(m, dict))

    for r in sorted(missing, key=get_rule_name):
        rule_gap_rows.append({"issueType": "ExportMissing", "ruleId": get_rule_id(r), "ruleName": get_rule_name(r),
                              "notes": "Enabled rule was requested for export but definition was not returned"})

    return coverage_rows, rule_gap_rows


def build_technique_status(all_mitre: list[dict], coverage: list[dict]) -> dict[str, dict]:
    """Per technique: direct status, rolled-up status (including sub-techniques) and mapped rules."""
    rules_by_tech: dict[str, dict[str, dict]] = {}
    for c in coverage:
        tid = c["techniqueKey"]
        if not tid:
            continue
        rules_by_tech.setdefault(tid, {})[c["ruleId"] or c["ruleName"]] = {
            "ruleId": c["ruleId"],
            "ruleName": c["ruleName"],
            "status": c["ruleStatus"],
            "lastTriggeredAt": c["lastTriggeredAt"],
        }

    out: dict[str, dict] = {}
    for r in all_mitre:
        tid = r["techniqueId"]
        rules = list(rules_by_tech.get(tid, {}).values())
        status = TS_NONE
        for rr in rules:
            s = RULE_TO_TECH_STATUS.get(rr["status"], TS_UNVALIDATED)
            if TS_RANK[s] > TS_RANK[status]:
                status = s
        out[tid] = {"status": status, "rolled": status, "viaSub": False, "rules": rules}

    # Roll sub-technique coverage up to parents
    for r in all_mitre:
        if not r["isSubtechnique"]:
            continue
        parent = out.get(r["parentTechniqueId"])
        sub = out[r["techniqueId"]]
        if parent and TS_RANK[sub["status"]] > TS_RANK[parent["rolled"]]:
            parent["rolled"] = sub["status"]
            parent["viaSub"] = parent["status"] == TS_NONE
    return out


def build_technique_gaps(all_mitre: list[dict], tech_status: dict[str, dict], priorities: dict[str, dict]) -> list[dict]:
    gaps: list[dict] = []
    for r in all_mitre:
        t = tech_status[r["techniqueId"]]
        if t["status"] != TS_NONE:
            continue
        p = priorities.get(r["techniqueId"], {})
        gaps.append({
            "issueType": "NotCovered",
            "techniqueId": r["techniqueId"],
            "name": r["name"],
            "isSubtechnique": str(r["isSubtechnique"]),
            "parentTechniqueId": r["parentTechniqueId"],
            "tactics": r["tactics"],
            "externalLink": r["externalLink"],
            "coveredViaSubtechnique": str(t["viaSub"]) if not r["isSubtechnique"] else "",
            "priority": p.get("priority", ""),
            "ruleId": "",
            "ruleName": "",
            "notes": "",
        })
    return gaps


def load_priorities(path: str) -> dict[str, dict]:
    if not path:
        return {}
    if not os.path.exists(path):
        fail(f"Priority file not found: {path}")
    out = {}
    for row in read_csv_dicts(path):
        tid = (row.get("techniqueId") or "").strip()
        if tid:
            out[tid] = {"priority": (row.get("priority") or "").strip(), "source": (row.get("source") or "").strip()}
    return out


def priority_sort_key(p: str) -> tuple:
    try:
        return (0, float(p), "")
    except ValueError:
        return (1, 0.0, p.lower())


# =========================================================
# 7) SNAPSHOTS + RUN-TO-RUN COMPARISON
# =========================================================
def find_previous_snapshot(out_root: str, current_dir: str, region: str) -> str:
    if not os.path.isdir(out_root):
        return ""
    for name in sorted(os.listdir(out_root), reverse=True):
        d = os.path.join(out_root, name)
        snap = os.path.join(d, "snapshot.json")
        if os.path.abspath(d) == os.path.abspath(current_dir) or not os.path.isfile(snap):
            continue
        try:
            with open(snap, encoding="utf-8") as f:
                if json.load(f).get("region") == region:
                    return snap
        except (OSError, json.JSONDecodeError):
            continue
    return ""


def surface_snapshot(surface: dict | None) -> dict | None:
    """The part of the Attack Surface kept between runs, to spot sources and collectors that change."""
    if not surface or not surface.get("eventsAvailable"):
        return None
    return {
        "windowDays": surface.get("windowDays"),
        "products": {p["product"]: {"status": p["status"], "events": p["events"], "rules": p["ruleCount"]}
                     for p in surface["products"]},
        "collectors": {c["name"]: c["health"] for c in surface.get("collectors", [])},
    }


def compare_surface(prev: dict | None, cur: dict | None) -> list[dict]:
    """Data-source and collector changes between two runs (only when both collected Attack Surface data)."""
    if not prev or not cur:
        return []
    out = []
    pp, cp = prev.get("products", {}), cur.get("products", {})
    for name in sorted(set(pp) | set(cp), key=str.lower):
        a, b = pp.get(name), cp.get(name)
        a_ev, b_ev = (a or {}).get("events", 0), (b or {}).get("events", 0)
        if a_ev > 0 and b_ev == 0:
            rules = (b or a or {}).get("rules", 0)
            out.append({"change": "Source stopped sending", "item": name, "from": f"{a_ev:,} events",
                        "to": "no events" + (f" - {rules} rule{'s' if rules != 1 else ''} depend on it" if rules else "")})
        elif a_ev == 0 and b_ev > 0:
            out.append({"change": "New data source", "item": name, "from": "not sending", "to": f"{b_ev:,} events"})
        elif a and b and a["status"] != b["status"]:
            if b["status"] == "Detecting":
                kind = "Source now detecting"
            elif a["status"] == "Detecting":
                kind = "Source stopped detecting"
            else:
                kind = "Source status changed"
            out.append({"change": kind, "item": name, "from": a["status"], "to": b["status"]})
    pc, cc = prev.get("collectors", {}), cur.get("collectors", {})
    for name in sorted(set(pc) & set(cc), key=str.lower):
        if pc[name] == "Healthy" and cc[name] != "Healthy":
            out.append({"change": "Collector unhealthy", "item": name, "from": "Healthy", "to": cc[name]})
        elif pc[name] != "Healthy" and cc[name] == "Healthy":
            out.append({"change": "Collector recovered", "item": name, "from": pc[name], "to": "Healthy"})
    return out


def compare_snapshots(prev: dict, cur: dict) -> list[dict]:
    changes: list[dict] = []

    prev_t, cur_t = prev.get("techniques", {}), cur.get("techniques", {})
    for tid in sorted(set(prev_t) | set(cur_t)):
        a = prev_t.get(tid, {}).get("status", TS_NONE)
        b = cur_t.get(tid, {}).get("status", TS_NONE)
        if a == b:
            continue
        if a == TS_NONE:
            kind = "Coverage gained"
        elif b == TS_NONE:
            kind = "Coverage lost"
        elif TS_RANK[b] > TS_RANK[a]:
            kind = "Technique improved"
        else:
            kind = "Technique degraded"
        name = cur_t.get(tid, {}).get("name") or prev_t.get(tid, {}).get("name", "")
        changes.append({"change": kind, "item": f"{tid} {name}".strip(),
                        "from": TS_LABEL.get(a, a), "to": TS_LABEL.get(b, b)})

    prev_r, cur_r = prev.get("rules", {}), cur.get("rules", {})
    for rid in sorted(set(prev_r) | set(cur_r), key=lambda x: (cur_r.get(x) or prev_r.get(x) or {}).get("name", "")):
        a, b = prev_r.get(rid), cur_r.get(rid)
        name = (b or a or {}).get("name", rid)
        if a is None:
            if b["enabled"]:
                changes.append({"change": "Rule added", "item": name, "from": "", "to": b["status"]})
            continue
        if b is None:
            changes.append({"change": "Rule removed", "item": name, "from": a["status"], "to": ""})
            continue
        if a["status"] == b["status"]:
            continue
        if b["status"] == RS_AUTO_DISABLED:
            kind = "Rule auto-disabled"
        elif a["status"] == RS_ACTIVE and b["status"] == RS_QUIET:
            kind = "Rule stopped firing"
        elif b["status"] == RS_DISABLED:
            kind = "Rule disabled"
        elif a["status"] in (RS_DISABLED, RS_AUTO_DISABLED):
            kind = "Rule enabled"
        elif b["status"] == RS_ACTIVE:
            kind = "Rule started firing"
        else:
            kind = "Rule status changed"
        changes.append({"change": kind, "item": name, "from": a["status"], "to": b["status"]})

    changes.extend(compare_surface(prev.get("surface"), cur.get("surface")))

    order = ["Rule auto-disabled", "Source stopped sending", "Rule stopped firing", "Collector unhealthy",
             "Source stopped detecting", "Coverage lost", "Technique degraded", "Rule disabled", "Rule removed",
             "Coverage gained", "Technique improved", "Source now detecting", "New data source", "Collector recovered",
             "Rule added", "Rule enabled", "Rule started firing", "Source status changed", "Rule status changed"]
    changes.sort(key=lambda c: order.index(c["change"]))
    return changes


# =========================================================
# 8) OUTPUT HELPERS (CSV, NAVIGATOR)
# =========================================================
def write_csv(path: str, rows: list[dict], fieldnames: list[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def read_csv_dicts(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8-sig") as f:
        return [dict(row) for row in csv.DictReader(f)]


def write_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


NAV_COLOURS = {TS_VALIDATED: "#31a717", TS_QUIET: "#1f72d0", TS_UNVALIDATED: "#9b1fc0"}  # Outcomes Navigator bands


def build_navigator_layer(all_mitre: list[dict], tech_status: dict[str, dict], region: str, generated: str) -> dict:
    techniques = []
    for r in all_mitre:
        t = tech_status[r["techniqueId"]]
        if t["status"] == TS_NONE:
            continue
        names = sorted({x["ruleName"] for x in t["rules"]})
        comment = f"{TS_LABEL[t['status']]} - {len(names)} rule(s): " + "; ".join(names[:20])
        if len(names) > 20:
            comment += f"; +{len(names) - 20} more"
        techniques.append({
            "techniqueID": r["techniqueId"],
            "score": len(names),
            "color": NAV_COLOURS[t["status"]],
            "comment": comment,
            "enabled": True,
            "showSubtechniques": False,
        })
    return {
        "name": f"Exabeam coverage ({region})",
        "versions": {"attack": "17", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Exabeam correlation rule coverage, region {region}, generated {generated}",
        "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "legendItems": [
            {"label": "Validated (rule fired recently)", "color": NAV_COLOURS[TS_VALIDATED]},
            {"label": "Quiet (fired before, not recently)", "color": NAV_COLOURS[TS_QUIET]},
            {"label": "Unvalidated (never fired)", "color": NAV_COLOURS[TS_UNVALIDATED]},
        ],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


# =========================================================
# 9) HTML REPORT
# =========================================================
def esc(x: Any) -> str:
    return (str(x) if x is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def to_html_table(rows: list[dict], table_id: str, max_rows: int = 5000, cols: list[str] | None = None) -> str:
    if not rows:
        return '<div class="footer-note">No rows.</div>'
    rows2 = rows[:max_rows]
    cols = cols or list(rows2[0].keys())
    thead = "".join(f"<th>{esc(c)}</th>" for c in cols)
    tbody = "".join("<tr>" + "".join(f"<td>{esc(row.get(c, ''))}</td>" for c in cols) + "</tr>" for row in rows2)
    note = f'<div class="footer-note">Showing first {max_rows} of {len(rows)} rows - see the CSV for the full list.</div>' \
        if len(rows) > max_rows else ""
    return f'<div class="table-wrap"><table class="data-table" id="{table_id}"><thead><tr>{thead}</tr></thead><tbody>{tbody}</tbody></table></div>{note}'


def filterable_panel(title: str, sub: str, rows: list[dict], table_id: str, placeholder: str,
                     cols: list[str] | None = None) -> str:
    return f"""
      <div class="panel">
        <h2>{esc(title)}</h2>
        <p class="sub">{sub}</p>
        <div class="controls">
          <input type="text" placeholder="{esc(placeholder)}" oninput="filterTable('{table_id}', this.value)">
          <span class="pill">Rows: {len(rows)}</span>
        </div>
        {to_html_table(rows, table_id, cols=cols)}
      </div>"""


def card(label: str, value: Any, hint: str, tone: str = "", delta: str = "", meter: float | None = None) -> str:
    delta_html = f'<div class="delta">{esc(delta)}</div>' if delta else ""
    meter_html = f'<div class="meter"><i style="width:{max(0.0, min(meter, 100.0)):.1f}%"></i></div>' \
        if meter is not None else ""
    return f"""
      <div class="card">
        <div class="label">{esc(label)}</div>
        <div class="value {tone}">{esc(value)}</div>{delta_html}{meter_html}
        <div class="hint">{hint}</div>
      </div>"""


def delta_text(cur: float, prev_kpis: dict | None, key: str, suffix: str = "") -> str:
    if not prev_kpis or key not in prev_kpis:
        return ""
    d = cur - prev_kpis[key]
    if abs(d) < 0.05:
        return "No change vs last run"
    arrow = "▲" if d > 0 else "▼"
    num = f"{abs(d):.1f}" if isinstance(d, float) and not float(d).is_integer() else f"{abs(int(d))}"
    return f"{arrow} {num}{suffix} vs last run"


def tactic_key(raw: str) -> str:
    return re.sub(r"[^a-z0-9]", "", raw.lower())


# =========================================================
# 9a) ATT&CK CONTEXT: PLATFORMS + THREAT GROUPS (from MITRE's STIX data)
# =========================================================
ATTACK_INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
ATTACK_CACHE_MAX_AGE_DAYS = 30
ATTACK_CACHE_SCHEMA = 2  # bump when build_attack_context() output changes, to force a refresh
ATTACK_DOWNLOAD_TIMEOUT_SECONDS = 180

# MITRE has no structured "targeted sector" field, so sectors are matched from keywords
# in each group's description. The report lists the matching groups so this can be checked.
SECTOR_PATTERNS = {
    "Healthcare": r"\b(health ?care|hospitals?|medical|pharmaceuticals?|health sector|health organi[sz]ations?|social care)\b",
    "Financial services": r"\b(financial|finance|banks?|banking|insurance|cryptocurrenc(y|ies)|fintech)\b",
    "Government": r"\b(government|governmental|diplomatic|ministr(y|ies)|embass(y|ies)|public sector)\b",
    "Energy & utilities": r"\b(energy|oil and gas|petroleum|utilit(y|ies)|electric|power grid|nuclear)\b",
    "Manufacturing & industrial": r"\b(manufacturing|industrial|automotive|engineering|chemicals?)\b",
    "Technology & IT services": r"\b(technology|software|IT services?|managed service providers?|MSPs?|cloud service providers?)\b",
    "Telecommunications": r"\b(telecommunications?|telecoms?|telcos?)\b",
    "Defense & aerospace": r"\b(defen[cs]e (industry|industrial|contractors?|sector)|military|aerospace)\b",
    "Education & research": r"\b(education(al)?|universit(y|ies)|academi[ac]|think tanks?|research institut\w*)\b",
    "Retail & hospitality": r"\b(retail|hospitality|restaurants?|point[- ]of[- ]sale|e-?commerce|casinos?)\b",
    "Media & entertainment": r"\b(media organi[sz]ations?|news|journalists?|broadcast\w*|entertainment)\b",
    "Legal & professional services": r"\b(legal|law firms?|consulting|accounting)\b",
    "Transportation & logistics": r"\b(transportation|aviation|airlines?|maritime|logistics|shipping)\b",
    "Non-profit & NGOs": r"\b(non-?profits?|NGOs?|non-governmental|human rights)\b",
}


def _stix_external_id(obj: dict) -> str:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id") or ""
    return ""


def _stix_url(obj: dict) -> str:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url") or ""
    return ""


def build_attack_context(bundle: dict, version: str) -> dict:
    """Reduce the (large) ATT&CK STIX bundle to what the report needs."""
    objs = bundle.get("objects", [])
    live = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")  # noqa: E731

    techniques = {o["id"]: o for o in objs if o.get("type") == "attack-pattern" and live(o)}
    groups = {o["id"]: o for o in objs if o.get("type") == "intrusion-set" and live(o)}

    platforms = {}
    for o in techniques.values():
        tid = _stix_external_id(o)
        if tid:
            platforms[tid] = sorted(o.get("x_mitre_platforms", []) or [])

    uses: dict[str, set] = {}
    for o in objs:
        if (o.get("type") == "relationship" and o.get("relationship_type") == "uses" and live(o)
                and o.get("source_ref") in groups and o.get("target_ref") in techniques):
            tid = _stix_external_id(techniques[o["target_ref"]])
            if tid:
                uses.setdefault(o["source_ref"], set()).add(tid)

    group_rows = []
    for gid, g in groups.items():
        if not uses.get(gid):
            continue
        desc = g.get("description", "") or ""
        group_rows.append({
            "id": _stix_external_id(g),
            "name": g.get("name", ""),
            "url": _stix_url(g),
            "aliases": [a for a in (g.get("aliases") or []) if a != g.get("name")][:10],
            "description": clean_description(desc)[:900],
            "sectors": [s for s, pat in SECTOR_PATTERNS.items() if re.search(pat, desc, re.I)],
            "techniques": sorted(uses[gid]),
        })
    group_rows.sort(key=lambda g: g["name"].lower())

    return {
        "schema": ATTACK_CACHE_SCHEMA,
        "version": version,
        "fetchedAt": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
        "platforms": platforms,
        "groups": group_rows,
    }


def download_attack_context() -> dict:
    index = requests.get(ATTACK_INDEX_URL, timeout=API_TIMEOUT_SECONDS)
    index.raise_for_status()
    collection = next(c for c in index.json()["collections"] if c.get("name") == "Enterprise ATT&CK")
    latest = collection["versions"][0]
    info(f"Downloading MITRE ATT&CK Enterprise v{latest['version']} (platforms and threat groups, ~55 MB)...")
    resp = requests.get(latest["url"], timeout=ATTACK_DOWNLOAD_TIMEOUT_SECONDS)
    resp.raise_for_status()
    return build_attack_context(resp.json(), latest["version"])


def load_attack_context(cache_path: str, mode: str) -> dict | None:
    """mode: 'auto' (use cache, refresh when older than 30 days), 'refresh' (always download), 'off'."""
    if mode == "off":
        return None
    cached = None
    if os.path.exists(cache_path):
        try:
            with open(cache_path, encoding="utf-8") as f:
                cached = json.load(f)
        except (OSError, json.JSONDecodeError):
            cached = None
    if cached and mode == "auto":
        fetched = parse_ts(cached.get("fetchedAt"))
        if (cached.get("schema") == ATTACK_CACHE_SCHEMA and fetched
                and (datetime.now(timezone.utc) - fetched).days < ATTACK_CACHE_MAX_AGE_DAYS):
            return cached
    try:
        ctx = download_attack_context()
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        write_json(cache_path, ctx)
        return ctx
    except Exception as e:  # network/proxy issues must not stop the report
        if cached:
            warn(f"Could not refresh MITRE ATT&CK data ({e}); using cached v{cached.get('version')}")
            return cached
        warn(f"Could not download MITRE ATT&CK data ({e}); platform and sector filters will be unavailable")
        return None


def attack_lookups(attack: dict | None) -> tuple[dict[str, list[str]], dict[str, list[int]]]:
    """technique id -> platforms, technique id -> indexes into attack['groups'] of groups using it."""
    if not attack:
        return {}, {}
    groups_by_tech: dict[str, list[int]] = {}
    for i, g in enumerate(attack["groups"]):
        for tid in g["techniques"]:
            groups_by_tech.setdefault(tid, []).append(i)
    return attack["platforms"], groups_by_tech


# =========================================================
# 9b) ATTACK SURFACE: DATA SOURCES, CLOUD COLLECTORS, RULE DEPENDENCIES
# =========================================================
# Products Exabeam generates itself - kept out of the data-source list
INTERNAL_PRODUCTS = {"correlation rule", "audit log", "exabeam", "null", ""}
SURFACE_EVENTS_LIMIT = 5000
SURFACE_RULE_QUERY_LIMIT = 500


def _ci(row: dict, *names: str) -> Any:
    """Case-insensitive lookup of the first matching key in a result row."""
    lowered = {str(k).lower(): v for k, v in row.items()}
    for n in names:
        if n.lower() in lowered:
            return lowered[n.lower()]
    return None


def _row_count(row: dict) -> int:
    v = _ci(row, "events", "count", "event_count", "count(*)", "cnt")
    if v is None:  # fall back to the only numeric value in the row
        nums = [x for x in row.values() if isinstance(x, (int, float)) and not isinstance(x, bool)]
        v = nums[0] if len(nums) == 1 else 0
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _product_name(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value).strip()


def _friendly_api_error(err: Any) -> str:
    text = str(err)
    if "HTTP 403" in text:
        return text[:300] + " - the API key does not have permission for this; ask your Exabeam administrator to grant read access."
    if "HTTP 401" in text:
        return text[:300] + " - authentication was rejected for this API."
    return text[:500]


def grouped_search(api: "ExabeamApi", select: list[str], group: list[str], where: str, window: dict,
                   limit: int, state: dict) -> tuple[bool, list[dict], list[str]]:
    """Aggregate search (COUNT(*) AS events grouped by fields). Tries the SQL-style filter first, then the
    fields/groupBy body, and remembers whichever works so later queries use it straight away."""
    sql = f"SELECT {', '.join(select)}, COUNT(*) AS events" + (f" WHERE ({where})" if where else "") + f" GROUP-BY {', '.join(group)}"
    styles = [
        ("SQL filter", {"filter": sql, "fields": ["*"], "limit": limit, **window}),
        ("fields+groupBy", {"filter": where or "", "fields": select + ["count(*) as events"], "groupBy": group,
                            "limit": limit, **window}),
    ]
    if state.get("style"):
        styles.sort(key=lambda s: s[0] != state["style"])
    errors = []
    for label, body in styles:
        ok, data = api.search_events(body)
        if ok:
            state["style"] = label
            rows = data.get("rows", []) if isinstance(data, dict) else []
            rows.sort(key=_row_count, reverse=True)
            return True, rows, errors
        errors.append(f"{label}: {_friendly_api_error(data)}")
    return False, [], errors


def collect_attack_surface(api: "ExabeamApi", defs: list[dict], days: int, deep: bool, max_seconds: int,
                           workers: int = 4, trigger_days: int = STALE_DAYS) -> dict:
    """Run the Attack Surface queries. Only aggregated counts are kept (no raw log content), plus any API errors."""
    import time
    now = datetime.now(timezone.utc)
    window = {"startTime": (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "endTime": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
    trig_window = {"startTime": (now - timedelta(days=trigger_days)).strftime("%Y-%m-%dT%H:%M:%SZ"), "endTime": window["endTime"]}
    out: dict = {"schema": 2, "collectedAt": now.strftime("%Y-%m-%d %H:%M:%SZ"), "windowDays": days, "triggerDays": trigger_days,
                 "events": None, "triggers": None, "cloudCollectors": None, "ruleQueries": {}, "errors": []}
    state: dict = {}

    # 1) Event volume per data source - product is the key; vendor, category and platform are context
    ok, rows, errors = grouped_search(api, ["vendor", "product", "product_category", "platform"],
                                      ["vendor", "product", "product_category", "platform"], "", window,
                                      SURFACE_EVENTS_LIMIT, state)
    if ok:
        out["events"] = {"method": state["style"], "rows": rows}
        info(f"Attack surface: {len(rows)} data source rows over {days} days ({state['style']})")
    else:
        out["errors"].extend({"step": "data sources", "error": e} for e in errors)
        warn("Attack surface: could not query event volume per product - check the API key has Search access")

    # 2) Correlation rule triggers in the last 30 days, counted per rule and source product
    ok, rows, errors = grouped_search(api, ["rule", "src_product"], ["rule", "src_product"],
                                      'product:"Correlation Rule"', trig_window, SURFACE_EVENTS_LIMIT, state)
    if ok:
        out["triggers"] = {"grouped": True, "rows": rows}
        info(f"Attack surface: {sum(_row_count(r) for r in rows)} correlation rule triggers in {trigger_days} days")
    else:
        out["errors"].extend({"step": "rule triggers", "error": e} for e in errors)

    # 3) Cloud collectors
    ok, data = api.get_cloud_collectors()
    if ok:
        out["cloudCollectors"] = data
    else:
        out["errors"].append({"step": "cloud collectors", "error": _friendly_api_error(data)})

    # 4) Each rule's own query, grouped by product: which sources feed it (even product-agnostic rules)
    if deep and out["events"] is not None:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        jobs = []
        for d in defs:
            name = get_rule_name(d)
            queries = [s.get("query", "") for s in ((d.get("sequencesConfig") or {}).get("sequences") or [])
                       if isinstance(s, dict) and s.get("query")]
            if name and queries:
                jobs.append((name, queries))

        def check(job: tuple[str, list[str]]) -> tuple[str, dict]:
            name, queries = job
            per_rule = {"products": {}, "errors": []}
            for q in queries:
                ok, rows, errors = grouped_search(api, ["product"], ["product"], q, window, SURFACE_RULE_QUERY_LIMIT, state)
                if ok:
                    for row in rows:
                        p = _product_name(_ci(row, "product"))
                        per_rule["products"][p] = per_rule["products"].get(p, 0) + _row_count(row)
                else:
                    per_rule["errors"].extend(errors)
            return name, per_rule

        started, done, idx, failed = time.monotonic(), 0, 0, 0
        confirmed = False
        # Run rules one at a time until one succeeds (this also settles which request style works); give up
        # if the first five all fail, rather than repeating the same error for every rule
        while idx < len(jobs) and not confirmed and failed < 5:
            name, per_rule = check(jobs[idx])
            out["ruleQueries"][name] = per_rule
            idx, done = idx + 1, done + 1
            if per_rule["errors"]:
                failed += 1
            else:
                confirmed = True
        if not confirmed and jobs:
            warn("Attack surface: the first rule queries all failed - skipping the rest (see Collection notes)")
            last = out["ruleQueries"][jobs[idx - 1][0]]["errors"]
            out["errors"].append({"step": "rule queries", "error": last[-1] if last else ""})
        elif idx < len(jobs):
            truncated = False
            with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
                futures = [pool.submit(check, j) for j in jobs[idx:]]
                for fut in as_completed(futures):
                    if fut.cancelled():
                        continue
                    name, per_rule = fut.result()
                    out["ruleQueries"][name] = per_rule
                    done += 1
                    if done % 25 == 0:
                        info(f"Attack surface: checked {done} of {len(jobs)} rule queries...")
                    if not truncated and time.monotonic() - started > max_seconds:
                        truncated = True
                        for f in futures:
                            f.cancel()
                        warn(f"Attack surface: stopped rule queries after {max_seconds}s ({done} of {len(jobs)} rules checked)"
                             " - raise --surface-max-seconds")
            out["ruleQueriesTruncated"] = truncated
        out["ruleQueries"] = dict(sorted(out["ruleQueries"].items()))
        out["ruleQueryMethod"] = state.get("style", "")
        info(f"Attack surface: checked the queries of {done} rules against {days} days of data")
    return out


def _detect_key(rows: list[dict], candidates: set[str], exclude: set[str] = frozenset()) -> str:
    """Find the field whose values most often match a known set of names (e.g. rule names)."""
    scores: dict[str, int] = {}
    lowered = {c.lower() for c in candidates}
    for row in rows[:500]:
        for k, v in row.items():
            if k in exclude:
                continue
            vals = v if isinstance(v, list) else [v]
            if any(isinstance(x, str) and x.strip().lower() in lowered for x in vals):
                scores[k] = scores.get(k, 0) + 1
    return max(scores, key=scores.get) if scores else ""


def build_attack_surface(raw: dict | None, health_all: list[dict], rule_products: dict[str, list[str]],
                         rule_vendors: dict[str, list[str]],
                         rule_techniques: dict[str, list[str]], tech_names: dict[str, str]) -> dict | None:
    """Merge data-source volume, rule dependencies and rule health into one row per product."""
    if not raw:
        return None
    health_by_name = {h["ruleName"]: h for h in health_all if h["enabled"]}

    products: dict[str, dict] = {}

    def product(name: str, vendor: str = "") -> dict:
        key = name.lower()
        if key not in products:
            products[key] = {"product": name, "vendor": vendor, "events": 0, "namedBy": set(), "fedRules": set(),
                             "triggers": 0, "triggerRules": set(), "vendorRules": set(), "collectors": [],
                             "categories": set(), "platforms": set()}
        if vendor and not products[key]["vendor"]:
            products[key]["vendor"] = vendor
        return products[key]

    def present(value: Any) -> str:
        v = _product_name(value)
        return "" if v.lower() in ("", "null", "none") else v

    # Events from Exabeam itself (correlation rules, audit log...) are not data sources
    internal = set(INTERNAL_PRODUCTS)
    for row in (raw.get("events") or {}).get("rows", []):
        name = present(_ci(row, "product"))
        vendor = present(_ci(row, "vendor"))
        if not name or name.lower() in internal or vendor.lower() == "exabeam":
            internal.add(name.lower())
            continue
        p = product(name, vendor)
        p["events"] += _row_count(row)
        for field, bucket in (("product_category", "categories"), ("platform", "platforms")):
            v = present(_ci(row, field))
            if v:
                p[bucket].add(v)

    for rule, names in rule_products.items():
        if rule in health_by_name:
            for n in names:
                if n.lower() not in internal:
                    product(n)["namedBy"].add(rule)
    # vendor:"X" in a rule query *may* apply to any product from that vendor. It is listed, but does not change a
    # product's status - the rule query results and triggers show whether the rule really uses that product.
    # If no product from the vendor sends data at all, the rule cannot fire, which is flagged.
    for rule, vendors in rule_vendors.items():
        if rule not in health_by_name:
            continue
        for v in vendors:
            if v.lower() == "exabeam":
                continue
            matches = [p for p in products.values() if (p["vendor"] or "").lower() == v.lower()]
            for p in matches:
                p["vendorRules"].add(rule)
            if not matches:
                product(f"{v} (any product)", v)["namedBy"].add(rule)

    starved = []
    for rule, res in (raw.get("ruleQueries") or {}).items():
        if rule not in health_by_name:
            continue
        fed = {p: n for p, n in res.get("products", {}).items() if p.lower() not in internal and n > 0}
        for p in fed:
            product(p)["fedRules"].add(rule)
        if not fed and not res.get("errors"):
            starved.append(rule)

    # Rule triggers: grouped counts (rule, src_product) from new runs, or raw trigger events from older files
    trig = raw.get("triggers") or {}
    trigger_rows = trig.get("rows", [])
    trigger_by_rule: dict[str, int] = {}
    attributed = 0
    if trig.get("grouped"):
        rule_key, source_key = "rule", "src_product"
        for row in trigger_rows:
            n = _row_count(row)
            r = _product_name(_ci(row, "rule"))
            trigger_by_rule[r] = trigger_by_rule.get(r, 0) + n
            src = present(_ci(row, "src_product"))
            if src and src.lower() in products:
                products[src.lower()]["triggers"] += n
                products[src.lower()]["triggerRules"].add(r)
                attributed += n
    else:
        rule_key = _detect_key(trigger_rows, set(health_by_name))
        source_key = _detect_key(trigger_rows, {p["product"] for p in products.values()}, exclude={"product", rule_key})
        for row in trigger_rows:
            r = _product_name(row.get(rule_key)) if rule_key else ""
            if r:
                trigger_by_rule[r] = trigger_by_rule.get(r, 0) + 1
            src = present(row.get(source_key)) if source_key else ""
            if src and src.lower() in products:
                products[src.lower()]["triggers"] += 1
                products[src.lower()]["triggerRules"].add(r)
                attributed += 1
    total_triggers = sum(trigger_by_rule.values())

    cc = raw.get("cloudCollectors")
    collectors = cc.get("items", cc.get("configs", [])) if isinstance(cc, dict) else (cc or [])
    now = datetime.now(timezone.utc)
    collector_rows = []
    for c in collectors if isinstance(collectors, list) else []:
        if not isinstance(c, dict):
            continue
        last = parse_ts(c.get("lastLogReceived"))
        hours = round((now - last).total_seconds() / 3600, 1) if last else None
        state = "Error" if str(c.get("status", "")).lower() == "error" else (
            "Silent" if hours is None or hours > 24 else "Healthy")
        row = {"name": c.get("name", ""), "vendor": c.get("vendor", ""), "type": c.get("type", ""),
               "status": c.get("status", ""), "lastLogReceived": fmt_dt(last), "hoursSinceLastLog": hours,
               "site": (c.get("siteDetails") or {}).get("sitename", ""), "health": state}
        collector_rows.append(row)
        vendor = (row["vendor"] or "").lower()
        for p in products.values():   # link collectors to products of the same vendor
            if vendor and (vendor in (p["vendor"] or "").lower() or vendor in p["product"].lower()):
                p["collectors"].append(row["name"])

    rows = []
    for p in products.values():
        rules = sorted(p["namedBy"] | p["fedRules"] | {r for r in p["triggerRules"] if r in health_by_name})
        statuses = [health_by_name[r]["status"] for r in rules if r in health_by_name]
        active = [r for r in rules if health_by_name.get(r, {}).get("status") == RS_ACTIVE]
        techniques = sorted({t for r in rules for t in rule_techniques.get(r, [])})
        validated = sorted({t for r in active for t in rule_techniques.get(r, [])})
        if p["events"] == 0:
            status = "No data"           # rules name this product but it sent nothing in the window
        elif active or p["triggers"]:
            status = "Detecting"
        elif rules:
            status = "Monitored, silent"
        else:
            status = "No detections"
        rows.append({
            "product": p["product"], "vendor": p["vendor"], "events": p["events"], "status": status,
            "categories": sorted(p["categories"]), "platforms": sorted(p["platforms"], key=str.lower),
            "vendorRules": sorted(p["vendorRules"] - set(rules)),
            "rules": rules, "ruleCount": len(rules), "namedRules": len(p["namedBy"]), "fedRules": len(p["fedRules"]),
            "active": len(active), "quiet": statuses.count(RS_QUIET), "never": statuses.count(RS_NEVER),
            "triggers": p["triggers"], "techniques": techniques, "validatedTechniques": validated,
            "collectors": sorted(set(p["collectors"])),
        })
    order = {"No data": 0, "No detections": 1, "Monitored, silent": 2, "Detecting": 3}
    rows.sort(key=lambda r: (order[r["status"]], -r["events"], r["product"].lower()))

    rule_info = {r: {"status": h["status"], "last": h["lastTriggeredAt"], "triggers": trigger_by_rule.get(r, 0),
                     "techniques": [{"id": t, "name": tech_names.get(t, "")} for t in rule_techniques.get(r, [])]}
                 for r, h in health_by_name.items()}
    return {
        "collectedAt": raw.get("collectedAt", ""), "windowDays": raw.get("windowDays"),
        "triggerDays": raw.get("triggerDays", 30),
        "eventsMethod": (raw.get("events") or {}).get("method", ""),
        "eventsAvailable": raw.get("events") is not None,
        # only rule queries that actually ran count as checked
        "deepChecked": sum(1 for r in (raw.get("ruleQueries") or {}).values() if not r.get("errors")),
        "deepTruncated": bool(raw.get("ruleQueriesTruncated")),
        "triggerEvents": total_triggers, "triggerAttributed": attributed,
        "triggerRuleField": rule_key, "triggerSourceField": source_key,
        "ruleQueryMethod": raw.get("ruleQueryMethod", ""),
        "products": rows, "collectors": collector_rows,
        "starvedRules": sorted(starved),
        "rules": rule_info,
        "errors": raw.get("errors", []),
    }


# Score bands mirror the Exabeam Outcomes Navigator legend (<=0, 1-49, 50-74, 75-100)
SCORE_BANDS = {TS_VALIDATED: (75, 100), TS_QUIET: (50, 74), TS_UNVALIDATED: (20, 49)}
DESCRIPTION_MAX_CHARS = 1500


def tech_score(status: str, rule_statuses: list[str]) -> int:
    """0-100 score: the band comes from the technique status, depth within the band from how many
    rules share that status (each extra rule adds 5 points)."""
    if status not in SCORE_BANDS:
        return 0
    lo, hi = SCORE_BANDS[status]
    n = sum(1 for s in rule_statuses if RULE_TO_TECH_STATUS.get(s, TS_UNVALIDATED) == status)
    return min(hi, lo + (max(n, 1) - 1) * 5)


def clean_description(text: str) -> str:
    """Strip ATT&CK citation markers and markdown links from a technique description."""
    s = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    s = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", s)
    s = re.sub(r"<code>|</code>", "", s)
    s = re.sub(r"\.(?=[A-Z])", ". ", s)          # paragraphs are joined without a space
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > DESCRIPTION_MAX_CHARS:
        s = s[:DESCRIPTION_MAX_CHARS].rsplit(" ", 1)[0] + "..."
    return s


def mitre_descriptions(data: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    if not isinstance(data, dict):
        return out
    for tech_id, tech in data.items():
        if not isinstance(tech, dict):
            continue
        out[tech_id] = clean_description(tech.get("description", ""))
        for sub in tech.get("subTechniques", []) or []:
            if isinstance(sub, dict) and sub.get("id"):
                out[sub["id"]] = clean_description(sub.get("description", ""))
    return out


def build_matrix_data(all_mitre: list[dict], tech_status: dict[str, dict], descriptions: dict[str, str],
                      attack: dict | None = None) -> list[dict]:
    """Columns of parent techniques per tactic, each with its sub-techniques, for the matrix.
    plat = ATT&CK platforms, grp = indexes into attack['groups'] of threat groups that use the technique."""
    alias: dict[str, tuple[str, str]] = {}
    for tid, name in TACTIC_ORDER:
        for a in (tid, name, name.replace(" ", "-")):
            alias[tactic_key(a)] = (tid, name)
    alias[tactic_key("Defense Evasion")] = ("TA0005", "Stealth")
    platforms, groups_by_tech = attack_lookups(attack)

    def rule_view(rules: list[dict]) -> list[dict]:
        return [{"name": x["ruleName"], "status": x["status"], "last": x["lastTriggeredAt"]} for x in rules]

    subs_by_parent: dict[str, list[dict]] = {}
    for r in all_mitre:
        if r["isSubtechnique"]:
            t = tech_status[r["techniqueId"]]
            name = r["name"].split(": ", 1)[1] if ": " in r["name"] else r["name"]
            subs_by_parent.setdefault(r["parentTechniqueId"], []).append({
                "id": r["techniqueId"], "name": name, "fullName": r["name"], "link": r["externalLink"],
                "desc": descriptions.get(r["techniqueId"], ""),
                "status": t["status"], "score": tech_score(t["status"], [x["status"] for x in t["rules"]]),
                "rules": rule_view(t["rules"]),
                "plat": platforms.get(r["techniqueId"], []),
                "grp": groups_by_tech.get(r["techniqueId"], []),
            })

    columns: dict[str, dict] = {tid: {"id": tid, "name": name, "techs": []} for tid, name in TACTIC_ORDER}

    for r in all_mitre:
        if r["isSubtechnique"]:
            continue
        t = tech_status[r["techniqueId"]]
        subs = sorted(subs_by_parent.get(r["techniqueId"], []), key=lambda s: s["id"])
        direct = {x["ruleId"] or x["ruleName"]: x["status"] for x in t["rules"]}
        rolled = dict(direct)
        for s in subs:
            for x in tech_status[s["id"]]["rules"]:
                rolled[x["ruleId"] or x["ruleName"]] = x["status"]
        # A group that uses any sub-technique also uses the parent technique
        grp = set(groups_by_tech.get(r["techniqueId"], []))
        for s in subs:
            grp.update(s["grp"])
        tech = {
            "id": r["techniqueId"], "name": r["name"], "link": r["externalLink"],
            "desc": descriptions.get(r["techniqueId"], ""),
            "status": t["status"], "rolled": t["rolled"], "viaSub": t["viaSub"],
            "score": tech_score(t["status"], list(direct.values())),
            "rolledScore": tech_score(t["rolled"], list(rolled.values())),
            "rules": rule_view(t["rules"]),
            "subs": subs,
            "plat": platforms.get(r["techniqueId"], []),
            "grp": sorted(grp),
        }
        for raw in [x.strip() for x in (r["tactics"] or "").split(",") if x.strip()] or ["Unmapped"]:
            tid, name = alias.get(tactic_key(raw), (raw, raw.replace("-", " ").title()))
            columns.setdefault(tid, {"id": tid, "name": name, "techs": []})["techs"].append(tech)

    out = [c for c in columns.values() if c["techs"]]
    for c in out:
        # Like the Outcomes Navigator: covered techniques first (highest score first), then the rest A-Z
        c["techs"].sort(key=lambda t: (-t["rolledScore"], t["name"].lower()))
    return out


MATRIX_CSV_COLUMNS = [
    "tacticId", "tactic", "techniqueId", "techniqueName", "isSubtechnique", "parentTechniqueId",
    "status", "score", "statusInclSubtechniques", "scoreInclSubtechniques",
    "ruleCount", "activeRules", "quietRules", "neverFiredRules", "lastFired", "rules",
    "platforms", "threatGroupCount", "threatGroups", "mitreUrl",
]

# Display order for ATT&CK platforms in the report filters
PLATFORM_ORDER = ["Windows", "macOS", "Linux", "Identity Provider", "Office Suite", "SaaS", "IaaS",
                  "Containers", "Network Devices", "ESXi", "PRE"]


def build_matrix_csv_rows(matrix: list[dict], attack: dict | None = None) -> list[dict]:
    """One row per technique per tactic, in ATT&CK matrix order (tactic, then technique, then its sub-techniques)."""
    groups = attack["groups"] if attack else []
    rows: list[dict] = []

    def row(col: dict, t: dict, parent: str, rolled_status: str, rolled_score: int) -> dict:
        statuses = [x["status"] for x in t["rules"]]
        last = max((x["last"] for x in t["rules"] if x["last"]), default="")
        return {
            "tacticId": col["id"], "tactic": col["name"],
            "techniqueId": t["id"], "techniqueName": t.get("fullName", t["name"]),
            "isSubtechnique": bool(parent), "parentTechniqueId": parent,
            "status": TS_LABEL[t["status"]], "score": t["score"],
            "statusInclSubtechniques": TS_LABEL[rolled_status], "scoreInclSubtechniques": rolled_score,
            "ruleCount": len(t["rules"]),
            "activeRules": statuses.count(RS_ACTIVE), "quietRules": statuses.count(RS_QUIET),
            "neverFiredRules": statuses.count(RS_NEVER) + statuses.count(RS_UNKNOWN),
            "lastFired": last, "rules": "; ".join(sorted(x["name"] for x in t["rules"])),
            "platforms": "; ".join(t.get("plat", [])),
            "threatGroupCount": len(t.get("grp", [])),
            "threatGroups": "; ".join(sorted(groups[i]["name"] for i in t.get("grp", []))),
            "mitreUrl": t["link"],
        }

    for col in matrix:
        for t in sorted(col["techs"], key=lambda x: x["id"]):
            rows.append(row(col, t, "", t["rolled"], t["rolledScore"]))
            for s in t["subs"]:
                rows.append(row(col, s, t["id"], s["status"], s["score"]))
    return rows


def attack_for_html(attack: dict | None) -> dict | None:
    """The slice of the ATT&CK context the report page needs (groups without their technique lists)."""
    if not attack:
        return None
    present = {p for plats in attack["platforms"].values() for p in plats}
    sector_counts = {s: sum(1 for g in attack["groups"] if s in g["sectors"]) for s in SECTOR_PATTERNS}
    return {
        "version": attack["version"],
        "platforms": [p for p in PLATFORM_ORDER if p in present] + sorted(present - set(PLATFORM_ORDER)),
        "sectors": [{"name": s, "groups": n} for s, n in sector_counts.items() if n],
        "groups": [{"id": g["id"], "name": g["name"], "url": g["url"], "sectors": g["sectors"],
                    "aliases": g.get("aliases", []), "desc": g.get("description", ""), "techniques": g["techniques"]}
                   for g in attack["groups"]],
    }


HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Exabeam MITRE Coverage Report</title>
<script>try { if (localStorage.getItem('exabeamMitreReport.theme') === 'light') document.documentElement.setAttribute('data-theme', 'light'); } catch (e) {}</script>
<style>
  :root {
    /* Palette sampled from the Exabeam New-Scale / Outcomes Navigator UI */
    --bg: #05060f; --panel: #040b1b; --panel-2: #0b0e17; --line: #1d2130;
    --tile: #13151d; --tile-scored: #3c434f; --tile-border: #42444a; --tile-selected: #49586a; --tick: #757a83;
    --pop: #22232c; --pop-border: #4e4f56; --pop-tick: #3a3c46;
    --text: #ffffff; --text-2: #e6ebf2; --muted: #a3aab5; --muted-2: #8a8d96;
    --grad-a: #2aa90f; --grad-b: #0573da;      /* green -> blue widget border */
    --brand-green: #2aa90f; --accent: #0371e0; --accent-hover: #1a82ec; --track: #013870; --link: #4fa3f7;
    --band-zero: #a3aab5; --band-low: #9b1fc0; --band-mid: #1f72d0; --band-high: #31a717;
    --bad: #f0506e; --warn: #f0b429;
    --tab-hover: #12161f; --hair: #30323e; --knob: #2a2f3c; --hidico: #1b5ea5;
    --tile-high-border: #636972; --tile-mid: #2f343f; --tile-mid-border: #575c66; --tile-low: #22232c; --tile-low-border: #4e4f56;
    --hair-soft: rgba(255,255,255,0.08); --hover-soft: rgba(255,255,255,0.06);
    --fg-validated: #6fd35a; --fg-quiet: #6fb0f5; --fg-unvalidated: #cf86ea; --hot: #ff8fa3;
    --value-blue: #3d8fe8; --value-purple: #b45ad6;
    --overlay: rgba(2,3,8,0.7); --shadow: rgba(0,0,0,0.55); --modal-table: rgba(0,0,0,0.15); --modal-head: #1a1b23;
    --export-border: #043c77;
    --radius: 2px;
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    --sans: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  /* Light theme - chosen with the toggle in the header and remembered per viewer */
  :root[data-theme="light"] {
    --bg: #f3f4f6; --panel: #ffffff; --panel-2: #eceef2; --line: #d9dde3;
    --tile: #f7f8fa; --tile-scored: #dce3ec; --tile-border: #c4cad3; --tile-selected: #bcd2ee; --tick: #9aa1ac;
    --pop: #ffffff; --pop-border: #c4cad3; --pop-tick: #e1e4e9;
    --text: #0f1216; --text-2: #2b2f36; --muted: #5b6472; --muted-2: #6b7280;
    --brand-green: #1f8a0e; --accent: #0b6bcb; --accent-hover: #0959a8; --track: #dbe5f2; --link: #0b6bcb;
    --band-zero: #9aa1ac; --band-low: #8a2fb0; --band-mid: #1f66c1; --band-high: #2e8b23;
    --bad: #c0392b; --warn: #b45309;
    --tab-hover: #e4e7ec; --hair: #dde1e6; --knob: #c4cad3; --hidico: #0b6bcb;
    --tile-high-border: #a9b4c4; --tile-mid: #e6ebf2; --tile-mid-border: #b9c3d1; --tile-low: #eef0f4; --tile-low-border: #cbd1da;
    --hair-soft: rgba(0,0,0,0.08); --hover-soft: rgba(0,0,0,0.05);
    --fg-validated: #2a7a1f; --fg-quiet: #1f5fae; --fg-unvalidated: #7a2a9e; --hot: #c0392b;
    --value-blue: #1f66c1; --value-purple: #8a2fb0;
    --overlay: rgba(20,24,32,0.45); --shadow: rgba(20,24,32,0.18); --modal-table: transparent; --modal-head: #eceef2;
    --export-border: #9cc0e8;
  }
  * { box-sizing: border-box; }
  body { margin:0; font-family: var(--sans); color: var(--text-2); background: var(--bg); font-size: 13px; }
  .wrap { padding: 18px 24px 60px; }
  svg.ic { width: 16px; height: 16px; flex: none; }

  /* Gradient border used on widgets */
  .card, .panel {
    border: 1px solid transparent; border-radius: var(--radius);
    background: linear-gradient(var(--panel), var(--panel)) padding-box,
                linear-gradient(to bottom right, var(--grad-a), var(--grad-b)) border-box;
  }

  /* Header */
  .topbar { display:flex; align-items:center; justify-content:space-between; gap: 14px; margin-bottom: 18px; }
  .brand { display:flex; align-items:center; gap: 14px; }
  .logo { width: 34px; height: 34px; display:flex; align-items:center; justify-content:center; overflow:hidden; }
  .logo img { width:100%; height:100%; object-fit:contain; display:block; }
  .logo .fallback { color: var(--muted); font-size: 11px; font-family: var(--mono); }
  .title h1 { margin:0; font-size: 18px; font-weight: 400; color: var(--brand-green); text-transform: uppercase; letter-spacing: 0.01em; }
  .title .sub { margin-top:4px; font-size: 12px; color: var(--muted); }
  .meta { text-align:right; color: var(--muted); font-size: 12px; }
  .topright { display:flex; align-items:center; gap: 18px; }
  .themebtn { display:inline-flex; align-items:center; gap: 7px; background: var(--panel-2); color: var(--text-2);
              border: 1px solid var(--line); border-radius: var(--radius); padding: 7px 11px; font: 500 12px var(--sans); cursor: pointer; }
  .themebtn:hover { border-color: var(--link); color: var(--text); }
  .themebtn svg { width: 15px; height: 15px; }

  /* Tabs (Outcomes Navigator style) */
  .tabs { display:flex; gap: 2px; margin-bottom: 18px; flex-wrap: wrap; }
  .tab { background: var(--panel-2); color: var(--text-2); border: 0; border-top: 2px solid transparent;
         padding: 16px 22px; font: 500 13px var(--sans); cursor: pointer; }
  .tab:hover { color: var(--text); background: var(--tab-hover); }
  .tab.active { background: var(--bg); color: var(--text); border-top-color: var(--accent);
                box-shadow: inset 1px 0 var(--line), inset -1px 0 var(--line); }
  .tab .count { margin-left: 6px; font-size: 11px; color: var(--muted); }
  .tabpane { display:none; }
  .tabpane.active { display:block; }

  /* Buttons */
  .btn { display:inline-flex; align-items:center; gap: 8px; font: 500 12px var(--sans); padding: 8px 14px;
         border-radius: var(--radius); cursor: pointer; text-decoration: none; border: 1px solid transparent; }
  .btn-primary { background: var(--accent); color: #fff; }
  .btn-primary:hover { background: var(--accent-hover); }
  .btn-outline { background: var(--panel-2); color: var(--link); border-color: var(--line); }
  .btn-outline:hover { border-color: var(--link); }
  .btn-ghost { background: transparent; color: var(--link); padding: 8px 10px; }
  .btn-ghost:hover { background: rgba(79,163,247,0.1); }

  /* KPI cards */
  .grid { display:grid; grid-template-columns: repeat(12, 1fr); gap: 14px; margin-bottom: 18px; }
  .card { grid-column: span 3; padding: 16px 18px; }
  .card .label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 10px; }
  .card .value { font-size: 28px; font-weight: 600; color: var(--text); }
  .card .delta { margin-top: 4px; font-size: 12px; color: var(--muted); }
  .card .hint { margin-top: 10px; font-size: 12px; color: var(--muted); line-height: 1.4; }
  .card .value.score { display:flex; align-items:center; gap: 10px; }
  .card .value.score svg.shield { width: 30px; height: 30px; color: var(--band-low); }
  .helplink { color: var(--link); text-decoration: none; }
  .helplink:hover { text-decoration: underline; }
  table.factors { width: 100%; border-collapse: collapse; margin-top: 14px; border: 1px solid var(--hair); font-size: 13px; }
  table.factors th, table.factors td { padding: 14px 16px; border-bottom: 1px solid var(--hair); text-align: left; }
  table.factors th { color: var(--muted); font-weight: 500; }
  table.factors td:last-child, table.factors th:last-child { text-align: right; white-space: nowrap; }
  table.factors tr.total td { font-weight: 600; color: var(--text); border-top: 1px solid var(--pop-border); }
  .meter { margin-top: 10px; height: 3px; background: var(--track); }
  .meter > i { display:block; height: 100%; background: var(--accent); }
  .value.good { color: var(--band-high); } .value.blue { color: var(--value-blue); }
  .value.purple { color: var(--value-purple); } .value.bad { color: var(--bad); } .value.warn { color: var(--warn); }

  /* Panels */
  .panel { grid-column: span 12; padding: 16px 18px 8px; min-width: 0; }
  .panel.half { grid-column: span 6; }
  .panel h2 { margin: 0 0 6px; font-size: 15px; font-weight: 500; color: var(--text); }
  .panel .sub { margin: 0 0 10px; color: var(--muted); font-size: 12px; }
  .controls { display:flex; flex-wrap:wrap; gap: 10px; margin: 8px 0 12px; align-items:center; }
  .controls input[type=text] { flex: 1; min-width: 240px; background: var(--panel-2); color: var(--text);
    border: 1px solid var(--line); border-radius: var(--radius); padding: 9px 12px; outline: none; font-size: 12px; }
  .controls input[type=text]:focus { border-color: var(--accent); }
  .pill { border: 1px solid var(--line); color: var(--muted); border-radius: var(--radius); padding: 8px 10px;
          font-size: 12px; background: var(--panel-2); }

  .table-wrap { overflow-x: auto; max-height: 560px; overflow-y: auto; margin: 10px 0 14px; }
  table.data-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  table.data-table thead th { text-align:left; background: var(--panel-2); color: var(--muted); font-weight: 500;
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em;
    border-bottom: 1px solid var(--line); padding: 9px 10px; position: sticky; top: 0; z-index: 2; white-space: nowrap; }
  table.data-table tbody td { padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
  table.data-table tbody tr:hover { background: rgba(3,113,224,0.08); }
  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-thumb { background: var(--knob); }
  ::-webkit-scrollbar-track { background: transparent; }

  /* Coverage & score legend + toolbar */
  .legendbar { display:flex; flex-wrap:wrap; align-items:center; gap: 18px; margin: 0 0 14px; font-size: 13px; color: var(--muted); }
  .legendbar strong { color: var(--text); font-weight: 600; text-transform: uppercase; font-size: 13px; }
  .legendbar .item { display:flex; align-items:center; gap: 8px; }
  .lg-box { width: 22px; height: 16px; display:inline-block; border-radius: var(--radius); }
  .lg-box.nocov { border: 1px dashed var(--tile-border); }
  .lg-box.plain { background: var(--tile); border: 1px solid var(--tile-border); }
  .lg-box.scored { background: var(--tile-scored); border: 1px solid var(--tile-scored); }
  .lg-line { width: 10px; height: 4px; display:inline-block; }
  .legendbar .sep { width: 1px; height: 18px; background: var(--line); }
  .toolbar { display:flex; justify-content:space-between; align-items:center; gap: 14px; margin: 0 0 14px; flex-wrap: wrap; }
  .toolbar .group { display:flex; align-items:center; gap: 18px; flex-wrap: wrap; }
  .switch { display:flex; align-items:center; gap: 10px; color: var(--text-2); font-size: 12px; cursor: pointer; user-select: none; }
  .switch input { display:none; }
  .switch .knob { width: 30px; height: 16px; border-radius: 999px; background: var(--knob); position: relative; transition: background .15s; }
  .switch .knob::after { content:""; position:absolute; top: 2px; left: 2px; width: 12px; height: 12px; border-radius: 50%;
                         background: #fff; transition: left .15s; }
  .switch input:checked + .knob { background: var(--accent); }
  .switch input:checked + .knob::after { left: 16px; }

  /* ATT&CK matrix (Outcomes Navigator style) */
  .matrix { display:flex; gap: 10px; overflow-x:auto; padding-bottom: 12px; }
  .col { min-width: 180px; flex: 1 0 180px; }
  .col h3 { margin: 0 0 10px; font-size: 13px; font-weight: 600; color: var(--text); }
  .col h3 small { display:block; color: var(--muted); font-weight: 400; font-size: 12px; margin-top: 3px; }
  .tile { display:flex; margin-bottom: 6px; border-radius: var(--radius); cursor: pointer;
          background: var(--tile); border: 1px solid var(--tile-border); }
  .tile.scored, .tile.band-high { background: var(--tile-scored); border-color: var(--tile-high-border); }
  /* Outcomes Navigator shades tiles by score band: lower bands sit closer to the page background */
  .tile.band-mid { background: var(--tile-mid); border-color: var(--tile-mid-border); }
  .tile.band-low { background: var(--tile-low); border-color: var(--tile-low-border); }
  .tile.hiddentile { opacity: 0.45; }
  .tile.hiddentile .body { padding-right: 34px; }
  .tile .hidico { position: absolute; top: 9px; right: 9px; color: var(--hidico); }
  .tile .hidico svg { width: 18px; height: 18px; }
  .tile.dim { opacity: 0.18; }
  .tile.nocov { background: transparent; border: 1px dashed var(--tile-border); }
  .tile:hover { border-color: var(--link); border-style: solid; }
  .tile.sel { background: var(--tile-selected); border: 1px solid var(--tile-selected); }
  .tile .body { flex: 1; min-width: 0; padding: 12px 14px 8px 16px; }
  .tile.nocov .body { padding-bottom: 12px; }
  .tile .tname { font-size: 13px; font-weight: 600; color: var(--text); line-height: 1.4; }
  .tile.nocov .tname { font-weight: 400; color: var(--muted); }
  /* Sub-technique expander - the side handle used by the MITRE ATT&CK Navigator */
  .tile .expander { width: 18px; flex: none; display:flex; align-items:center; justify-content:center;
                    border-left: 1px solid var(--hair-soft); color: var(--muted); font-size: 10px;
                    writing-mode: vertical-rl; letter-spacing: 1px; }
  .tile .expander:hover { color: var(--text); background: var(--hover-soft); }
  .subs { margin: -2px 0 8px 10px; padding-left: 8px; border-left: 2px solid var(--tile-border); }
  .subs .tile { margin-bottom: 4px; }
  .subs .tile .body { padding: 8px 12px 6px 12px; }
  .subs .tile.nocov .body { padding-bottom: 8px; }
  .subs .tile .tname { font-size: 12px; font-weight: 500; }
  .subs .tile .tid { font-family: var(--mono); font-size: 10.5px; color: var(--muted-2); margin-bottom: 2px; }
  .bar { position: relative; height: 10px; margin-top: 10px;
    background:
      linear-gradient(var(--tick), var(--tick)) 0% 100% / 1px 8px no-repeat,
      linear-gradient(var(--tick), var(--tick)) 25% 100% / 1px 8px no-repeat,
      linear-gradient(var(--tick), var(--tick)) 50% 100% / 1px 8px no-repeat,
      linear-gradient(var(--tick), var(--tick)) 75% 100% / 1px 8px no-repeat,
      linear-gradient(var(--tick), var(--tick)) 100% 100% / 1px 8px no-repeat; }
  .subs .bar { margin-top: 6px; }
  .bar b { position:absolute; left: 0; bottom: 2px; height: 3px; }
  .b-low  { background: linear-gradient(to right, rgba(155,31,192,0), var(--band-low)); }
  .b-mid  { background: linear-gradient(to right, rgba(31,114,208,0), var(--band-mid)); }
  .b-high { background: linear-gradient(to right, rgba(49,167,23,0), var(--band-high)); }
  /* Large score bar used in the popover */
  .bar.big { height: 40px; margin: 14px 0 16px;
    background:
      linear-gradient(var(--pop-tick), var(--pop-tick)) 0% 0 / 1px 100% no-repeat,
      linear-gradient(var(--pop-tick), var(--pop-tick)) 25% 0 / 1px 100% no-repeat,
      linear-gradient(var(--pop-tick), var(--pop-tick)) 50% 0 / 1px 100% no-repeat,
      linear-gradient(var(--pop-tick), var(--pop-tick)) 75% 0 / 1px 100% no-repeat,
      linear-gradient(var(--pop-tick), var(--pop-tick)) 100% 0 / 1px 100% no-repeat; }
  .bar.big b { bottom: 9px; height: 22px; }

  /* Status tags */
  .tag { display:inline-block; font-size: 11px; padding: 2px 7px; border-radius: var(--radius); font-weight: 500; white-space: nowrap; }
  .s-validated { background: rgba(49,167,23,0.18); color: var(--fg-validated); }
  .s-quiet { background: rgba(31,114,208,0.22); color: var(--fg-quiet); }
  .s-unvalidated { background: rgba(155,31,192,0.22); color: var(--fg-unvalidated); }
  .s-none { background: rgba(163,170,181,0.12); color: var(--muted); }

  /* Technique popover (Outcomes Navigator style) */
  .pop { position: absolute; z-index: 30; width: 380px; display: none; padding: 20px 22px 18px;
         background: var(--pop); border: 1px solid var(--pop-border); border-radius: var(--radius);
         box-shadow: 0 16px 40px var(--shadow); }
  .pop.open { display: block; }
  .pop .ptitle { font-size: 15px; font-weight: 600; color: var(--text); padding-right: 24px; line-height: 1.35; }
  .pop .pid { margin-top: 4px; font-size: 12px; color: var(--muted-2); }
  .pop .pdesc { font-size: 12px; color: var(--text-2); line-height: 1.5; display: -webkit-box; -webkit-line-clamp: 4;
                -webkit-box-orient: vertical; overflow: hidden; margin-bottom: 14px; }
  .pop .plabel, .modal h4 { font-size: 12px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.03em; color: var(--muted); margin: 0 0 8px; }
  .pop .pstats { display:flex; flex-wrap: wrap; gap: 8px 18px; font-size: 12px; color: var(--text); font-weight: 600; }
  .pop .pstats span { display:flex; align-items:center; gap: 6px; }
  .pop .pstats span.muted { color: var(--muted); font-weight: 400; }
  .pop .pactions { display:flex; justify-content:flex-end; align-items:center; gap: 10px; margin-top: 18px; }
  .xbtn { position:absolute; top: 12px; right: 12px; background: none; border: 0; color: var(--muted); font-size: 20px;
          line-height: 1; cursor: pointer; padding: 4px; }
  .xbtn:hover { color: var(--text); }

  /* Technique details modal */
  .overlay { position: fixed; inset: 0; z-index: 40; background: var(--overlay); display: none;
             align-items: flex-start; justify-content: center; padding: 6vh 16px; overflow-y: auto; }
  .overlay.open { display: flex; }
  .modal { position: relative; width: min(820px, 100%); background: var(--pop); border: 1px solid var(--pop-border);
           border-radius: var(--radius); padding: 24px 26px; box-shadow: 0 24px 60px var(--shadow); }
  .modal .ptitle { font-size: 19px; font-weight: 600; color: var(--text); padding-right: 30px; }
  .modal .pid { margin-top: 6px; font-size: 12px; color: var(--muted-2); }
  .modal .row { display:flex; align-items:center; gap: 14px; flex-wrap: wrap; margin-top: 14px; }
  .modal .row .num { font-size: 28px; font-weight: 600; color: var(--text); }
  .modal .row .bar.big { flex: 1; min-width: 200px; margin: 0; }
  .modal p.desc { font-size: 13px; line-height: 1.6; color: var(--text-2); margin: 16px 0 6px; }
  .modal h4 { margin-top: 22px; }
  .modal table.data-table { background: var(--modal-table); }
  .modal table.data-table thead th { background: var(--modal-head); }
  .modal table.data-table tbody td { border-bottom-color: var(--hair); }
  .modal .note { color: var(--muted); font-size: 12px; }
  .modal a { color: var(--link); }

  /* Tailoring: filter bar, tactic codes, sector threat badges, setup dialog */
  .filterbar { display:flex; flex-wrap:wrap; align-items:center; gap: 10px; margin: 0 0 16px; }
  .chip { display:inline-flex; align-items:center; gap: 6px; padding: 7px 10px; font-size: 12px; border: 1px solid var(--line);
          background: var(--panel-2); color: var(--text-2); border-radius: var(--radius); }
  .chip.muted { color: var(--muted); }
  .chip.sector { border-color: rgba(240,80,110,0.5); color: var(--hot); }
  .chip.right { margin-left: auto; }
  .tcode { font-family: var(--mono); font-size: 11px; color: var(--muted-2); margin-bottom: 3px; letter-spacing: 0.02em; }
  .tile .body { position: relative; }
  .tile.has-threat .tname { padding-right: 34px; }
  .threat { position: absolute; top: 7px; right: 7px; font-size: 10.5px; font-weight: 600; color: var(--hot); white-space: nowrap;
            background: rgba(240,80,110,0.16); padding: 1px 5px; border-radius: var(--radius); }
  .threat.static { position: static; display: inline-block; }
  .pstats span.hot { color: var(--hot); }
  .pplat { display:flex; align-items:center; gap: 6px; font-size: 11.5px; color: var(--muted); margin: -4px 0 12px; }
  .choice-grid { display:grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 8px; }
  .choice { text-align: left; background: var(--tile); border: 1px solid var(--tile-border); color: var(--text-2); padding: 10px 12px;
            border-radius: var(--radius); cursor: pointer; font: 500 12.5px var(--sans); }
  .choice small { display:block; color: var(--muted); font-weight: 400; margin-top: 3px; font-size: 11.5px; }
  .choice:hover { border-color: var(--link); }
  .choice.on { background: rgba(3,113,224,0.2); border-color: var(--accent); color: var(--text); }
  .check { display:flex; align-items:center; gap: 9px; padding: 9px 12px; background: var(--tile); border: 1px solid var(--tile-border);
           border-radius: var(--radius); cursor: pointer; font-size: 12.5px; color: var(--text-2); }
  .check input { accent-color: var(--accent); width: 15px; height: 15px; margin: 0; }
  .presets { display:flex; flex-wrap: wrap; gap: 8px; margin: 0 0 10px; }
  .modal .actions { display:flex; justify-content:flex-end; gap: 10px; margin-top: 22px; }
  .btn-secondary { background: transparent; color: var(--text-2); border-color: var(--pop-border); }
  .btn-secondary:hover { border-color: var(--text-2); }
  .grouplist { display:flex; flex-wrap: wrap; gap: 6px; }
  .grouplist a { font-size: 12px; padding: 3px 8px; border: 1px solid var(--hair); border-radius: var(--radius); text-decoration: none; color: var(--text-2); }
  .grouplist a:hover { border-color: var(--link); }
  .grouplist a.hit { border-color: rgba(240,80,110,0.6); color: var(--hot); }
  #sectorPanel tr[data-open], tr[data-tech], tr[data-group], tr[data-product] { cursor: pointer; }
  .panel.third { grid-column: span 4; }
  .card.span2 { grid-column: span 2; }
  @media (max-width: 1100px) { .card.span2 { grid-column: span 4; } }
  @media (max-width: 560px) { .card.span2 { grid-column: span 12; } }
  .card.clickable { cursor: pointer; }
  .card.clickable:hover { box-shadow: inset 0 0 0 1px var(--link); }
  .card.selected { box-shadow: inset 0 0 0 2px var(--accent); }
  .fchip { background: var(--panel-2); color: var(--text-2); border: 1px solid var(--line); border-radius: var(--radius);
           padding: 6px 10px; font: 500 12px var(--sans); cursor: pointer; }
  .fchip:hover { border-color: var(--link); }
  .fchip.on { background: var(--accent); border-color: var(--accent); color: #fff; }
  .fchip.on .note { color: rgba(255,255,255,0.8); }
  tr[data-rule] { cursor: pointer; }
  @media (max-width: 1100px) { .panel.third { grid-column: span 12; } }
  .flist { display:flex; flex-direction: column; gap: 6px; max-height: 720px; overflow-y: auto; margin-bottom: 10px; }
  .fitem { background: var(--tile); border: 1px solid var(--tile-border); border-radius: var(--radius); padding: 10px 12px; cursor: pointer; }
  .fitem:hover { border-color: var(--link); }
  .fhead { display:flex; justify-content: space-between; align-items: center; margin-bottom: 3px; }
  .fname { font-weight: 600; color: var(--text); margin-bottom: 3px; }
  .mono { font-family: var(--mono); font-size: 11.5px; color: var(--muted); }
  td.rank { font: 600 15px var(--sans); color: var(--muted); width: 36px; }
  .s-bad { background: rgba(240,80,110,0.18); color: var(--hot); }
  .lead { font-size: 14px; line-height: 1.65; color: var(--text-2); margin: 0 0 8px; }
  .lead strong { color: var(--text); }
  table.data-table thead th { cursor: pointer; user-select: none; }
  table.data-table thead th:hover { color: var(--text); }
  table.data-table thead th[data-sort="asc"]::after { content: " ▲"; font-size: 9px; }
  table.data-table thead th[data-sort="desc"]::after { content: " ▼"; font-size: 9px; }
  details > summary { cursor: pointer; list-style: none; }
  details > summary::-webkit-details-marker { display: none; }
  details > summary h2::after { content: "  +"; color: var(--muted); }
  details[open] > summary h2::after { content: "  -"; }
  ul.notes { margin: 0 0 10px; padding-left: 18px; color: var(--muted); font-size: 12px; line-height: 1.7; }
  .select { background: var(--panel-2); color: var(--text); border: 1px solid var(--line); border-radius: var(--radius);
            padding: 8px 10px; font: 500 12.5px var(--sans); min-width: 260px; }
  .select:focus { outline: none; border-color: var(--accent); }
  .covbar { display:inline-block; vertical-align: middle; width: 80px; height: 5px; background: var(--track); margin-right: 8px; }
  .covbar i { display:block; height: 100%; background: var(--accent); }
  .covbar i.validfill { background: var(--band-high); }
  .covbar i.threatfill { background: var(--bad); }
  .mini { display:inline-block; font-size: 10.5px; padding: 1px 6px; margin: 1px 0; border: 1px solid var(--hair); border-radius: var(--radius);
          color: var(--muted); white-space: nowrap; }
  .mini.hit { border-color: rgba(240,80,110,0.6); color: var(--hot); }
  .note { color: var(--muted); font-size: 12px; }
  .btn-export { background: transparent; color: var(--accent); border-color: var(--export-border); padding: 9px 16px; font-size: 13px; }
  .btn-export:hover { border-color: var(--accent); background: rgba(3,113,224,0.08); }
  .attver { font-size: 11px; font-weight: 600; text-transform: uppercase; color: var(--muted); letter-spacing: 0.02em; }
  .attver b { text-transform: none; font-weight: 600; }
  .disclaimer { margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--line); color: var(--muted-2);
                font-size: 11.5px; line-height: 1.6; }
  .disclaimer p { margin: 0 0 6px; }
  .disclaimer a { color: var(--link); }

  @media (max-width: 1100px) { .card { grid-column: span 6; } .panel.half { grid-column: span 12; } .meta { display:none; } }
  @media (max-width: 560px) { .card { grid-column: span 12; } .wrap { padding: 14px 16px 40px; } .pop { width: calc(100vw - 32px); } }
  .footer-note { margin: 8px 0 10px; color: var(--muted); font-size: 12px; }
</style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <div class="logo">
          <img src="%%LOGO_SRC%%" alt="Exabeam" onerror="this.style.display='none'; this.nextElementSibling.style.display='block';" />
          <span class="fallback" style="display:none;">LOGO</span>
        </div>
        <div class="title">
          <h1>MITRE ATT&amp;CK Coverage Report</h1>
          <div class="sub">Exabeam Correlation Rules • Region: %%REGION%% • Generated: %%GENERATED%%</div>
        </div>
      </div>
      <div class="topright">
        <div class="meta">%%COMPARE_META%%</div>
        <button class="themebtn" id="themeBtn" onclick="toggleTheme()" aria-label="Switch between dark and light mode"></button>
      </div>
    </div>

    <div class="tabs" role="tablist">
      <button class="tab" data-tab="coverage">MITRE ATT&amp;CK&reg; Coverage</button>
      <button class="tab" data-tab="focus">Focus</button>
      <button class="tab" data-tab="surface">Attack Surface</button>
      <button class="tab" data-tab="groups">Threat Groups</button>
      <button class="tab" data-tab="rules">Rules</button>
      <button class="tab" data-tab="changes">Changes<span class="count">%%CHANGE_COUNT%%</span></button>
    </div>

    <section class="tabpane" id="tab-coverage">
      <div class="filterbar" id="filterbar"></div>
      <div class="grid" id="coverageCards"></div>

      <div class="legendbar">
        <strong>Coverage &amp; Score</strong>
        <span class="item"><i class="lg-box nocov"></i>No coverage</span>
        <span class="item"><i class="lg-box plain"></i>Via sub-technique</span>
        <span class="item"><i class="lg-box scored"></i>Coverage</span>
        <span class="sep"></span>
        <span class="item"><i class="lg-line" style="background:var(--band-zero)"></i>&le; 0</span>
        <span class="item"><i class="lg-line" style="background:var(--band-low)"></i>1-49 Unvalidated</span>
        <span class="item"><i class="lg-line" style="background:var(--band-mid)"></i>50-74 Quiet</span>
        <span class="item"><i class="lg-line" style="background:var(--band-high)"></i>75-100 Validated</span>
        <span class="item" id="threatLegend" style="display:none"><span class="threat static">&#9679; n</span>Threat groups targeting your sector</span>
        <span class="sep" id="attackVersionSep" style="display:none"></span>
        <span class="attver" id="attackVersion" style="display:none"></span>
      </div>
      <div class="toolbar">
        <div class="group">
          <button class="btn btn-outline" onclick="expandAll(true)">Expand all sub-techniques</button>
          <button class="btn btn-outline" onclick="expandAll(false)">Collapse all</button>
        </div>
        <div class="group">
          <label class="switch"><input type="checkbox" id="rollup" checked onchange="renderMatrix()"><span class="knob"></span>Count sub-technique coverage</label>
          <label class="switch"><input type="checkbox" id="showNone" checked onchange="renderMatrix()"><span class="knob"></span>Show uncovered techniques</label>
          <label class="switch"><input type="checkbox" id="showHidden" onchange="FILTER.showHidden = this.checked; saveFilter(); renderMatrix()"><span class="knob"></span>Show hidden techniques</label>
          <button class="btn btn-export" onclick="exportCsv()" title="Download the matrix as CSV (follows the current filters)">
            <svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>
            Export MITRE ATT&amp;CK Coverage
          </button>
        </div>
      </div>
      <div class="matrix" id="matrix"></div>
      <div class="footer-note">
        Score: Validated (a mapped rule fired in the last %%STALE%% days) = 75-100, Quiet (mapped rules fired before, but not recently) = 50-74,
        Unvalidated (mapped rules have never fired) = 20-49, Not covered = 0. Each additional rule in the same state adds 5 points within its band.
        Click a technique for details; use the handle on the right of a tile to show its sub-techniques.
      </div>
    </section>

    <section class="tabpane" id="tab-focus"><div id="focusView"></div><div class="grid">%%PRIORITY_PANEL%%</div></section>

    <section class="tabpane" id="tab-surface"><div id="surfaceView"></div></section>

    <section class="tabpane" id="tab-groups"><div id="groupsView"></div></section>

    <section class="tabpane" id="tab-rules"><div id="rulesView"></div></section>

    <section class="tabpane" id="tab-changes">
      <div class="grid">%%CHANGES%%</div>
    </section>

    <footer class="disclaimer">
      <p>Exabeam MITRE Coverage Report v%%VERSION%%</p>
      <p>&copy; 2023 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.
        <a href="https://attack.mitre.org/resources/terms-of-use/" target="_blank" rel="noopener">https://attack.mitre.org/resources/terms-of-use/</a></p>
      <p>ATT&amp;CK is subject to the license linked here and the following copyright: &copy; 2023 The MITRE Corporation. This work is reproduced
        and distributed with the permission of The MITRE Corporation. MITRE ATT&amp;CK and ATT&amp;CK are trademarks of The MITRE Corporation.
        Exabeam is not affiliated with, sponsored, or endorsed by The MITRE Corporation.</p>
    </footer>
  </div>

  <div class="pop" id="pop" role="dialog" aria-modal="false"></div>
  <div class="overlay" id="overlay" onclick="if (event.target === this) closeModal()">
    <div class="modal" id="modal" role="dialog" aria-modal="true"></div>
  </div>

<script id="matrixData" type="application/json">%%MATRIX_JSON%%</script>
<script id="matrixCsv" type="application/json">%%MATRIX_CSV%%</script>
<script id="attackData" type="application/json">%%ATTACK_JSON%%</script>
<script id="surfaceData" type="application/json">%%SURFACE_JSON%%</script>
<script id="rulesData" type="application/json">%%RULES_JSON%%</script>
<script>
const MATRIX = JSON.parse(document.getElementById('matrixData').textContent);
const ATTACK = JSON.parse(document.getElementById('attackData').textContent);   // null when ATT&CK data was unavailable
const CSV_NAME = %%MATRIX_CSV_NAME%%;
const PREV_KPIS = %%PREV_KPIS%%;
const KPIS = %%KPIS%%;
const STALE_DAYS = %%STALE%%;
const DEFAULT_SECTOR = %%DEFAULT_SECTOR%%;
const REPORT_ID = %%REPORT_ID%%;
const LABEL = {validated: 'Validated', quiet: 'Quiet', unvalidated: 'Unvalidated', none: 'Not covered'};
const RULE_CLASS = {Active: 'validated', Quiet: 'quiet', NeverFired: 'unvalidated', Unknown: 'unvalidated'};
const RULE_LABEL = {Active: 'Active', Quiet: 'Quiet', NeverFired: 'Never fired', Unknown: 'Unknown'};
const ICON = {
  shield: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z"/></svg>',
  bigShield: '<svg class="shield" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z"/></svg>',
  rules: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/></svg>',
  subs: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 4v10a3 3 0 0 0 3 3h13"/><path d="M16 13l4 4-4 4"/></svg>',
  ext: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14L21 3"/></svg>',
  target: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.5" fill="currentColor"/></svg>',
  filter: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 5h18l-7 8v6l-4 2v-8z"/></svg>',
  platform: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="4" width="18" height="12" rx="1"/><path d="M8 20h8M12 16v4"/></svg>',
  download: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>',
  eye: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>',
  eyeOff: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.9 17.9A10.4 10.4 0 0 1 12 19c-7 0-11-7-11-7a19 19 0 0 1 5.1-5.9M9.9 5.2A9.7 9.7 0 0 1 12 5c7 0 11 7 11 7a19 19 0 0 1-2.2 3.2M14.1 14.1a3 3 0 1 1-4.2-4.2"/><path d="M1 1l22 22"/></svg>',
};

/* ---------- Tailoring filters (sector + platforms), remembered per viewer ---------- */
const ALL_PLATFORMS = ATTACK ? ATTACK.platforms : [];
const PRESETS = [
  {name: 'All platforms', platforms: ALL_PLATFORMS},
  {name: 'Windows enterprise', platforms: ['Windows', 'Identity Provider', 'Office Suite', 'SaaS', 'IaaS', 'Network Devices', 'PRE']},
  {name: 'macOS estate', platforms: ['macOS', 'Identity Provider', 'Office Suite', 'SaaS', 'Network Devices', 'PRE']},
  {name: 'Linux / servers', platforms: ['Linux', 'Containers', 'ESXi', 'IaaS', 'Network Devices', 'PRE']},
  {name: 'Cloud only', platforms: ['IaaS', 'SaaS', 'Office Suite', 'Identity Provider', 'Containers', 'PRE']},
];
// Saved per report, so choices made in one report (or for one customer) never carry into another
const FILTER_KEY = 'exabeamMitreReport.filters.v2.' + REPORT_ID;
// --sector given when the report was built: open on that sector, without the first-run setup dialog
const START_SECTOR = ATTACK && ATTACK.sectors.some(s => s.name === DEFAULT_SECTOR) ? DEFAULT_SECTOR : '';
let FILTER = loadFilter();
let DRAFT = null;

function defaultFilter() {
  return {sector: START_SECTOR, platforms: ALL_PLATFORMS.slice(), onlySector: false, hidden: [], showHidden: false,
          saved: !!START_SECTOR};
}
function loadFilter() {
  const f = defaultFilter();
  try {
    const saved = JSON.parse(localStorage.getItem(FILTER_KEY) || 'null');
    if (saved) {
      f.hidden = Array.isArray(saved.hidden) ? saved.hidden.filter(x => typeof x === 'string') : [];
      f.showHidden = !!saved.showHidden;
    }
    if (saved && ATTACK) {
      f.sector = ATTACK.sectors.some(s => s.name === saved.sector) ? saved.sector : '';
      const plats = (saved.platforms || []).filter(p => ALL_PLATFORMS.includes(p));
      if (plats.length) f.platforms = plats;
      f.onlySector = !!saved.onlySector && !!f.sector;
      f.saved = true;
    }
  } catch (e) {}
  return f;
}
function saveFilter() {
  try { localStorage.setItem(FILTER_KEY, JSON.stringify(FILTER)); } catch (e) {}
}
function platformFiltered() { return !!ATTACK && FILTER.platforms.length < ALL_PLATFORMS.length; }
function filtersActive() { return platformFiltered() || (FILTER.onlySector && !!FILTER.sector) || FILTER.hidden.length > 0; }
function isManuallyHidden(id) { return FILTER.hidden.includes(id); }
function toggleHidden(id) {
  FILTER.hidden = isManuallyHidden(id) ? FILTER.hidden.filter(x => x !== id) : FILTER.hidden.concat([id]);
  FILTER.saved = true;
  saveFilter();
  renderMatrix();
}
function platformOk(t) {
  if (!ATTACK || !t.plat || !t.plat.length) return true;
  return t.plat.some(p => FILTER.platforms.includes(p));
}
function sectorGroups(t) {
  if (!ATTACK || !FILTER.sector) return [];
  return (t.grp || []).filter(i => ATTACK.groups[i].sectors.includes(FILTER.sector));
}
// Why a technique is hidden (left out of the matrix counts and the score), or '' when it is in scope
function hiddenReason(t) {
  if (isManuallyHidden(t.id)) return 'Hidden by you';
  if (!platformOk(t)) return 'Not applicable to your platforms';
  if (FILTER.onlySector && FILTER.sector && !sectorGroups(t).length) return `Not used by groups targeting ${FILTER.sector}`;
  return '';
}
function inScope(t) { return !hiddenReason(t); }

/* ---------- Helpers ---------- */
const expanded = new Set();
let selectedTile = null;
let current = null;   // {ci, ti, si} of the technique in the popover / modal
let lastScore = {sum: 0, techniques: 0, score: 0};
const POS = {};       // technique id -> first {ci, ti} it appears at
MATRIX.forEach((col, ci) => col.techs.forEach((t, ti) => { if (!POS[t.id]) POS[t.id] = {ci, ti}; }));

function escHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function bandClass(score) { return score <= 0 ? '' : score < 50 ? 'b-low' : score < 75 ? 'b-mid' : 'b-high'; }
function barHtml(score, big) {
  const cls = bandClass(score);
  return `<div class="bar${big ? ' big' : ''}">${cls ? `<b class="${cls}" style="width:${score}%"></b>` : ''}</div>`;
}
function rollup() { return document.getElementById('rollup').checked; }
// Effective status/score of a technique (or sub-technique) under the current toggle
function view(t) {
  if (t.subs === undefined) return {status: t.status, score: t.score, viaSub: false};
  return rollup() ? {status: t.rolled, score: t.rolledScore, viaSub: t.viaSub}
                  : {status: t.status, score: t.score, viaSub: false};
}
function lookup(ci, ti, si) {
  const t = MATRIX[ci].techs[ti];
  return si === undefined || si === null || si < 0 ? t : t.subs[si];
}
function pct(a, b) { return b ? Math.round(a / b * 1000) / 10 : 0; }

/* ---------- Matrix ---------- */
function threatBadge(t) {
  const n = sectorGroups(t).length;
  return n ? `<span class="threat" title="Used by ${n} threat group${n === 1 ? '' : 's'} known to target ${escHtml(FILTER.sector)}">&#9679; ${n}</span>` : '';
}
function tileHtml(t, key, isSub) {
  const v = view(t);
  const band = v.score >= 75 ? 'band-high' : v.score >= 50 ? 'band-mid' : 'band-low';
  const hidden = isSub ? '' : hiddenReason(t);
  const cls = (v.status === 'none' ? 'nocov' : v.viaSub ? 'plain' : band)
    + (hidden ? ' hiddentile' : '') + (dimmed(t, isSub) ? ' dim' : '');
  const showNone = document.getElementById('showNone').checked;
  const subs = isSub ? [] : t.subs.filter(s => platformOk(s));
  const shownSubs = subs.filter(s => showNone || s.status !== 'none');
  const open = !isSub && expanded.has(key) && shownSubs.length;   // per tile: a technique can sit under several tactics
  const handle = !isSub && subs.length
    ? `<div class="expander" data-expand="${key}" title="${open ? 'Hide' : 'Show'} ${subs.length} sub-techniques">${open ? '&#9650;' : '&#9660;'} ${subs.length}</div>` : '';
  const badge = hidden ? `<span class="hidico" title="${escHtml(hidden)}">${ICON.eyeOff}</span>` : threatBadge(t);
  let html = `<div class="tile ${cls}${badge && !hidden ? ' has-threat' : ''}" data-key="${key}">`
    + `<div class="body">${badge}${isSub ? `<div class="tid">${escHtml(t.id)}</div>` : ''}<div class="tname">${escHtml(t.name)}</div>`
    + `${v.status === 'none' ? '' : barHtml(v.score)}</div>${handle}</div>`;
  if (open) {
    html += '<div class="subs">' + t.subs.map((s, si) =>
      (platformOk(s) && (showNone || s.status !== 'none')) ? tileHtml(s, key + ':' + si, true) : '').join('') + '</div>';
  }
  return html;
}

function renderMatrix() {
  closePop();
  const showNone = document.getElementById('showNone').checked;
  document.getElementById('matrix').innerHTML = MATRIX.map((col, ci) => {
    const scoped = col.techs.filter(inScope);
    const covered = scoped.filter(t => view(t).status !== 'none').length;
    let html = `<div class="col"><div class="tcode">${escHtml(col.id)}</div>`
      + `<h3>${escHtml(col.name)}<small>${scoped.length} Techniques &bull; ${covered} covered</small></h3>`;
    col.techs.forEach((t, ti) => {
      if ((!inScope(t) && !FILTER.showHidden) || (!showNone && view(t).status === 'none')) return;
      html += tileHtml(t, ci + ':' + ti, false);
    });
    return html + '</div>';
  }).join('');
  document.getElementById('threatLegend').style.display = FILTER.sector ? '' : 'none';
  document.getElementById('showHidden').checked = FILTER.showHidden;
  renderCards();
  renderFilterBar();
  renderGroups();
  renderFocus();
}

function expandAll(on) {
  expanded.clear();
  if (on) MATRIX.forEach((col, ci) => col.techs.forEach((t, ti) => { if (t.subs.length) expanded.add(ci + ':' + ti); }));
  renderMatrix();
}

/* ---------- Coverage cards (recalculated for the current filters) ---------- */
function card(label, value, hint, tone, delta, meter, valueHtml) {
  return `<div class="card"><div class="label">${escHtml(label)}</div>`
    + `<div class="value ${tone || ''}">${valueHtml || escHtml(value)}</div>`
    + (delta ? `<div class="delta">${escHtml(delta)}</div>` : '')
    + (meter !== undefined ? `<div class="meter"><i style="width:${Math.max(0, Math.min(meter, 100))}%"></i></div>` : '')
    + `<div class="hint">${hint}</div></div>`;
}
function deltaText(cur, key, suffix) {
  if (!PREV_KPIS || !(key in PREV_KPIS) || filtersActive() || !rollup()) return '';
  const d = Math.round((cur - PREV_KPIS[key]) * 10) / 10;
  if (Math.abs(d) < 0.05) return 'No change vs last run';
  return `${d > 0 ? '▲' : '▼'} ${Math.abs(d)}${suffix || ''} vs last run`;
}
function renderCards() {
  const parents = new Map();
  MATRIX.forEach(col => col.techs.forEach(t => { if (inScope(t)) parents.set(t.id, t); }));
  let sum = 0, covered = 0, direct = 0, validated = 0, subsTotal = 0, subsCovered = 0;
  parents.forEach(t => {
    const v = view(t);
    sum += v.score;
    if (v.status !== 'none') covered++;
    if (v.status === 'validated') validated++;
    if (t.status !== 'none') direct++;
    t.subs.forEach(s => { if (platformOk(s)) { subsTotal++; if (s.status !== 'none') subsCovered++; } });
  });
  const n = parents.size;
  const score = n ? Math.round(sum / n) : 0;
  lastScore = {sum, techniques: n, score};
  const scope = filtersActive() ? 'in-scope ' : '';
  document.getElementById('coverageCards').innerHTML =
      card('MITRE ATT&CK Coverage Score', score,
        `Average of ${n} ${scope}technique scores &bull; <a href="#" class="helplink" onclick="openScoreHelp(); return false;">How was this calculated?</a>`,
        'score', deltaText(score, 'coverageScore'), score, ICON.bigShield + score)
    + card('Parent techniques covered', pct(covered, n).toFixed(1) + '%',
        `${covered}/${n} ${scope}incl. via sub-techniques &bull; ${direct} mapped directly`, '',
        deltaText(pct(covered, n), 'parentsCoveredPct', ' pts'), pct(covered, n))
    + card('Validated coverage', pct(validated, n).toFixed(1) + '%',
        `${validated}/${n} ${scope}techniques have a rule that fired in the last ${STALE_DAYS} days`, 'good',
        deltaText(pct(validated, n), 'validatedPct', ' pts'), pct(validated, n))
    + (KPIS.subTechniqueTags
      ? card('Sub-techniques covered', pct(subsCovered, subsTotal).toFixed(1) + '%', `${subsCovered}/${subsTotal}`, '',
          deltaText(pct(subsCovered, subsTotal), 'subsCoveredPct', ' pts'), pct(subsCovered, subsTotal))
      // Correlation rules can only be tagged with a tactic and technique, so show tagging coverage instead
      : card('Rules with MITRE tags', `${KPIS.rulesTagged} of ${KPIS.enabledRules}`,
          `${KPIS.enabledRules - KPIS.rulesTagged} enabled rules have no MITRE tag and don't count towards coverage. `
          + 'Correlation rules are tagged by tactic and technique (not sub-technique).', '',
          deltaText(KPIS.rulesTagged, 'rulesTagged'), pct(KPIS.rulesTagged, KPIS.enabledRules)));
}

/* ---------- Filter bar + sector priority panel ---------- */
function renderFilterBar() {
  const bar = document.getElementById('filterbar');
  if (!ATTACK) {
    bar.innerHTML = '<span class="chip muted">Platform and sector filters unavailable - MITRE ATT&amp;CK data could not be downloaded when this report was built.</span>';
    return;
  }
  const plats = FILTER.platforms.length === ALL_PLATFORMS.length ? 'All platforms'
    : FILTER.platforms.length <= 4 ? FILTER.platforms.join(', ') : `${FILTER.platforms.length} of ${ALL_PLATFORMS.length} platforms`;
  bar.innerHTML = `<button class="btn btn-primary" onclick="openSetup(false)">${ICON.filter}Tailor report</button>`
    + `<span class="chip${FILTER.sector ? ' sector' : ' muted'}">${ICON.target}${FILTER.sector ? escHtml(FILTER.sector) : 'No sector selected'}</span>`
    + `<span class="chip${platformFiltered() ? '' : ' muted'}">${ICON.platform}${escHtml(plats)}</span>`
    + (FILTER.onlySector && FILTER.sector ? `<span class="chip sector">Only techniques used against ${escHtml(FILTER.sector)}</span>` : '')
    + (FILTER.hidden.length ? `<span class="chip">${ICON.eyeOff}${FILTER.hidden.length} hidden by you</span>` : '')
    + (HIGHLIGHT !== null ? `<span class="chip sector">Highlighting ${escHtml(ATTACK.groups[HIGHLIGHT].name)}`
       + ` <a href="#" class="helplink" onclick="clearHighlight(); return false;">&times; clear</a></span>` : '')
    + (filtersActive() ? `<button class="btn btn-ghost" onclick="resetFilters()">Clear filters</button>` : '');
}
if (ATTACK) {
  // Shown at the end of the legend row, as in the Outcomes Navigator
  const v = document.getElementById('attackVersion');
  v.innerHTML = `ATT&amp;CK <b>v${escHtml(ATTACK.version)}</b>`;
  v.title = 'MITRE ATT&CK Enterprise version used for platforms and threat groups';
  v.style.display = document.getElementById('attackVersionSep').style.display = '';
}
function resetFilters() {
  FILTER = Object.assign(defaultFilter(), {saved: true});
  saveFilter();
  renderMatrix();
}

function renderSectorPanel() {
  const panel = document.getElementById('sectorPanel');
  if (!panel || !ATTACK || !FILTER.sector) return;
  const seen = new Set();
  const used = [];
  MATRIX.forEach(col => col.techs.forEach(t => {
    if (seen.has(t.id) || !platformOk(t)) return;
    seen.add(t.id);
    const g = sectorGroups(t).length;
    if (g) used.push({t, g, v: view(t)});
  }));
  const validated = used.filter(x => x.v.status === 'validated').length;
  const gaps = used.filter(x => x.v.status !== 'validated')
    .sort((a, b) => b.g - a.g || a.v.score - b.v.score || a.t.name.localeCompare(b.t.name)).slice(0, 25);
  const tactics = id => MATRIX.filter(c => c.techs.some(x => x.id === id)).map(c => c.name).join(', ');
  const rows = gaps.map(x => `<tr data-tech="${escHtml(x.t.id)}"><td style="font-family:var(--mono)">${escHtml(x.t.id)}</td>`
    + `<td>${escHtml(x.t.name)}</td><td>${escHtml(tactics(x.t.id))}</td><td><span class="threat static">&#9679; ${x.g}</span></td>`
    + `<td><span class="tag s-${x.v.status}">${LABEL[x.v.status]}</span></td><td>${x.v.score}</td></tr>`).join('');
  panel.style.display = '';
  panel.innerHTML = `<h2>Priority gaps for ${escHtml(FILTER.sector)} <span class="note">(${gaps.length})</span></h2>`
    + `<p class="sub">${used.length} techniques in scope are used by threat groups known to target ${escHtml(FILTER.sector)}; `
    + `${validated} of them are validated. The techniques below are not covered, or only covered by rules that have never fired or gone quiet, `
    + `ranked by how many of those groups use them. Click a row for details.</p>`
    + (rows ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>ID</th><th>Technique</th><th>Tactics</th>`
      + `<th>Groups</th><th>Status</th><th>Score</th></tr></thead><tbody>${rows}</tbody></table></div>`
      : '<div class="footer-note">Every technique used against this sector is validated.</div>');
}

/* ---------- Threat groups tab ---------- */
const PARENTS = {};   // parent technique id -> matrix technique
MATRIX.forEach(col => col.techs.forEach(t => { PARENTS[t.id] = t; }));
const GROUP_PARENTS = ATTACK ? ATTACK.groups.map(g => new Set(g.techniques.map(id => id.split('.')[0]).filter(id => PARENTS[id]))) : [];
const GROUP_IDS = ATTACK ? ATTACK.groups.map(g => new Set(g.techniques)) : [];

function groupStats(i) {
  const ids = [...GROUP_PARENTS[i]].filter(id => platformOk(PARENTS[id]) && !isManuallyHidden(id));
  let covered = 0, validated = 0;
  ids.forEach(id => {
    const s = view(PARENTS[id]).status;
    if (s !== 'none') covered++;
    if (s === 'validated') validated++;
  });
  return {ids, total: ids.length, covered, validated, gaps: ids.length - covered};
}
function covBar(a, b, cls) {
  return `<span class="covbar"><i class="${cls || ''}" style="width:${b ? Math.round(a / b * 100) : 0}%"></i></span>`;
}
function sectorSelect(id) {
  return `<select class="select" id="${id}" onchange="setSector(this.value)">`
    + `<option value="">All sectors</option>`
    + ATTACK.sectors.map(s => `<option value="${escHtml(s.name)}"${FILTER.sector === s.name ? ' selected' : ''}>${escHtml(s.name)} (${s.groups} groups)</option>`).join('')
    + `</select>`;
}
function setSector(name) {
  FILTER.sector = name;
  if (!name) FILTER.onlySector = false;
  FILTER.saved = true;
  saveFilter();
  renderMatrix();
}

function renderGroups() {
  const root = document.getElementById('groupsView');
  if (!ATTACK) {
    root.innerHTML = '<div class="panel"><h2>Threat groups</h2><p class="sub">MITRE ATT&amp;CK data could not be downloaded when this report was built.</p></div>';
    return;
  }
  const sector = FILTER.sector;
  const groups = ATTACK.groups.map((g, i) => ({g, i, st: groupStats(i)}))
    .filter(x => !sector || x.g.sectors.includes(sector))
    .sort((a, b) => b.st.total - a.st.total || a.g.name.localeCompare(b.g.name));

  // Techniques used by these groups, ranked by how many of them use each one
  const counts = {};
  groups.forEach(x => x.st.ids.forEach(id => { counts[id] = (counts[id] || 0) + 1; }));
  const ranked = Object.entries(counts).sort((a, b) => b[1] - a[1] || PARENTS[a[0]].name.localeCompare(PARENTS[b[0]].name));
  const used = ranked.length;
  const usedCovered = ranked.filter(([id]) => view(PARENTS[id]).status !== 'none').length;
  const usedValidated = ranked.filter(([id]) => view(PARENTS[id]).status === 'validated').length;
  const who = sector ? `known to target ${escHtml(sector)}` : 'in MITRE ATT&amp;CK';

  const cards = card(sector ? `Threat groups targeting ${sector}` : 'Threat groups', groups.length,
      sector ? `Groups whose MITRE description mentions ${escHtml(sector)}` : 'Choose a sector to focus on the groups that target it', '')
    + card('Techniques they use', used, `Parent techniques used by these groups${platformFiltered() ? ' on your platforms' : ''}`, '')
    + card('Covered', pct(usedCovered, used).toFixed(1) + '%', `${usedCovered}/${used} have at least one enabled rule`, '', '', pct(usedCovered, used))
    + card('Validated', pct(usedValidated, used).toFixed(1) + '%', `${usedValidated}/${used} have a rule that fired in the last ${STALE_DAYS} days`, 'good', '', pct(usedValidated, used));

  const maxCount = ranked.length ? ranked[0][1] : 1;
  const topRows = ranked.slice(0, 25).map(([id, n]) => {
    const t = PARENTS[id], v = view(t);
    return `<tr data-tech="${escHtml(id)}"><td style="font-family:var(--mono)">${escHtml(id)}</td><td>${escHtml(t.name)}</td>`
      + `<td>${covBar(n, maxCount, 'threatfill')}${n} of ${groups.length}</td>`
      + `<td><span class="tag s-${v.status}">${LABEL[v.status]}</span></td><td>${v.score}</td></tr>`;
  }).join('');

  const groupRows = groups.map(x => {
    const {g, i, st} = x;
    const aliases = g.aliases && g.aliases.length ? `<div class="note">${escHtml(g.aliases.slice(0, 4).join(', '))}</div>` : '';
    return `<tr data-group="${i}"><td><strong>${escHtml(g.name)}</strong> <span class="note" style="font-family:var(--mono)">${escHtml(g.id)}</span>${aliases}</td>`
      + `<td>${g.sectors.map(s => `<span class="mini${s === sector ? ' hit' : ''}">${escHtml(s)}</span>`).join(' ') || '<span class="note">-</span>'}</td>`
      + `<td>${st.total}</td>`
      + `<td>${covBar(st.covered, st.total)}${st.covered}/${st.total}</td>`
      + `<td>${covBar(st.validated, st.total, 'validfill')}${st.validated}/${st.total}</td>`
      + `<td>${st.gaps}</td></tr>`;
  }).join('');

  root.innerHTML =
      `<div class="filterbar"><span class="chip muted">${ICON.target}Sector</span>${sectorSelect('groupSector')}`
    + `<span class="note">${groups.length} threat groups ${who}. MITRE does not tag groups by sector, so this is matched from keywords in each group's description.</span></div>`
    + `<div class="grid">${cards}</div>`
    + `<div class="grid">`
    + `<div class="panel half"><h2>Most used ${sector ? 'against ' + escHtml(sector) : 'techniques'}</h2>`
    + `<p class="sub">Techniques used by the most ${sector ? 'of these ' : ''}groups, with your coverage. Click a row for details.</p>`
    + `<div class="table-wrap"><table class="data-table" id="tblTopTech"><thead><tr><th>ID</th><th>Technique</th><th>Groups</th><th>Status</th><th>Score</th></tr></thead><tbody>${topRows}</tbody></table></div></div>`
    + `<div class="panel half"><h2>Threat groups (${groups.length})</h2>`
    + `<p class="sub">Your coverage of the techniques each group uses. Click a group for its techniques, or to highlight them on the matrix.</p>`
    + `<div class="controls"><input type="text" placeholder="Filter (name, alias, sector)..." oninput="filterTable('tblGroups', this.value)"></div>`
    + `<div class="table-wrap"><table class="data-table" id="tblGroups"><thead><tr><th>Group</th><th>Sectors</th><th>Techniques</th><th>Covered</th><th>Validated</th><th>Gaps</th></tr></thead><tbody>${groupRows}</tbody></table></div></div>`
    + `</div>`;
}

document.getElementById('groupsView').addEventListener('click', e => {
  const tech = e.target.closest('tr[data-tech]');
  if (tech && POS[tech.dataset.tech]) {
    current = {ci: POS[tech.dataset.tech].ci, ti: POS[tech.dataset.tech].ti, si: undefined};
    openModal();
    return;
  }
  const grp = e.target.closest('tr[data-group]');
  if (grp) openGroup(Number(grp.dataset.group));
});

function openGroup(i) {
  const g = ATTACK.groups[i];
  const st = groupStats(i);
  const order = {none: 0, unvalidated: 1, quiet: 2, validated: 3};
  const byTactic = MATRIX.map(col => {
    const techs = col.techs.filter(t => st.ids.includes(t.id))
      .sort((a, b) => order[view(a).status] - order[view(b).status] || a.name.localeCompare(b.name));
    if (!techs.length) return '';
    return `<h4>${escHtml(col.id)} ${escHtml(col.name)} (${techs.length})</h4>`
      + `<div class="table-wrap" style="max-height:none"><table class="data-table"><tbody>`
      + techs.map(t => {
          const v = view(t);
          const subs = t.subs.filter(s => GROUP_IDS[i].has(s.id)).map(s => s.id);
          return `<tr data-tech="${escHtml(t.id)}"><td style="font-family:var(--mono);width:90px">${escHtml(t.id)}</td>`
            + `<td>${escHtml(t.name)}${subs.length ? `<div class="note">uses ${subs.map(escHtml).join(', ')}</div>` : ''}</td>`
            + `<td style="width:120px"><span class="tag s-${v.status}">${LABEL[v.status]}</span></td><td style="width:50px">${v.score}</td></tr>`;
        }).join('') + `</tbody></table></div>`;
  }).join('');
  document.getElementById('modal').innerHTML =
      `<button class="xbtn" onclick="closeModal()" aria-label="Close">&times;</button>`
    + `<div class="ptitle">${escHtml(g.name)}</div>`
    + `<div class="pid">${escHtml(g.id)}${g.aliases && g.aliases.length ? ' &bull; also known as ' + escHtml(g.aliases.join(', ')) : ''}</div>`
    + (g.sectors.length ? `<div class="row">${g.sectors.map(s => `<span class="mini${s === FILTER.sector ? ' hit' : ''}">${escHtml(s)}</span>`).join(' ')}</div>` : '')
    + (g.desc ? `<p class="desc">${escHtml(g.desc)}</p>` : '')
    + `<div class="row"><span class="num">${st.covered}/${st.total}</span><span class="note">techniques covered &bull; ${st.validated} validated &bull; ${st.gaps} gaps</span></div>`
    + `<div class="actions" style="justify-content:flex-start">`
    + `<button class="btn btn-primary" onclick="highlightGroup(${i})">Highlight on matrix</button>`
    + (g.url ? `<a class="btn btn-ghost" href="${escHtml(g.url)}" target="_blank" rel="noopener">${ICON.ext}View ${escHtml(g.id)} on attack.mitre.org</a>` : '')
    + `</div>`
    + byTactic;
  closePop();
  document.getElementById('overlay').classList.add('open');
}
document.getElementById('modal').addEventListener('click', e => {
  const tech = e.target.closest('tr[data-tech]');
  if (!tech || !POS[tech.dataset.tech]) return;
  current = {ci: POS[tech.dataset.tech].ci, ti: POS[tech.dataset.tech].ti, si: undefined};
  openModal();
});

let HIGHLIGHT = null;   // index into ATTACK.groups of the group highlighted on the matrix
function highlightGroup(i) {
  HIGHLIGHT = i;
  closeModal();
  showTab('coverage');
  renderMatrix();
  window.scrollTo({top: document.getElementById('matrix').getBoundingClientRect().top + window.scrollY - 80, behavior: 'smooth'});
}
function clearHighlight() { HIGHLIGHT = null; renderMatrix(); }
function dimmed(t, isSub) {
  if (HIGHLIGHT === null) return false;
  return isSub ? !GROUP_IDS[HIGHLIGHT].has(t.id) : !GROUP_PARENTS[HIGHLIGHT].has(t.id);
}

/* ---------- Focus tab: what to work on next ---------- */
const LANES = {
  fix:   {title: 'Fix', sub: 'Covered only by rules that have gone quiet - most likely a broken log source or parser', tag: 's-quiet'},
  build: {title: 'Build', sub: 'No enabled rule covers these - new detection content needed', tag: 's-none'},
  prove: {title: 'Prove', sub: 'Covered only by rules that have never fired - validate with Echo', tag: 's-unvalidated'},
};
function focusWeight(t) { return FILTER.sector ? sectorGroups(t).length : (t.grp || []).length; }
function techRules(t) { return t.rules.concat(...t.subs.map(s => s.rules)); }
function focusLanes() {
  const seen = new Set(), lanes = {fix: [], build: [], prove: []};
  MATRIX.forEach(col => col.techs.forEach(t => {
    if (seen.has(t.id) || !inScope(t)) return;
    seen.add(t.id);
    const st = view(t).status;
    const lane = st === 'none' ? 'build' : st === 'unvalidated' ? 'prove' : st === 'quiet' ? 'fix' : '';
    if (lane) lanes[lane].push({t, w: focusWeight(t), lane});
  }));
  Object.values(lanes).forEach(l => l.sort((a, b) => b.w - a.w || (b.t.grp || []).length - (a.t.grp || []).length || a.t.name.localeCompare(b.t.name)));
  return lanes;
}
function tacticsOf(id) { return MATRIX.filter(c => c.techs.some(x => x.id === id)).map(c => c.name); }
function focusReason(x) {
  const rules = techRules(x.t);
  if (x.lane === 'fix') {
    const quiet = rules.filter(r => r.status === 'Quiet').sort((a, b) => (b.last || '').localeCompare(a.last || ''));
    return quiet.length ? `${quiet.length} quiet rule${quiet.length === 1 ? '' : 's'} - last fired ${escHtml((quiet[0].last || '').slice(0, 10))}` : '';
  }
  if (x.lane === 'prove') {
    const never = rules.filter(r => r.status === 'NeverFired' || r.status === 'Unknown');
    return `${never.length} rule${never.length === 1 ? '' : 's'} never fired`;
  }
  return 'No detection content';
}

function renderFocus() {
  const root = document.getElementById('focusView');
  const lanes = focusLanes();
  const who = FILTER.sector ? `groups targeting ${escHtml(FILTER.sector)}` : 'threat groups';
  let validated = 0, total = 0;
  const seen = new Set();
  MATRIX.forEach(col => col.techs.forEach(t => {
    if (seen.has(t.id) || !inScope(t)) return;
    seen.add(t.id); total++;
    if (view(t).status === 'validated') validated++;
  }));
  // Top 10: highest threat use first; quiet rules (likely broken) win ties, then gaps, then unproven
  const laneRank = {fix: 0, build: 1, prove: 2};
  const top = [].concat(lanes.fix, lanes.build, lanes.prove)
    .sort((a, b) => b.w - a.w || laneRank[a.lane] - laneRank[b.lane] || a.t.name.localeCompare(b.t.name)).slice(0, 10);

  const topRows = top.map((x, i) => `<tr data-tech="${escHtml(x.t.id)}"><td class="rank">${i + 1}</td>`
    + `<td><span class="tag ${LANES[x.lane].tag}">${LANES[x.lane].title}</span></td>`
    + `<td style="font-family:var(--mono)">${escHtml(x.t.id)}</td><td><strong>${escHtml(x.t.name)}</strong></td>`
    + `<td>${escHtml(tacticsOf(x.t.id).join(', '))}</td>`
    + `<td>${ATTACK ? `<span class="threat static">&#9679; ${x.w}</span>` : '-'}</td><td class="note">${focusReason(x)}</td></tr>`).join('');

  const lane = key => {
    const items = lanes[key].slice(0, 25);
    return `<div class="panel third"><h2><span class="tag ${LANES[key].tag}">${LANES[key].title}</span> ${lanes[key].length} techniques</h2>`
      + `<p class="sub">${LANES[key].sub}. Ranked by ${who} using them.</p>`
      + `<div class="flist">${items.map(x => `<div class="fitem" data-tech="${escHtml(x.t.id)}">`
        + `<div class="fhead"><span class="mono">${escHtml(x.t.id)}</span>${ATTACK ? `<span class="threat static" title="${x.w} ${who}">&#9679; ${x.w}</span>` : ''}</div>`
        + `<div class="fname">${escHtml(x.t.name)}</div>`
        + `<div class="note">${escHtml(tacticsOf(x.t.id).join(' · '))}</div>`
        + `<div class="note">${focusReason(x)}</div></div>`).join('')
        || '<div class="footer-note">Nothing here.</div>'}</div>`
      + (lanes[key].length > 25 ? `<div class="footer-note">+${lanes[key].length - 25} more in the CSV export.</div>` : '')
      + `</div>`;
  };

  root.innerHTML =
      `<div class="filterbar"><span class="chip${FILTER.sector ? ' sector' : ' muted'}">${ICON.target}${FILTER.sector ? escHtml(FILTER.sector) : 'All sectors'}</span>`
    + `<span class="note">The work list for the next cycle, built from your coverage, rule health and ${ATTACK ? 'threat-group data' : 'rule data'}. `
    + `Follows the sector and platform choices from <a href="#" class="helplink" onclick="openSetup(false); return false;">Tailor report</a>.</span>`
    + `<button class="btn btn-export" style="margin-left:auto" onclick="exportFocusCsv()">${ICON.download}Export focus list</button></div>`
    + `<div class="grid">`
    + card('Fix', lanes.fix.length, 'techniques whose only rules have gone quiet', 'blue')
    + card('Build', lanes.build.length, 'techniques with no detection content', '')
    + card('Prove', lanes.prove.length, 'techniques whose rules have never fired', 'purple')
    + card('Validated', `${validated}/${total}`, `techniques with a rule that fired in the last ${STALE_DAYS} days`, 'good', '', pct(validated, total))
    + `</div>`
    + (FILTER.sector && ATTACK
      ? `<div class="grid"><div class="panel" id="sectorPanel"></div></div>`
      : `<div class="grid"><div class="panel"><h2>Top 10 this cycle</h2>`
        + `<p class="sub">The ten techniques where work will reduce the most risk: highest use by ${who} first, with gone-quiet detections ahead of gaps when tied. `
        + `Choose a sector in <a href="#" class="helplink" onclick="openSetup(false); return false;">Tailor report</a> for priority gaps specific to it. Click a row for details.</p>`
        + `<div class="table-wrap"><table class="data-table"><thead><tr><th>#</th><th>Action</th><th>ID</th><th>Technique</th><th>Tactics</th><th>Groups</th><th>Why</th></tr></thead><tbody>${topRows}</tbody></table></div></div></div>`)
    + `<div class="grid">${lane('fix')}${lane('build')}${lane('prove')}</div>`;
  renderSectorPanel();
}

function exportFocusCsv() {
  const lanes = focusLanes();
  const head = ['action', 'rank', 'techniqueId', 'technique', 'tactics', 'threatGroups', FILTER.sector ? 'sectorGroups' : null,
                'status', 'score', 'rules', 'mitreUrl'].filter(Boolean);
  const lines = [head.join(',')];
  ['fix', 'build', 'prove'].forEach(key => lanes[key].forEach((x, i) => {
    const v = view(x.t);
    const row = [LANES[key].title, i + 1, x.t.id, x.t.name, tacticsOf(x.t.id).join('; '), (x.t.grp || []).length];
    if (FILTER.sector) row.push(sectorGroups(x.t).length);
    row.push(LABEL[v.status], v.score, techRules(x.t).map(r => `${r.name} (${RULE_LABEL[r.status] || r.status})`).join('; '), x.t.link);
    lines.push(row.map(csvCell).join(','));
  }));
  downloadCsv(lines, CSV_NAME.replace('attack_matrix', 'focus_list'));
}
function downloadCsv(lines, name) {
  const blob = new Blob(['\\ufeff' + lines.join('\\r\\n') + '\\r\\n'], {type: 'text/csv;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 0);
}

/* ---------- Attack Surface tab ---------- */
const SURFACE = JSON.parse(document.getElementById('surfaceData').textContent);
const SURFACE_TAG = {'Detecting': 's-validated', 'Monitored, silent': 's-quiet', 'No detections': 's-unvalidated', 'No data': 's-bad'};
const SURFACE_HELP = {
  'Detecting': 'Data is arriving and rules that use it have fired recently',
  'Monitored, silent': 'Data is arriving and rules use it, but none of them has fired recently',
  'No detections': 'Data is arriving but no enabled correlation rule uses it',
  'No data': 'Rules name this source, but it sent no events in the window - those rules cannot fire',
};

function renderSurface() {
  const root = document.getElementById('surfaceView');
  if (!SURFACE) {
    root.innerHTML = `<div class="panel"><h2>Attack surface</h2><p class="sub">Attack surface data was not collected for this report. It is gathered from the `
      + `Search and Cloud Collector APIs on a live run (not when replaying older raw files without raw_surface.json), unless --no-surface is used.</p></div>`;
    return;
  }
  const P = SURFACE.products.map((p, i) => Object.assign({i}, p));
  const days = SURFACE.windowDays;
  const sending = P.filter(p => p.events > 0);
  const total = sending.reduce((a, p) => a + p.events, 0) || 1;
  const by = s => P.filter(p => p.status === s);
  const dark = by('No data').sort((a, b) => b.ruleCount - a.ruleCount || a.product.localeCompare(b.product));
  const unused = by('No detections').sort((a, b) => b.events - a.events);
  const silent = by('Monitored, silent').sort((a, b) => b.ruleCount - a.ruleCount || b.events - a.events);
  const working = by('Detecting').sort((a, b) => b.triggers - a.triggers || b.active - a.active || b.events - a.events);
  const vol = list => list.reduce((a, p) => a + p.events, 0);
  const share = list => Math.round(vol(list) / total * 1000) / 10;
  const pctOf = n => { const v = n / total * 100; return v > 0 && v < 0.1 ? '<0.1%' : (Math.round(v * 10) / 10) + '%'; };
  const fmt = n => Number(n).toLocaleString();
  const compact = n => n >= 1e9 ? (n / 1e9).toFixed(1) + 'B' : n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'K' : String(n);
  const maxEv = Math.max(1, ...P.map(p => p.events));
  const cc = SURFACE.collectors;
  const ccBad = cc.filter(c => c.health !== 'Healthy');

  const context = p => [p.vendor, (p.categories || []).join(', '), (p.platforms || []).length ? p.platforms.join(', ') : '']
    .filter(Boolean).map(escHtml).join(' &bull; ');
  const source = p => `<td data-v="${escHtml(p.product.toLowerCase())}"><strong>${escHtml(p.product)}</strong>`
    + (context(p) ? `<div class="note">${context(p)}</div>` : '') + `</td>`;
  const events = p => `<td data-v="${p.events}">${covBar(p.events, maxEv)}${fmt(p.events)}</td>`;
  const how = p => `${p.namedRules} name this source in their query; ${p.fedRules} match its events when their query is run`
    + (p.triggers ? `; ${p.triggers} triggers in ${SURFACE.triggerDays} days name it as the source` : '');
  const rulesCell = p => `<td data-v="${p.ruleCount}" title="${escHtml(how(p))}">${p.ruleCount}</td>`;
  const techCell = p => `<td data-v="${p.validatedTechniques.length}">${p.validatedTechniques.length} of ${p.techniques.length}</td>`;

  const section = (n, title, list, tone, meaning, action, head, row, emptyText) =>
    `<div class="panel"><h2><span class="tag ${tone}">${n}</span> ${title} <span class="note">(${list.length})</span></h2>`
    + `<p class="sub"><strong>What it means:</strong> ${meaning}<br><strong>What to do:</strong> ${action}</p>`
    + (list.length ? `<div class="table-wrap"><table class="data-table sortable surface-tbl"><thead><tr>${head}</tr></thead><tbody>`
        + list.map(p => `<tr data-product="${p.i}">${row(p)}</tr>`).join('') + `</tbody></table></div>`
      : `<div class="footer-note">${emptyText}</div>`)
    + `</div>`;

  // Plain-English summary
  const summary = [];
  summary.push(`In the last ${days} days, <strong>${sending.length} data sources</strong> sent <strong>${compact(vol(sending))} events</strong>.`);
  summary.push(`Rules that use the data fired recently for <strong>${working.length}</strong> of them.`);
  if (unused.length) summary.push(`<strong>${unused.length} sources (${share(unused)}% of all events)</strong> have no detection rules using their data${unused[0] ? `, led by ${escHtml(unused[0].product)} (${compact(unused[0].events)} events)` : ''}.`);
  if (silent.length) summary.push(`${silent.length} more have rules that haven't fired recently.`);
  if (dark.length) summary.push(`<strong>${dark.length} sources that your rules depend on sent nothing</strong>, so ${dark.reduce((a, p) => a + p.ruleCount, 0)} rules cannot fire.`);
  if (ccBad.length) summary.push(`${ccBad.length} cloud collector${ccBad.length === 1 ? ' is' : 's are'} in error or silent.`);

  const notes = [];
  if (!SURFACE.eventsAvailable) notes.push('Event volume per source could not be queried - check that the API key can run searches.');
  notes.push(`Data sources come from a grouped search of the last ${days} days by vendor, product, product category and platform`
    + (SURFACE.eventsMethod ? ` (${escHtml(SURFACE.eventsMethod)})` : '') + '. Events generated by Exabeam itself are not counted.');
  notes.push('A rule <em>uses</em> a source when its query names the product, when its query matches events from that source, or when its triggers name that source.');
  notes.push(SURFACE.deepChecked ? `${SURFACE.deepChecked} rule queries were run against the last ${days} days to link rules to sources`
    + (SURFACE.deepTruncated ? ' (stopped early by the time limit).' : '.')
    : 'Rule queries were not run in this report (--no-surface-deep or not yet collected), so most rules are linked to sources only through their triggers. Run without --no-surface-deep for the full picture.');
  notes.push(SURFACE.triggerEvents ? `${fmt(SURFACE.triggerEvents)} correlation rule triggers in the last ${SURFACE.triggerDays} days, of which ${fmt(SURFACE.triggerAttributed)} name the source product.`
    : `No correlation rule triggers were returned for the last ${SURFACE.triggerDays} days.`);
  SURFACE.errors.forEach(e => notes.push(`<span style="color:var(--bad)">${escHtml(e.step)}: ${escHtml(String(e.error).slice(0, 240))}</span>`));

  const ccRows = cc.map(c => `<tr><td data-v="${escHtml(c.name.toLowerCase())}"><strong>${escHtml(c.name)}</strong><div class="note">${escHtml(c.type)}</div></td>`
      + `<td>${escHtml(c.vendor)}</td><td>${escHtml(c.site || '-')}</td>`
      + `<td data-v="${c.hoursSinceLastLog === null ? 1e9 : c.hoursSinceLastLog}">${escHtml(c.lastLogReceived || 'never')}`
      + (c.hoursSinceLastLog !== null ? `<div class="note">${c.hoursSinceLastLog}h ago</div>` : '') + `</td>`
      + `<td><span class="tag ${c.health === 'Healthy' ? 's-validated' : c.health === 'Silent' ? 's-quiet' : 's-bad'}">${escHtml(c.health)}</span></td></tr>`).join('');
  const starved = SURFACE.starvedRules.map(r => {
    const info = SURFACE.rules[r] || {techniques: []};
    return `<tr><td>${escHtml(r)}</td><td style="font-family:var(--mono)">${info.techniques.map(t => escHtml(t.id)).join(', ') || '-'}</td>`
      + `<td><span class="tag s-${RULE_CLASS[info.status] || 'none'}">${escHtml(RULE_LABEL[info.status] || info.status || '')}</span></td></tr>`;
  }).join('');
  const ccError = SURFACE.errors.find(e => e.step === 'cloud collectors');

  root.innerHTML =
      `<div class="grid"><div class="panel"><h2>What your data is telling you</h2><p class="lead">${summary.join(' ')}</p>`
    + `<p class="sub">This tab compares the data Exabeam receives with the correlation rules that use it. Sections are in priority order. Click a source for its rules and techniques, `
    + `or click a column heading to sort.</p>`
    + (SURFACE.deepChecked ? '' : `<p class="sub" style="color:var(--warn)"><strong>Partial picture:</strong> the rule queries were not checked against your data in this report, `
      + `so rules are linked to sources only when they name the product or their triggers name it. Some sources listed as unused may be used by rules that match them `
      + `without naming them. Run without --no-surface-deep (and with Search access) for the full picture.</p>`)
    + `</div></div>`
    + `<div class="grid">`
    + card("Rules can't fire", dark.length, `sources your rules depend on sent nothing (${dark.reduce((a, p) => a + p.ruleCount, 0)} rules affected)`, dark.length ? 'bad' : 'good')
    + card('Unused data', unused.length, `sources with no detection rules - ${share(unused)}% of all events`, unused.length ? 'purple' : 'good')
    + card('Silent', silent.length, 'sources whose rules have not fired recently', silent.length ? 'blue' : 'good')
    + card('Working', working.length, `sources with rules firing in the last ${STALE_DAYS} days`, 'good', '', pct(working.length, sending.length))
    + `</div>`
    + `<div class="controls"><input type="text" placeholder="Find a source, vendor or platform in all sections..." oninput="filterSurface(this.value)"></div>`
    + `<div class="grid">`
    + section(1, "Rules that can't fire - sources gone dark", dark, 's-bad',
        `rules expect data from these sources, but none arrived in the last ${days} days.`,
        'check the source is still sending (collector, agent or log forwarding) and parsing. If the source has been retired, disable or update the rules.',
        `<th>Source</th><th>Rules waiting on it</th><th>Techniques affected</th>`,
        p => source(p) + rulesCell(p) + `<td data-v="${p.techniques.length}">${p.techniques.length}</td>`,
        'None - every source your rules name is sending data.')
    + section(2, 'Unused data - no detections', unused, 's-unvalidated',
        `Exabeam receives this data, but no enabled correlation rule uses it. Together, these sources are ${share(unused)}% of the events received.`
          + (SURFACE.deepChecked ? '' : ' (Partial check - see the note at the top.)'),
        'build detections for the sources that matter (the Focus and Threat Groups tabs show what to prioritise), or review whether the data is needed.',
        `<th>Source</th><th>Events (${days}d)</th><th>Share of all events</th>`,
        p => source(p) + events(p) + `<td data-v="${p.events}">${pctOf(p.events)}</td>`,
        'None - every source sending data is used by at least one rule.')
    + section(3, 'Silent - rules exist but have not fired', silent, 's-quiet',
        `rules use this data, but none of them has fired in the last ${STALE_DAYS} days.`,
        'confirm the rules still match the data (field names and values change when parsers are updated), then prove them with a log replay such as Echo.',
        `<th>Source</th><th>Events (${days}d)</th><th>Rules using it</th><th>Quiet</th><th>Never fired</th>`,
        p => source(p) + events(p) + rulesCell(p) + `<td data-v="${p.quiet}">${p.quiet}</td><td data-v="${p.never}">${p.never}</td>`,
        'None.')
    + section(4, 'Working - rules firing on this data', working, 's-validated',
        `rules that use this data fired in the last ${STALE_DAYS} days.`,
        'keep these healthy - watch the Changes tab for rules that stop firing.',
        `<th>Source</th><th>Events (${days}d)</th><th>Rules firing</th><th>Triggers (${SURFACE.triggerDays}d)</th><th>Techniques validated</th>`,
        p => source(p) + events(p) + `<td data-v="${p.active}">${p.active} of ${p.ruleCount}</td>`
          + `<td data-v="${p.triggers}">${p.triggers ? fmt(p.triggers) : '<span class="note">-</span>'}</td>` + techCell(p),
        'None.')
    + `</div>`
    + `<div class="grid">`
    + `<div class="panel half"><h2>Starved rules <span class="note">(${SURFACE.starvedRules.length})</span></h2>`
    + `<p class="sub">Enabled rules whose own query matched no events at all in the last ${days} days, whatever the source. They cannot fire until matching data arrives.</p>`
    + (starved ? `<div class="table-wrap"><table class="data-table sortable"><thead><tr><th>Rule</th><th>Techniques</th><th>Status</th></tr></thead><tbody>${starved}</tbody></table></div>`
               : `<div class="footer-note">${SURFACE.deepChecked ? 'None - every checked rule has matching data.' : 'Not checked in this report.'}</div>`) + `</div>`
    + `<div class="panel half"><h2>Cloud collectors <span class="note">(${ccError ? 'not available' : `${cc.length - ccBad.length} of ${cc.length} healthy`})</span></h2>`
    + `<p class="sub">Cloud-to-cloud collection. Silent means no logs were received for 24 hours.</p>`
    + (cc.length ? `<div class="table-wrap"><table class="data-table sortable"><thead><tr><th>Collector</th><th>Vendor</th><th>Site</th><th>Last log</th><th>Health</th></tr></thead><tbody>${ccRows}</tbody></table></div>`
       : `<div class="footer-note">${ccError ? 'Not available - the API key does not have Cloud Collector access.' : 'No cloud collectors returned.'}</div>`) + `</div>`
    + `</div>`
    + `<div class="grid"><div class="panel"><details><summary><h2 style="display:inline">How this was worked out</h2></summary>`
    + `<ul class="notes" style="margin-top:10px">${notes.map(n => `<li>${n}</li>`).join('')}</ul></details></div></div>`;
}

function filterSurface(query) {
  const q = (query || '').toLowerCase().trim();
  document.querySelectorAll('#surfaceView table.surface-tbl tbody tr').forEach(row => {
    row.style.display = row.innerText.toLowerCase().includes(q) ? '' : 'none';
  });
}

/* ---------- Click-to-sort for every data table ---------- */
document.addEventListener('click', e => {
  const th = e.target.closest('table.data-table thead th');
  if (!th) return;
  const table = th.closest('table');
  const idx = Array.from(th.parentNode.children).indexOf(th);
  const asc = !(th.dataset.sort === 'asc');
  table.querySelectorAll('thead th').forEach(h => { delete h.dataset.sort; });
  th.dataset.sort = asc ? 'asc' : 'desc';
  const value = row => {
    const cell = row.children[idx];
    if (!cell) return '';
    if (cell.dataset.v !== undefined) {
      const n = Number(cell.dataset.v);
      return Number.isNaN(n) ? cell.dataset.v : n;
    }
    const text = cell.innerText.trim();
    const n = Number(text.replace(/,/g, '').replace(/%$/, ''));
    return text !== '' && !Number.isNaN(n) ? n : text.toLowerCase();
  };
  const body = table.tBodies[0];
  const rows = Array.from(body.rows);
  rows.sort((a, b) => {
    const x = value(a), y = value(b);
    const r = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y));
    return asc ? r : -r;
  });
  rows.forEach(r => body.appendChild(r));
});

function openProduct(i) {
  const p = SURFACE.products[i];
  const ruleRows = p.rules.map(r => {
    const info = SURFACE.rules[r] || {techniques: []};
    return `<tr><td>${escHtml(r)}</td><td><span class="tag s-${RULE_CLASS[info.status] || 'none'}">${escHtml(RULE_LABEL[info.status] || info.status || '')}</span></td>`
      + `<td>${info.last ? escHtml(info.last) : '<span class="note">never</span>'}</td>`
      + `<td>${info.triggers ? info.triggers.toLocaleString() : '<span class="note">0</span>'}</td>`
      + `<td style="font-family:var(--mono)">${info.techniques.map(t => escHtml(t.id)).join(', ') || '-'}</td></tr>`;
  }).join('');
  const techs = p.techniques.map(id => {
    const pid = id.split('.')[0], ok = p.validatedTechniques.includes(id);
    return `<tr data-tech="${escHtml(pid)}"><td style="font-family:var(--mono)">${escHtml(id)}</td><td>${escHtml((PARENTS[pid] || {}).name || '')}</td>`
      + `<td><span class="tag ${ok ? 's-validated' : 's-unvalidated'}">${ok ? 'Validated by this source' : 'Not proven'}</span></td></tr>`;
  }).join('');
  document.getElementById('modal').innerHTML =
      `<button class="xbtn" onclick="closeModal()" aria-label="Close">&times;</button>`
    + `<div class="ptitle">${escHtml(p.product)}</div>`
    + `<div class="pid">${escHtml(p.vendor || '')}${p.vendor ? ' &bull; ' : ''}${p.events.toLocaleString()} events in ${SURFACE.windowDays} days`
    + (p.collectors.length ? ' &bull; collectors: ' + escHtml(p.collectors.join(', ')) : '') + `</div>`
    + ((p.categories || []).length ? `<div class="pid">Category: ${escHtml(p.categories.join(', '))}</div>` : '')
    + ((p.platforms || []).length ? `<div class="pid">Platform: ${escHtml(p.platforms.join(', '))}</div>` : '')
    + `<div class="row"><span class="tag ${SURFACE_TAG[p.status]}">${escHtml(p.status)}</span><span class="note">${escHtml(SURFACE_HELP[p.status])}</span></div>`
    + `<h4>Correlation rules using this source (${p.rules.length})</h4>`
    + (ruleRows ? `<div class="table-wrap" style="max-height:none"><table class="data-table"><thead><tr><th>Rule</th><th>Status</th><th>Last fired</th><th>Triggers (${SURFACE.triggerDays}d)</th><th>Techniques</th></tr></thead><tbody>${ruleRows}</tbody></table></div>`
                : '<div class="note">No enabled correlation rule uses this data. Consider content for it, or whether it is needed.</div>')
    + ((p.vendorRules || []).length ? `<h4>Rules that filter on vendor ${escHtml(p.vendor)} - may apply (${p.vendorRules.length})</h4>`
       + `<div class="note">These rules match on the vendor rather than the product, so they may or may not use this source: `
       + p.vendorRules.map(escHtml).join(', ') + '</div>' : '')
    + `<h4>Techniques this source supports (${p.validatedTechniques.length}/${p.techniques.length} validated)</h4>`
    + (techs ? `<div class="table-wrap" style="max-height:none"><table class="data-table"><tbody>${techs}</tbody></table></div>` : '<div class="note">None.</div>');
  closePop();
  document.getElementById('overlay').classList.add('open');
}

['focusView', 'surfaceView'].forEach(id => document.getElementById(id).addEventListener('click', e => {
  const prod = e.target.closest('tr[data-product]');
  if (prod) { openProduct(Number(prod.dataset.product)); return; }
  const tech = e.target.closest('[data-tech]');
  if (tech && POS[tech.dataset.tech]) {
    current = {ci: POS[tech.dataset.tech].ci, ti: POS[tech.dataset.tech].ti, si: undefined};
    openModal();
  }
}));

/* ---------- Rules tab: every correlation rule, its health, MITRE tags and data sources ---------- */
const RULES = JSON.parse(document.getElementById('rulesData').textContent);
const RULE_TAG = {Active: 's-validated', Quiet: 's-quiet', NeverFired: 's-unvalidated', Unknown: 's-unvalidated',
                  AutoDisabled: 's-bad', Disabled: 's-none'};
const RULE_STATUS_LABEL = {Active: 'Active', Quiet: 'Gone quiet', NeverFired: 'Never fired', Unknown: 'Unknown',
                           AutoDisabled: 'Auto-disabled', Disabled: 'Disabled'};
const RULE_VIEWS = {
  enabled:  {label: 'All enabled',   test: r => r.enabled},
  active:   {label: 'Active',        test: r => r.status === 'Active'},
  quiet:    {label: 'Gone quiet',    test: r => r.status === 'Quiet'},
  never:    {label: 'Never fired',   test: r => r.status === 'NeverFired' || r.status === 'Unknown'},
  untagged: {label: 'No MITRE tag',  test: r => r.enabled && !r.techniques.length},
  issues:   {label: 'Has issues',    test: r => r.issues.length > 0},
  auto:     {label: 'Auto-disabled', test: r => r.status === 'AutoDisabled'},
  disabled: {label: 'Disabled',      test: r => !r.enabled && r.status !== 'AutoDisabled'},
  all:      {label: 'All rules',     test: r => true},
};
let ruleView = 'enabled';
// Problems first: quiet (most recently stopped first), never fired (oldest first), then active (busiest first)
const RULE_ORDER = {AutoDisabled: 0, Quiet: 1, NeverFired: 2, Unknown: 3, Active: 4, Disabled: 5};
function ruleSort(a, b) {
  return (RULE_ORDER[a.status] ?? 9) - (RULE_ORDER[b.status] ?? 9)
    || (a.status === 'Quiet' ? (a.days ?? 1e9) - (b.days ?? 1e9) : 0)
    || (a.status === 'NeverFired' ? (b.age ?? 0) - (a.age ?? 0) : 0)
    || (b.times ?? 0) - (a.times ?? 0)
    || a.name.localeCompare(b.name);
}
function setRuleView(v) { ruleView = v; renderRules(); }

function renderRules() {
  const root = document.getElementById('rulesView');
  const enabled = RULES.filter(r => r.enabled);
  const n = v => RULES.filter(RULE_VIEWS[v].test).length;
  const testMode = enabled.filter(r => r.testMode).length;
  const ruleCard = (view, label, value, hint, tone) =>
    `<div class="card span2 clickable${ruleView === view ? ' selected' : ''}" onclick="setRuleView('${view}')" title="Show these rules">`
    + `<div class="label">${escHtml(label)}</div><div class="value ${tone}">${value}</div><div class="hint">${hint}</div></div>`;
  const list = RULES.filter(RULE_VIEWS[ruleView].test).sort(ruleSort);
  const chips = (items, max) => items.length
    ? items.slice(0, max).map(x => `<span class="mini">${escHtml(x)}</span>`).join(' ') + (items.length > max ? ` <span class="note">+${items.length - max}</span>` : '')
    : '<span class="note">-</span>';
  const rows = list.map(r => {
    const i = RULES.indexOf(r);
    return `<tr data-rule="${i}"><td data-v="${escHtml(r.name.toLowerCase())}"><strong>${escHtml(r.name)}</strong>`
      + `<div class="note">${escHtml(r.severity || '')}${r.testMode ? ' &bull; test mode' : ''}</div></td>`
      + `<td data-v="${RULE_ORDER[r.status] ?? 9}"><span class="tag ${RULE_TAG[r.status] || 's-none'}">${escHtml(RULE_STATUS_LABEL[r.status] || r.status)}</span></td>`
      + `<td data-v="${r.days ?? 1e9}">${r.last ? escHtml(r.last.slice(0, 10)) + `<div class="note">${r.days}d ago</div>` : '<span class="note">never</span>'}</td>`
      + `<td data-v="${r.times ?? 0}">${r.times ? Number(r.times).toLocaleString() : '<span class="note">0</span>'}</td>`
      + `<td data-v="${r.perDay ?? 0}">${r.perDay ? r.perDay : '<span class="note">-</span>'}</td>`
      + `<td data-v="${r.techniques.length}" style="font-family:var(--mono)">${chips(r.techniques.map(t => t.id), 4)}</td>`
      + `<td data-v="${r.sources.length}">${chips(r.sources, 2)}</td>`
      + `<td data-v="${r.issues.length}">${r.issues.map(x => `<span class="mini hit">${escHtml(x)}</span>`).join(' ') || '<span class="note">-</span>'}</td></tr>`;
  }).join('');

  root.innerHTML =
      `<div class="grid">`
    + ruleCard('enabled', 'Enabled rules', enabled.length, `${RULES.length} rules in total &bull; ${testMode} in test mode`, '')
    + ruleCard('active', 'Active', n('active'), `fired in the last ${STALE_DAYS} days`, 'good')
    + ruleCard('quiet', 'Gone quiet', n('quiet'), `fired before, but not in ${STALE_DAYS} days - check the log source`, n('quiet') ? 'blue' : 'good')
    + ruleCard('never', 'Never fired', n('never'), 'enabled but never proven - validate them', n('never') ? 'purple' : 'good')
    + ruleCard('untagged', 'No MITRE tag', n('untagged'), "enabled, but don't count towards coverage", n('untagged') ? 'warn' : 'good')
    + ruleCard('auto', 'Auto-disabled', n('auto'), 'switched off by the platform', n('auto') ? 'bad' : 'good')
    + `</div>`
    + `<div class="grid"><div class="panel"><h2>${escHtml(RULE_VIEWS[ruleView].label)} <span class="note">(${list.length})</span></h2>`
    + `<p class="sub">Every correlation rule with its health, MITRE techniques and the data sources it uses. Click a card or a filter to narrow the list, `
    + `a column heading to sort (sort by <em>Per day</em> to find the noisiest rules), or a rule for its details.</p>`
    + `<div class="controls">${Object.keys(RULE_VIEWS).map(v => `<button class="fchip${ruleView === v ? ' on' : ''}" onclick="setRuleView('${v}')">${escHtml(RULE_VIEWS[v].label)} <span class="note">${n(v)}</span></button>`).join('')}</div>`
    + `<div class="controls"><input type="text" placeholder="Find a rule, technique, data source or issue..." oninput="filterTable('tblRules', this.value)">`
    + `<button class="btn btn-export" onclick="exportRulesCsv()">${ICON.download}Export rules</button></div>`
    + (rows ? `<div class="table-wrap" style="max-height:720px"><table class="data-table" id="tblRules"><thead><tr><th>Rule</th><th>Status</th><th>Last fired</th>`
        + `<th>Triggers</th><th>Per day</th><th>MITRE</th><th>Data sources</th><th>Issues</th></tr></thead><tbody>${rows}</tbody></table></div>`
      : '<div class="footer-note">No rules in this view.</div>')
    + `<div class="footer-note">Every table in this report is also saved as a CSV file in the report's run folder.</div></div></div>`;
}

function openRule(i) {
  const r = RULES[i];
  const fact = (label, value) => `<tr><td class="note" style="width:180px">${label}</td><td>${value}</td></tr>`;
  const techRows = r.techniques.map(t => {
    const pid = t.id.split('.')[0];
    const known = !!POS[pid];
    return `<tr${known ? ` data-tech="${escHtml(pid)}"` : ''}><td style="font-family:var(--mono);width:100px">${escHtml(t.id)}</td>`
      + `<td>${escHtml(t.name || '')}${known ? '' : ' <span class="mini hit">not in the current ATT&amp;CK list</span>'}</td>`
      + `<td style="width:130px">${known ? `<span class="tag s-${view(PARENTS[pid]).status}">${LABEL[view(PARENTS[pid]).status]}</span>` : ''}</td></tr>`;
  }).join('');
  document.getElementById('modal').innerHTML =
      `<button class="xbtn" onclick="closeModal()" aria-label="Close">&times;</button>`
    + `<div class="ptitle">${escHtml(r.name)}</div>`
    + `<div class="row"><span class="tag ${RULE_TAG[r.status] || 's-none'}">${escHtml(RULE_STATUS_LABEL[r.status] || r.status)}</span>`
    + (r.testMode ? '<span class="mini">test mode</span>' : '') + r.issues.map(x => `<span class="mini hit">${escHtml(x)}</span>`).join('') + `</div>`
    + `<div class="table-wrap" style="max-height:none"><table class="data-table"><tbody>`
    + fact('Last fired', r.last ? `${escHtml(r.last)} <span class="note">(${r.days} days ago)</span>` : 'never')
    + fact('Triggers (lifetime)', r.times !== null ? Number(r.times).toLocaleString() : '-')
    + fact('Suppressed', r.suppressed !== null ? `${Number(r.suppressed).toLocaleString()}${r.suppressedPct !== null ? ` (${r.suppressedPct}%)` : ''}` : '-')
    + fact('Average per day', r.perDay ?? '-')
    + fact('Severity', escHtml(r.severity || '-'))
    + fact('Created', r.created ? `${escHtml(r.created.slice(0, 10))} <span class="note">(${r.age} days ago)</span>` : '-')
    + fact('Author', escHtml(r.author || '-'))
    + fact('Data sources', r.sources.length ? r.sources.map(escHtml).join(', ') : '<span class="note">not linked to a data source</span>')
    + `</tbody></table></div>`
    + `<h4>MITRE techniques (${r.techniques.length})</h4>`
    + (techRows ? `<div class="table-wrap" style="max-height:none"><table class="data-table"><tbody>${techRows}</tbody></table></div>`
       : '<div class="note">This rule has no MITRE tags, so it does not count towards coverage. Add the tactic and technique in the rule\\'s MITRE field.</div>');
  closePop();
  document.getElementById('overlay').classList.add('open');
}

document.getElementById('rulesView').addEventListener('click', e => {
  const row = e.target.closest('tr[data-rule]');
  if (row) openRule(Number(row.dataset.rule));
});

function exportRulesCsv() {
  const list = RULES.filter(RULE_VIEWS[ruleView].test).sort(ruleSort);
  const head = ['rule', 'status', 'enabled', 'testMode', 'severity', 'lastFired', 'daysSinceLastFired', 'triggers', 'suppressed',
                'perDay', 'created', 'techniques', 'dataSources', 'issues', 'author'];
  const lines = [head.join(',')];
  list.forEach(r => lines.push([r.name, RULE_STATUS_LABEL[r.status] || r.status, r.enabled, r.testMode, r.severity, r.last, r.days ?? '',
    r.times ?? '', r.suppressed ?? '', r.perDay ?? '', r.created, r.techniques.map(t => t.id).join('; '), r.sources.join('; '),
    r.issues.join('; '), r.author].map(csvCell).join(',')));
  downloadCsv(lines, CSV_NAME.replace('attack_matrix', 'rules' + (ruleView === 'enabled' ? '' : '_' + ruleView)));
}

/* ---------- Tailor dialog ---------- */
function openSetup(first) {
  if (!ATTACK) return;
  DRAFT = {sector: FILTER.sector, platforms: FILTER.platforms.slice(), onlySector: FILTER.onlySector};
  renderSetup(first);
  closePop();
  document.getElementById('overlay').classList.add('open');
}
function renderSetup(first) {
  const sectorBtn = (name, label, sub) => `<button class="choice${DRAFT.sector === name ? ' on' : ''}" onclick="DRAFT.sector='${escHtml(name)}'; renderSetup(${first})">`
    + `${escHtml(label)}${sub ? `<small>${sub}</small>` : ''}</button>`;
  const presetOn = p => p.platforms.length === DRAFT.platforms.length && p.platforms.every(x => DRAFT.platforms.includes(x));
  document.getElementById('modal').innerHTML =
      `<button class="xbtn" onclick="${first ? 'skipSetup()' : 'closeModal()'}" aria-label="Close">&times;</button>`
    + `<div class="ptitle">Tailor this report</div>`
    + `<p class="desc">Choose your sector and the platforms in your environment. Techniques that can't apply to your platforms are hidden `
    + `and left out of the score, and techniques used by threat groups that target your sector are highlighted.</p>`
    + `<h4>Your sector</h4><div class="choice-grid">${sectorBtn('', 'No sector', 'Show all techniques equally')}`
    + ATTACK.sectors.map(s => sectorBtn(s.name, s.name, `${s.groups} threat groups`)).join('') + `</div>`
    + `<h4>Platforms in your environment</h4>`
    + `<div class="presets">${PRESETS.map((p, i) => `<button class="btn ${presetOn(p) ? 'btn-primary' : 'btn-outline'}" onclick="DRAFT.platforms=PRESETS[${i}].platforms.filter(x => ALL_PLATFORMS.includes(x)); renderSetup(${first})">${escHtml(p.name)}</button>`).join('')}</div>`
    + `<div class="choice-grid">${ALL_PLATFORMS.map(p => `<label class="check"><input type="checkbox" ${DRAFT.platforms.includes(p) ? 'checked' : ''} `
      + `onchange="togglePlatform('${escHtml(p)}', this.checked, ${first})">${escHtml(p)}</label>`).join('')}</div>`
    + `<h4>Focus</h4><label class="check" style="${DRAFT.sector ? '' : 'opacity:.5'}"><input type="checkbox" ${DRAFT.onlySector ? 'checked' : ''} ${DRAFT.sector ? '' : 'disabled'} `
    + `onchange="DRAFT.onlySector=this.checked">Only show techniques used by threat groups that target my sector</label>`
    + `<p class="note" style="margin-top:14px">Platforms and threat groups come from MITRE ATT&amp;CK v${escHtml(ATTACK.version)}. MITRE does not tag groups by sector, `
    + `so sectors are matched from keywords in each group's description - open any technique to see the groups behind its count. PRE covers pre-attack `
    + `techniques (reconnaissance and resource development) that apply to every organisation.</p>`
    + `<div class="actions"><button class="btn btn-secondary" onclick="${first ? 'skipSetup()' : 'closeModal()'}">${first ? 'Skip' : 'Cancel'}</button>`
    + `<button class="btn btn-primary" onclick="applySetup()">Apply</button></div>`;
}
function togglePlatform(p, on, first) {
  DRAFT.platforms = on ? [...new Set([...DRAFT.platforms, p])] : DRAFT.platforms.filter(x => x !== p);
  renderSetup(first);
}
function applySetup() {
  if (!DRAFT.platforms.length) { alert('Select at least one platform.'); return; }
  FILTER = {sector: DRAFT.sector, platforms: ALL_PLATFORMS.filter(p => DRAFT.platforms.includes(p)),
            onlySector: DRAFT.onlySector && !!DRAFT.sector, hidden: FILTER.hidden, showHidden: FILTER.showHidden, saved: true};
  saveFilter();
  closeModal();
  renderMatrix();
}
function skipSetup() {
  FILTER.saved = true;
  saveFilter();
  closeModal();
}

/* ---------- Popover ---------- */
function ruleCounts(rules) {
  const active = rules.filter(r => r.status === 'Active').length;
  return `${rules.length} rule${rules.length === 1 ? '' : 's'}` + (rules.length ? ` &bull; ${active} active` : '');
}
function threatStats(t) {
  if (!ATTACK) return '';
  const total = (t.grp || []).length;
  const sector = sectorGroups(t).length;
  return `<div class="plabel" style="margin-top:14px">Threat</div><div class="pstats">`
    + `<span class="${total ? '' : 'muted'}">${ICON.target}${total} threat group${total === 1 ? '' : 's'} use this</span>`
    + (FILTER.sector ? `<span class="${sector ? 'hot' : 'muted'}">${sector} target ${escHtml(FILTER.sector)}</span>` : '') + `</div>`;
}
function openPop(tile, ci, ti, si) {
  const t = lookup(ci, ti, si);
  const v = view(t);
  const isSub = si !== undefined;
  current = {ci, ti, si};
  const subs = isSub ? [] : t.subs.filter(platformOk);
  const subLine = isSub ? '' :
    `<span class="${subs.length ? '' : 'muted'}">${ICON.subs}${subs.filter(s => s.status !== 'none').length}/${subs.length} sub-techniques covered</span>`;
  const pop = document.getElementById('pop');
  pop.innerHTML =
      `<button class="xbtn" onclick="closePop()" aria-label="Close">&times;</button>`
    + `<div class="ptitle">${escHtml(isSub ? t.fullName : t.name)}</div>`
    + `<div class="pid">${escHtml(t.id)} &bull; ${escHtml(MATRIX[ci].id)} ${escHtml(MATRIX[ci].name)}</div>`
    + barHtml(v.score, true)
    + (t.plat && t.plat.length ? `<div class="pplat">${ICON.platform}${t.plat.map(escHtml).join(' &bull; ')}</div>` : '')
    + (t.desc ? `<div class="pdesc">${escHtml(t.desc)}</div>` : '')
    + `<div class="plabel">Coverage</div>`
    + `<div class="pstats"><span>${ICON.shield}${v.score}</span><span class="tag s-${v.status}">${LABEL[v.status]}${v.viaSub ? ' via sub-technique' : ''}</span>`
    + `<span>${ICON.rules}${ruleCounts(t.rules)}</span>${subLine}</div>`
    + threatStats(t)
    + (!isSub && hiddenReason(t) ? `<div class="pplat" style="margin:12px 0 0">${ICON.eyeOff}${escHtml(hiddenReason(t))} - not counted in the score</div>` : '')
    + `<div class="pactions">`
    + (isSub ? '' : `<button class="btn btn-ghost" onclick="toggleHidden('${escHtml(t.id)}')" title="${isManuallyHidden(t.id) ? 'Unhide' : 'Hide'} this technique (hidden techniques are left out of the score)">`
       + `${isManuallyHidden(t.id) ? ICON.eye : ICON.eyeOff}</button>`)
    + (t.link ? `<a class="btn btn-ghost" href="${escHtml(t.link)}" target="_blank" rel="noopener" title="Open on attack.mitre.org">${ICON.ext}MITRE ATT&amp;CK</a>` : '')
    + `<button class="btn btn-primary" onclick="openModal()">See Details</button></div>`;

  if (selectedTile) selectedTile.classList.remove('sel');
  selectedTile = tile;
  tile.classList.add('sel');

  pop.classList.add('open');
  positionPop();
}
function positionPop() {
  const pop = document.getElementById('pop');
  if (!selectedTile || !pop.classList.contains('open')) return;
  const r = selectedTile.getBoundingClientRect();
  const w = pop.offsetWidth, h = pop.offsetHeight, gap = 8;
  let left = r.right + gap;
  if (left + w > window.innerWidth - gap) left = r.left - w - gap;
  left = Math.max(gap, Math.min(left, window.innerWidth - w - gap));
  let top = Math.max(gap, Math.min(r.top, window.innerHeight - h - gap));
  pop.style.left = (left + window.scrollX) + 'px';
  pop.style.top = (top + window.scrollY) + 'px';
}
function closePop() {
  document.getElementById('pop').classList.remove('open');
  if (selectedTile) selectedTile.classList.remove('sel');
  selectedTile = null;
}

/* ---------- Details modal ---------- */
function rulesTable(rules) {
  if (!rules.length) return '<div class="note">No rules mapped directly to this technique.</div>';
  const order = {Active: 0, Quiet: 1, NeverFired: 2, Unknown: 3};
  const rows = [...rules].sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9) || a.name.localeCompare(b.name))
    .map(r => `<tr><td>${escHtml(r.name)}</td><td><span class="tag s-${RULE_CLASS[r.status] || 'none'}">${escHtml(RULE_LABEL[r.status] || r.status)}</span></td>`
      + `<td>${r.last ? escHtml(r.last) : '<span class="note">never</span>'}</td></tr>`).join('');
  return `<div class="table-wrap" style="max-height:none"><table class="data-table"><thead><tr><th>Rule</th><th>Status</th><th>Last fired</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}
function groupList(t) {
  if (!ATTACK) return '';
  const idx = t.grp || [];
  if (!idx.length) return `<h4>Threat groups</h4><div class="note">No MITRE ATT&amp;CK group is recorded as using this technique.</div>`;
  const hits = new Set(sectorGroups(t));
  const sorted = [...idx].sort((a, b) => (hits.has(b) - hits.has(a)) || ATTACK.groups[a].name.localeCompare(ATTACK.groups[b].name));
  return `<h4>Threat groups using this technique (${idx.length}${FILTER.sector ? `, ${hits.size} target ${escHtml(FILTER.sector)}` : ''})</h4>`
    + `<div class="grouplist">${sorted.map(i => {
        const g = ATTACK.groups[i];
        const title = g.sectors.length ? 'Targets: ' + g.sectors.join(', ') : 'No sector keywords in description';
        return `<a class="${hits.has(i) ? 'hit' : ''}" href="${escHtml(g.url)}" target="_blank" rel="noopener" title="${escHtml(title)}">${escHtml(g.name)}</a>`;
      }).join('')}</div>`;
}
function openModal() {
  if (!current) return;
  const {ci, ti, si} = current;
  const t = lookup(ci, ti, si);
  const v = view(t);
  const isSub = si !== undefined;
  let subs = '';
  const subList = isSub ? [] : t.subs.filter(platformOk);
  if (subList.length) {
    const rows = subList.map(s => `<tr><td style="font-family:var(--mono)">${escHtml(s.id)}</td>`
      + `<td>${s.link ? `<a href="${escHtml(s.link)}" target="_blank" rel="noopener">${escHtml(s.name)}</a>` : escHtml(s.name)}</td>`
      + `<td><span class="tag s-${s.status}">${LABEL[s.status]}</span></td><td>${s.score}</td>`
      + `<td>${s.rules.length ? s.rules.map(r => escHtml(r.name)).join('<br>') : '<span class="note">-</span>'}</td></tr>`).join('');
    subs = `<h4>Sub-techniques (${subList.filter(s => s.status !== 'none').length}/${subList.length} covered)</h4>`
      + `<div class="table-wrap" style="max-height:none"><table class="data-table"><thead><tr><th>ID</th><th>Sub-technique</th><th>Status</th><th>Score</th><th>Rules</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }
  const parentId = isSub ? MATRIX[ci].techs[ti].id : t.id;
  const tactics = MATRIX.filter(c => c.techs.some(x => x.id === parentId)).map(c => `${c.id} ${c.name}`);
  document.getElementById('modal').innerHTML =
      `<button class="xbtn" onclick="closeModal()" aria-label="Close">&times;</button>`
    + `<div class="ptitle">${escHtml(isSub ? t.fullName : t.name)}</div>`
    + `<div class="pid">${escHtml(t.id)}${isSub ? ' &bull; sub-technique of ' + escHtml(parentId) : ''} &bull; ${tactics.map(escHtml).join(', ')}</div>`
    + (t.plat && t.plat.length ? `<div class="pid">Platforms: ${t.plat.map(escHtml).join(', ')}</div>` : '')
    + `<div class="row"><span class="num">${v.score}</span>${barHtml(v.score, true)}<span class="tag s-${v.status}">${LABEL[v.status]}${v.viaSub ? ' via sub-technique' : ''}</span></div>`
    + (t.desc ? `<p class="desc">${escHtml(t.desc)}</p>` : '')
    + (t.link ? `<a class="btn btn-ghost" style="padding-left:0" href="${escHtml(t.link)}" target="_blank" rel="noopener">${ICON.ext}View ${escHtml(t.id)} on attack.mitre.org</a>` : '')
    + `<h4>Correlation rules (${t.rules.length})</h4>${rulesTable(t.rules)}`
    + subs
    + groupList(t);
  closePop();
  document.getElementById('overlay').classList.add('open');
}
function closeModal() { document.getElementById('overlay').classList.remove('open'); }

function openScoreHelp() {
  const fmt = n => Number(n).toLocaleString();
  const scope = filtersActive()
    ? `<p class="note">Filters are applied, so only the ${fmt(lastScore.techniques)} techniques in scope are counted - the same as hidden techniques in the Outcomes Navigator.</p>` : '';
  document.getElementById('modal').innerHTML =
      `<button class="xbtn" onclick="closeModal()" aria-label="Close">&times;</button>`
    + `<div class="ptitle">MITRE ATT&amp;CK Coverage Score Explanation</div>`
    + `<p class="desc">The overall score is calculated the same way as the Exabeam Outcomes Navigator score: the scores of all visible (unhidden) techniques `
    + `are added up, then divided by the number of those techniques. The result is rounded to the nearest whole number.</p>`
    + scope
    + `<table class="factors"><thead><tr><th>Factor</th><th>Value</th></tr></thead><tbody>`
    + `<tr><td>Sum of scores of all ${filtersActive() ? 'in-scope' : 'unhidden'} techniques</td><td>${fmt(lastScore.sum)}</td></tr>`
    + `<tr><td>Total number of ${filtersActive() ? 'in-scope' : 'unhidden'} techniques</td><td>${fmt(lastScore.techniques)}</td></tr>`
    + `<tr class="total"><td>Total average MITRE ATT&amp;CK Coverage Score</td><td>${lastScore.score}</td></tr>`
    + `</tbody></table>`
    + `<h4>How each technique is scored</h4>`
    + `<p class="desc" style="margin-top:0">Unlike the Outcomes Navigator, which scores the data and content available for a technique, this report scores `
    + `whether the correlation rules mapped to it actually fire:</p>`
    + `<table class="factors"><thead><tr><th>Technique state</th><th>Score</th></tr></thead><tbody>`
    + `<tr><td><span class="tag s-validated">Validated</span> a mapped rule fired in the last ${STALE_DAYS} days</td><td>75 - 100</td></tr>`
    + `<tr><td><span class="tag s-quiet">Quiet</span> mapped rules fired before, but not recently</td><td>50 - 74</td></tr>`
    + `<tr><td><span class="tag s-unvalidated">Unvalidated</span> mapped rules have never fired</td><td>20 - 49</td></tr>`
    + `<tr><td><span class="tag s-none">Not covered</span> no enabled rule is mapped</td><td>0</td></tr>`
    + `</tbody></table>`
    + `<p class="desc">Each additional rule in the same state adds 5 points within its band. A parent technique takes the best score of its own rules `
    + `and its sub-techniques' rules${rollup() ? '' : ' (currently switched off with the "Count sub-technique coverage" toggle)'}. Only enabled correlation rules are counted.</p>`
    + `<div class="actions"><button class="btn btn-primary" onclick="closeModal()">Close</button></div>`;
  closePop();
  document.getElementById('overlay').classList.add('open');
}

/* ---------- Events ---------- */
document.getElementById('matrix').addEventListener('click', e => {
  const exp = e.target.closest('[data-expand]');
  if (exp) {
    e.stopPropagation();
    const id = exp.dataset.expand;
    expanded.has(id) ? expanded.delete(id) : expanded.add(id);
    renderMatrix();
    return;
  }
  const tile = e.target.closest('.tile');
  if (!tile) return;
  e.stopPropagation();
  if (tile === selectedTile) { closePop(); return; }
  const [ci, ti, si] = tile.dataset.key.split(':').map(Number);
  openPop(tile, ci, ti, Number.isNaN(si) ? undefined : si);
});
document.getElementById('matrix').addEventListener('scroll', closePop);
document.addEventListener('click', e => { if (!e.target.closest('#pop')) closePop(); });
window.addEventListener('resize', positionPop);
document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeModal(); closePop(); } });

/* ---------- CSV export (follows the current filters) ---------- */
function csvCell(v) {
  const s = String(v ?? '');
  return /[",\\r\\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
function exportCsv() {
  const data = JSON.parse(document.getElementById('matrixCsv').textContent);
  const col = name => data.columns.indexOf(name);
  const [cTac, cTech, cParent] = [col('tacticId'), col('techniqueId'), col('parentTechniqueId')];
  const byId = {};
  MATRIX.forEach(c => c.techs.forEach(t => { byId[t.id] = t; t.subs.forEach(s => { byId[s.id] = s; }); }));
  const keep = row => {
    const parent = row[cParent];
    const t = byId[parent || row[cTech]];
    if (!t || !inScope(t)) return false;
    return parent ? platformOk(byId[row[cTech]] || {}) : true;
  };
  const columns = data.columns.slice();
  const sectorCol = FILTER.sector ? [`groupsTargeting${FILTER.sector.replace(/[^A-Za-z]/g, '')}`, 'sectorThreatGroups'] : [];
  const lines = [columns.concat(sectorCol).map(csvCell).join(',')];
  data.rows.filter(keep).forEach(row => {
    const extra = [];
    if (FILTER.sector) {
      const g = sectorGroups(byId[row[cTech]] || {});
      extra.push(g.length, g.map(i => ATTACK.groups[i].name).sort().join('; '));
    }
    lines.push(row.concat(extra).map(csvCell).join(','));
  });
  const blob = new Blob(['\\ufeff' + lines.join('\\r\\n') + '\\r\\n'], {type: 'text/csv;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filtersActive() || FILTER.sector ? CSV_NAME.replace(/\\.csv$/, '_tailored.csv') : CSV_NAME;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 0);
}

/* ---------- Tabs + tables ---------- */
function showTab(name) {
  if (!document.getElementById('tab-' + name)) name = 'coverage';
  closePop();
  document.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('.tabpane').forEach(p => p.classList.toggle('active', p.id === 'tab-' + name));
  try { history.replaceState(null, '', '#' + name); } catch (e) {}
}
document.querySelectorAll('.tab').forEach(b => b.addEventListener('click', () => showTab(b.dataset.tab)));

function filterTable(tableId, query) {
  const q = (query || '').toLowerCase().trim();
  const table = document.getElementById(tableId);
  if (!table || !table.tBodies || !table.tBodies[0]) return;
  for (const row of table.tBodies[0].rows) {
    row.style.display = row.innerText.toLowerCase().includes(q) ? '' : 'none';
  }
}

/* ---------- Dark / light theme (dark by default; remembered per viewer) ---------- */
const THEME_KEY = 'exabeamMitreReport.theme';
function renderThemeButton() {
  const light = document.documentElement.getAttribute('data-theme') === 'light';
  document.getElementById('themeBtn').innerHTML = light
    ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>Dark mode'
    : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>Light mode';
}
function toggleTheme() {
  const light = document.documentElement.getAttribute('data-theme') !== 'light';
  if (light) document.documentElement.setAttribute('data-theme', 'light');
  else document.documentElement.removeAttribute('data-theme');
  try { localStorage.setItem(THEME_KEY, light ? 'light' : 'dark'); } catch (e) {}
  renderThemeButton();
}
renderThemeButton();

renderMatrix();
renderSurface();
renderRules();
showTab((location.hash || '#coverage').slice(1));
if (ATTACK && !FILTER.saved) openSetup(true);
</script>
</body>
</html>
"""


def logo_data_uri() -> str:
    """The transparent Exabeam mark as a data URI, so the report needs no separate image file."""
    import base64
    for name in ("logo_mark.png", "logo.png"):
        path = os.path.join(SCRIPT_DIR, "assets", name)
        if os.path.exists(path):
            with open(path, "rb") as f:
                return "data:image/png;base64," + base64.b64encode(f.read()).decode("ascii")
    return ""


def build_html_report(path: str, ctx: dict) -> None:
    k = ctx["kpis"]
    prev_kpis = ctx["prev"]["kpis"] if ctx["prev"] else None
    stale = ctx["stale_days"]

    # Changes since last run
    if ctx["prev"]:
        prev_when = esc(ctx["prev"].get("generatedAt", ""))
        prev_stale = ctx["prev"].get("staleDays")
        threshold_note = ""
        if prev_stale and prev_stale != stale:
            threshold_note = (f'<p class="sub" style="color:var(--warn)"><strong>Note:</strong> the previous run counted a rule as active if it '
                              f'fired within {prev_stale} days; this run uses {stale} days. Some rules change status because of that, not '
                              'because their behaviour changed.</p>')
        changes = ctx["changes"]
        body = to_html_table(changes, "tblChanges") if changes else '<div class="footer-note">Nothing changed.</div>'
        changes_html = f"""
      <div class="panel">
        <h2>Changes since last run ({prev_when})</h2>{threshold_note}
        <p class="sub">Rules that were auto-disabled or stopped firing, and data sources that stopped sending, are listed first - these are the most likely signs that a log source or rule has broken.</p>
        {body}
      </div>"""
        compare_meta = f"<div>Compared with run</div><div>{prev_when}</div>"
        change_count = str(len(changes))
    else:
        changes_html = """
      <div class="panel">
        <h2>Changes since last run</h2>
        <p class="sub">No previous run for this region was found. Run the report again later (for example weekly) to see rules that
        stopped firing, were auto-disabled, and coverage gained or lost.</p>
      </div>"""
        compare_meta = "<div>No previous run to compare with</div>"
        change_count = ""

    # Priority gaps
    priority_html = ""
    if ctx["priorities"]:
        pg = [g for g in ctx["gaps"] if g["issueType"] == "NotCovered" and g["priority"]]
        pg.sort(key=lambda g: priority_sort_key(g["priority"]))
        priority_html = f"""
      <div class="panel">
        <h2>Priority gaps ({len(pg)})</h2>
        <p class="sub">Uncovered techniques from your priority list, highest priority first.</p>
        {to_html_table(pg, "tblPriority", cols=["priority", "techniqueId", "name", "tactics", "coveredViaSubtechnique", "externalLink"])}
      </div>"""

    def embed(value: Any) -> str:
        return json.dumps(value, separators=(",", ":")).replace("</", "<\\/")

    html = HTML_TEMPLATE
    for token, value in {
        "%%REGION%%": esc(ctx["region"]),
        "%%VERSION%%": __version__,
        "%%DEFAULT_SECTOR%%": embed(ctx.get("sector", "")),
        "%%REPORT_ID%%": embed(f"{ctx['region']}-{ctx['generated']}"),
        "%%LOGO_SRC%%": logo_data_uri(),
        "%%GENERATED%%": esc(ctx["generated"]),
        "%%STALE%%": str(stale),
        "%%COMPARE_META%%": compare_meta,
        "%%CHANGE_COUNT%%": change_count,
        "%%CHANGES%%": changes_html,
        "%%PRIORITY_PANEL%%": priority_html,
        "%%RULES_JSON%%": embed(ctx["rules"]),
        "%%MATRIX_CSV_NAME%%": embed(ctx["matrix_csv_name"]),
        "%%PREV_KPIS%%": embed(prev_kpis),
        "%%KPIS%%": embed(k),
        "%%ATTACK_JSON%%": embed(attack_for_html(ctx["attack"])),
        "%%SURFACE_JSON%%": embed(ctx.get("surface")),
        "%%MATRIX_CSV%%": embed(ctx["matrix_csv"]),
        "%%MATRIX_JSON%%": embed(ctx["matrix"]),
    }.items():
        html = html.replace(token, value)

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


# =========================================================
# 10) MAIN
# =========================================================
def resolve_credentials(args: argparse.Namespace) -> tuple[str, str]:
    cid, secret = args.client_id, args.client_secret
    if (not cid or cid == PLACEHOLDER) and sys.stdin.isatty():
        cid = input("Exabeam client ID: ").strip()
    if (not secret or secret == PLACEHOLDER) and sys.stdin.isatty():
        secret = getpass.getpass("Exabeam client secret: ").strip()
    if not cid or cid == PLACEHOLDER or not secret or secret == PLACEHOLDER:
        fail("No API credentials. Set EXABEAM_CLIENT_ID / EXABEAM_CLIENT_SECRET or pass --client-id / --client-secret.")
    return cid, secret


def load_raw(folder: str, name: str) -> Any:
    path = os.path.join(folder, f"raw_{name}.json")
    if not os.path.exists(path):
        fail(f"--replay: {path} not found")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main() -> None:
    args = parse_args()
    region = args.region
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%d_%H%M%SZ")
    generated = now.strftime("%Y-%m-%d %H:%M:%SZ")

    out_root = os.path.abspath(args.out_dir)
    out_dir = os.path.join(out_root, ts)
    os.makedirs(out_dir, exist_ok=True)

    paths = {
        "all_mitre": os.path.join(out_dir, f"all_mitre_techniques_{region}_{ts}.csv"),
        "coverage": os.path.join(out_dir, f"current_coverage_{region}_{ts}.csv"),
        "gaps": os.path.join(out_dir, f"current_gaps_{region}_{ts}.csv"),
        "health": os.path.join(out_dir, f"rule_health_{region}_{ts}.csv"),
        "navigator": os.path.join(out_dir, f"navigator_layer_{region}_{ts}.json"),
        "matrix": os.path.join(out_dir, f"attack_matrix_{region}_{ts}.csv"),
        "html": os.path.join(out_dir, f"mitre_coverage_report_{region}_{ts}.html"),
        "word": os.path.join(out_dir, f"mitre_executive_briefing_{region}_{ts}.docx"),
        "snapshot": os.path.join(out_dir, "snapshot.json"),
    }
    info(f"Exabeam MITRE Coverage Report v{__version__}")
    info(f"Output folder: {out_dir}")

    priorities = load_priorities(args.priority_file)

    # --- Fetch (or replay) raw data ---
    if args.replay:
        info(f"Replaying raw API responses from {args.replay}")
        mitre_raw = load_raw(args.replay, "mitre")
        rules_raw = load_raw(args.replay, "rules")
        export_raw = load_raw(args.replay, "export")
    else:
        if not args.base_url and region not in KNOWN_REGIONS:
            warn(f"'{region}' is not a known Exabeam region ({', '.join(KNOWN_REGIONS)}) - trying it anyway")
        base_url = args.base_url or f"https://api.{region}.exabeam.cloud"
        cid, secret = resolve_credentials(args)
        api = ExabeamApi(base_url, cid, secret)
        info(f"Connecting to {base_url}")
        api.authenticate()
        mitre_raw = api.get_mitre_techniques(args.name_contains)
        rules_raw = api.list_correlation_rules()
        export_raw = None  # fetched below once we know which rules to export

    all_rules = dedupe_rules(normalize_rules_list(rules_raw))
    in_scope = all_rules if args.include_disabled else [r for r in all_rules if is_rule_enabled(r)]
    in_scope_ids = [get_rule_id(r) for r in in_scope if get_rule_id(r)]

    info(f"Rules returned by API: {len(all_rules)}")
    info(f"Rules in scope for coverage: {len(in_scope)}")
    if not in_scope_ids:
        fail("No enabled rule IDs found. Check is_rule_enabled() against your /correlation-rules/v2/rules payload.")

    if export_raw is None:
        export_raw = {"ruleDefinitions": api.export_rule_definitions(in_scope_ids)}
    exported_defs = [d for d in export_raw.get("ruleDefinitions", []) if isinstance(d, dict)]
    info(f"Rule definitions returned by export: {len(exported_defs)}")

    surface_raw = None
    if args.replay:
        surface_path = os.path.join(args.replay, "raw_surface.json")
        if os.path.exists(surface_path):
            with open(surface_path, encoding="utf-8") as f:
                surface_raw = json.load(f)
    elif not args.no_surface:
        surface_raw = collect_attack_surface(api, exported_defs, args.surface_days, not args.no_surface_deep,
                                             args.surface_max_seconds, args.surface_workers, args.stale_days)
        if args.save_raw:
            write_json(os.path.join(out_dir, "raw_surface.json"), surface_raw)

    if args.save_raw and not args.replay:
        write_json(os.path.join(out_dir, "raw_mitre.json"), mitre_raw)
        write_json(os.path.join(out_dir, "raw_rules.json"), rules_raw)
        write_json(os.path.join(out_dir, "raw_export.json"), export_raw)
        info("Saved raw API responses (raw_*.json) - these contain your rule definitions, share with care")

    # --- MITRE universe ---
    all_mitre = flatten_mitre(mitre_raw)
    universe = {r["techniqueId"] for r in all_mitre}

    # --- Rule health ---
    health_all = [build_rule_health(r, now, args.stale_days) for r in all_rules]
    health_by_id = {h["ruleId"]: h for h in health_all if h["ruleId"]}
    if all_rules and all(("lastTriggeredAt" not in r and "timesTriggered" not in r) for r in all_rules):
        warn("The rules API returned no trigger fields (lastTriggeredAt / timesTriggered) - firing status will show as Unknown")

    # --- Coverage + gaps ---
    pairs, missing = match_definitions(in_scope, exported_defs)
    coverage, rule_gaps = build_coverage_and_rule_gaps(pairs, missing, health_by_id)
    tech_status = build_technique_status(all_mitre, coverage)
    attack = load_attack_context(args.attack_cache, args.attack_data)
    if attack:
        info(f"MITRE ATT&CK data: v{attack['version']} ({len(attack['groups'])} threat groups, fetched {attack['fetchedAt']})")
    matrix = build_matrix_data(all_mitre, tech_status, mitre_descriptions(mitre_raw), attack)
    # Same method as the Outcomes Navigator: average technique score across all (parent) techniques
    unique_scores = {t["id"]: t["rolledScore"] for col in matrix for t in col["techs"]}
    score_sum = sum(unique_scores.values())

    unknown_keys = sorted({c["techniqueKey"] for c in coverage if c["techniqueKey"] and c["techniqueKey"] not in universe})
    for tid in unknown_keys:
        rule_names = sorted({c["ruleName"] for c in coverage if c["techniqueKey"] == tid})
        rule_gaps.append({"issueType": "UnknownTechnique", "ruleId": "", "ruleName": "; ".join(rule_names),
                          "notes": f"Rules map to {tid}, which is not in the MITRE technique list "
                                   "(retired or renumbered in a newer ATT&CK release?) - remap these rules"})

    rule_techniques: dict[str, list[str]] = {}
    for c in coverage:
        if c["techniqueKey"] and c["techniqueKey"] not in rule_techniques.setdefault(c["ruleName"], []):
            rule_techniques[c["ruleName"]].append(c["techniqueKey"])
    rule_products = rule_query_products(exported_defs)
    surface = build_attack_surface(surface_raw, health_all, rule_query_products(exported_defs, ("product",)),
                                   rule_query_products(exported_defs, ("vendor",)), rule_techniques,
                                   {r["techniqueId"]: r["name"] for r in all_mitre})

    gaps = build_technique_gaps(all_mitre, tech_status, priorities)
    for g in rule_gaps:
        gaps.append({
            "issueType": g["issueType"], "techniqueId": "", "name": "", "isSubtechnique": "",
            "parentTechniqueId": "", "tactics": "", "externalLink": "", "coveredViaSubtechnique": "",
            "priority": "", "ruleId": g["ruleId"], "ruleName": g["ruleName"],
            "notes": f"ruleId={g['ruleId']} | ruleName={g['ruleName']} | {g['notes']}",
        })

    # --- KPIs ---
    parents = [r for r in all_mitre if not r["isSubtechnique"]]
    subs = [r for r in all_mitre if r["isSubtechnique"]]

    def pct(a: int, b: int) -> float:
        return round(a / b * 100, 1) if b else 0.0

    health_enabled = [h for h in health_all if h["enabled"]]
    count = lambda s: sum(1 for h in health_enabled if h["status"] == s)  # noqa: E731
    parents_covered = sum(1 for r in parents if tech_status[r["techniqueId"]]["status"] != TS_NONE)
    parents_incl = sum(1 for r in parents if tech_status[r["techniqueId"]]["rolled"] != TS_NONE)
    parents_validated = sum(1 for r in parents if tech_status[r["techniqueId"]]["rolled"] == TS_VALIDATED)
    subs_covered = sum(1 for r in subs if tech_status[r["techniqueId"]]["status"] != TS_NONE)

    kpis = {
        "rulesReturned": len(all_rules),
        "enabledRules": len(health_enabled),
        "testModeRules": sum(1 for h in health_enabled if h["testMode"]),
        "parentsTotal": len(parents),
        "parentsCovered": parents_covered,
        "parentsCoveredPct": pct(parents_incl, len(parents)),
        "parentsCoveredInclSubs": parents_incl,
        "parentsValidated": parents_validated,
        "validatedPct": pct(parents_validated, len(parents)),
        "subsTotal": len(subs),
        "subsCovered": subs_covered,
        "subsCoveredPct": pct(subs_covered, len(subs)),
        "rulesActive": count(RS_ACTIVE),
        "rulesQuiet": count(RS_QUIET),
        "rulesNeverFired": count(RS_NEVER),
        "rulesUnknown": count(RS_UNKNOWN),
        "rulesAutoDisabled": sum(1 for h in health_all if h["status"] == RS_AUTO_DISABLED),
        "noMitreTag": sum(1 for g in rule_gaps if g["issueType"] == "NoMitreTag"),
        "exportMissing": sum(1 for g in rule_gaps if g["issueType"] == "ExportMissing"),
        "unknownTechniques": len(unknown_keys),
        "coverageRows": len(coverage),
        "rulesTagged": len({c["ruleId"] or c["ruleName"] for c in coverage}),
        # Exabeam correlation rules are tagged with tactic + technique only, so sub-technique tags are normally absent
        "subTechniqueTags": sum(1 for c in coverage if "." in (c["techniqueKey"] or "")),
        "coverageScore": round(score_sum / len(unique_scores)) if unique_scores else 0,
        "coverageScoreSum": score_sum,
        "coverageScoreTechniques": len(unique_scores),
    }

    # --- Snapshot + comparison ---
    snapshot = {
        "version": 2,
        "region": region,
        "generatedAt": generated,
        "staleDays": args.stale_days,
        "kpis": kpis,
        "techniques": {r["techniqueId"]: {"name": r["name"], "status": tech_status[r["techniqueId"]]["status"]}
                       for r in all_mitre},
        "rules": {h["ruleId"]: {"name": h["ruleName"], "status": h["status"], "enabled": h["enabled"],
                                "lastTriggeredAt": h["lastTriggeredAt"]}
                  for h in health_all if h["ruleId"]},
        "surface": surface_snapshot(surface),
    }

    prev, changes = None, []
    if not args.no_compare:
        prev_path = args.compare
        if prev_path and os.path.isdir(prev_path):
            prev_path = os.path.join(prev_path, "snapshot.json")
        prev_path = prev_path or find_previous_snapshot(out_root, out_dir, region)
        if prev_path:
            try:
                with open(prev_path, encoding="utf-8") as f:
                    prev = json.load(f)
                changes = compare_snapshots(prev, snapshot)
                info(f"Compared with previous run: {prev_path} ({len(changes)} changes)")
            except (OSError, json.JSONDecodeError) as e:
                warn(f"Could not read previous snapshot {prev_path}: {e}")

    # --- Write CSVs / JSON ---
    all_mitre_view = []
    for r in all_mitre:
        t = tech_status[r["techniqueId"]]
        all_mitre_view.append({**r, "status": TS_LABEL[t["status"]],
                               "coveredViaSubtechnique": str(t["viaSub"]) if not r["isSubtechnique"] else "",
                               "ruleCount": len(t["rules"])})

    write_csv(paths["all_mitre"], all_mitre_view,
              ["techniqueId", "name", "isSubtechnique", "parentTechniqueId", "tactics", "externalLink",
               "status", "coveredViaSubtechnique", "ruleCount"])
    write_csv(paths["coverage"], coverage,
              ["ruleId", "ruleName", "enabled", "tacticKey", "tactic", "techniqueKey", "technique",
               "ruleStatus", "lastTriggeredAt", "timesTriggered", "testMode"])
    write_csv(paths["gaps"], gaps,
              ["issueType", "techniqueId", "name", "isSubtechnique", "parentTechniqueId", "tactics", "externalLink",
               "coveredViaSubtechnique", "priority", "ruleId", "ruleName", "notes"])
    health_cols = ["ruleId", "ruleName", "enabled", "status", "testMode", "autoDisabled", "severity",
                   "lastTriggeredAt", "daysSinceLastTrigger", "timesTriggered", "timesSuppressed", "suppressedPct",
                   "createdAt", "ruleAgeDays", "avgTriggersPerDay", "mitreMappings", "author"]
    write_csv(paths["health"], health_all, health_cols)
    write_json(paths["navigator"], build_navigator_layer(all_mitre, tech_status, region, generated))
    matrix_rows = build_matrix_csv_rows(matrix, attack)
    write_csv(paths["matrix"], matrix_rows, MATRIX_CSV_COLUMNS)
    write_json(paths["snapshot"], snapshot)

    # --- Summary tables for the HTML ---
    tactic_rules: dict[tuple, set] = {}
    tactic_rows: dict[tuple, int] = {}
    tech_counts: dict[str, int] = {}
    for c in coverage:
        if c["tacticKey"]:
            key = (c["tacticKey"], c["tactic"])
            tactic_rules.setdefault(key, set()).add(c["ruleId"] or c["ruleName"])
            tactic_rows[key] = tactic_rows.get(key, 0) + 1
        if c["techniqueKey"]:
            tech_counts[c["techniqueKey"]] = tech_counts.get(c["techniqueKey"], 0) + 1
    tactic_summary = sorted(
        [{"tacticKey": tk, "tactic": tn, "uniqueRules": len(rs), "mappingRows": tactic_rows[(tk, tn)]}
         for (tk, tn), rs in tactic_rules.items()],
        key=lambda x: (x["uniqueRules"], x["mappingRows"]), reverse=True)
    name_lookup = {r["techniqueId"]: r["name"] for r in all_mitre}
    tech_counts_rows = [
        {"techniqueKey": tid, "techniqueName": name_lookup.get(tid, ""), "mappingCount": n,
         "status": TS_LABEL[tech_status[tid]["status"]] if tid in tech_status else ""}
        for tid, n in sorted(tech_counts.items(), key=lambda kv: kv[1], reverse=True)
    ]

    # --- One row per rule for the Rules tab ---
    no_tag = {g["ruleName"] for g in rule_gaps if g["issueType"] == "NoMitreTag"}
    not_exported = {g["ruleName"] for g in rule_gaps if g["issueType"] == "ExportMissing"}
    tech_names = {r["techniqueId"]: r["name"] for r in all_mitre}
    tech_names.update({c["techniqueKey"]: c["technique"] for c in coverage if c["techniqueKey"] not in tech_names})
    rule_sources: dict[str, list[str]] = {}
    if surface:
        for p in surface["products"]:
            for r in p["rules"]:
                rule_sources.setdefault(r, []).append(p["product"])
    starved_rules = set(surface["starvedRules"]) if surface else set()
    rules_view = []
    for h in health_all:
        name = h["ruleName"]
        techs = rule_techniques.get(name, [])
        issues = []
        if h["enabled"] and name in no_tag:
            issues.append("No MITRE tag")
        if h["enabled"] and name in not_exported:
            issues.append("Missing from export")
        issues += [f"Retired technique {t}" for t in techs if t in unknown_keys]
        if name in starved_rules:
            issues.append("No matching data")
        num = lambda v: v if isinstance(v, (int, float)) else None  # noqa: E731
        rules_view.append({
            "name": name, "status": h["status"], "enabled": h["enabled"], "testMode": h["testMode"],
            "severity": h["severity"], "last": h["lastTriggeredAt"], "days": num(h["daysSinceLastTrigger"]),
            "times": num(h["timesTriggered"]), "suppressed": num(h["timesSuppressed"]), "suppressedPct": num(h["suppressedPct"]),
            "perDay": num(h["avgTriggersPerDay"]), "created": h["createdAt"], "age": num(h["ruleAgeDays"]), "author": h["author"],
            "techniques": [{"id": t, "name": tech_names.get(t, "")} for t in techs],
            "sources": sorted(set(rule_sources.get(name, []) or rule_products.get(name, [])), key=str.lower),
            "issues": issues,
        })

    # --sector: the starting sector for the HTML report and the threat section of the Word briefing
    sector = ""
    if args.sector:
        sector = next((x for x in SECTOR_PATTERNS if x.lower() == args.sector.strip().lower()), "")
        if not sector:
            warn(f"Unknown --sector '{args.sector}'. Options: {', '.join(SECTOR_PATTERNS)}")

    build_html_report(paths["html"], {
        "sector": sector,
        "rules": rules_view,
        "region": region,
        "generated": generated,
        "stale_days": args.stale_days,
        "kpis": kpis,
        "prev": prev,
        "changes": changes,
        "health_all": sorted(health_all, key=lambda h: (not h["enabled"], h["status"], h["ruleName"].lower())),
        "health_enabled": health_enabled,
        "health_auto_disabled": [h for h in health_all if h["status"] == RS_AUTO_DISABLED],
        "priorities": priorities,
        "gaps": gaps,
        "coverage": coverage,
        "all_mitre_view": all_mitre_view,
        "tactic_summary": tactic_summary,
        "tech_counts": tech_counts_rows,
        "matrix": matrix,
        "matrix_csv": {"columns": MATRIX_CSV_COLUMNS,
                       "rows": [[str(r[c]) if isinstance(r[c], bool) else r[c] for c in MATRIX_CSV_COLUMNS] for r in matrix_rows]},
        "attack": attack,
        "surface": surface,
        "matrix_csv_name": os.path.basename(paths["matrix"]),
    })

    # --- Word executive briefing ---
    word_written = False
    if not args.no_word:
        if build_executive_report is None:
            warn(f"Word briefing skipped - install python-docx (pip install -r requirements.txt): {DOCX_IMPORT_ERROR}")
        else:
            retired_rules = {c["ruleName"] for c in coverage if c["techniqueKey"] in unknown_keys}
            # Transparent mark for light backgrounds (assets/logo.png has a black background for the HTML report)
            logo = os.path.join(SCRIPT_DIR, "assets", "logo_mark.png")
            try:
                build_executive_report(paths["word"], {
                    "region": region, "generated": generated, "stale_days": args.stale_days, "kpis": kpis,
                    "prev": prev, "changes": changes, "matrix": matrix, "attack": attack, "sector": sector,
                    "health_enabled": health_enabled, "rule_products": rule_products,
                    "rule_techniques": rule_techniques, "retired_ids": unknown_keys, "retired_rule_count": len(retired_rules),
                    "logo": logo if os.path.exists(logo) else None,
                    "version": __version__,
                    "surface": surface,
                })
                word_written = True
            except Exception as e:  # the briefing must never stop the main report
                warn(f"Word briefing could not be generated: {type(e).__name__}: {e}")

    for label, key in (("All techniques", "all_mitre"), ("Coverage", "coverage"), ("Gaps", "gaps"),
                       ("Rule health", "health"), ("ATT&CK matrix", "matrix"), ("Navigator layer", "navigator"),
                       ("HTML report", "html"), ("Word briefing", "word")):
        if key != "word" or word_written:
            info(f"{label + ':':17} {paths[key]}")

    print(
        f"\n{ANSI_GREEN}[SUMMARY]{ANSI_RESET} "
        f"Enabled rules={kpis['enabledRules']} | "
        f"Parent techniques covered={kpis['parentsCoveredInclSubs']}/{kpis['parentsTotal']} ({kpis['parentsCoveredPct']}%) | "
        f"Validated={kpis['parentsValidated']} ({kpis['validatedPct']}%) | "
        f"Active={kpis['rulesActive']} Quiet={kpis['rulesQuiet']} NeverFired={kpis['rulesNeverFired']} "
        f"AutoDisabled={kpis['rulesAutoDisabled']} | "
        f"No MITRE tag={kpis['noMitreTag']} | Missing from export={kpis['exportMissing']}"
    )
    if changes:
        print(f"\n{ANSI_GREEN}[CHANGES]{ANSI_RESET} since {prev.get('generatedAt', 'previous run')}:")
        for c in changes[:15]:
            print(f" - {c['change']}: {c['item']} ({c['from']} -> {c['to']})")
        if len(changes) > 15:
            print(f" ... and {len(changes) - 15} more (see HTML report)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(130)
