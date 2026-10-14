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
import shutil
import sys
from datetime import datetime, timezone
from typing import Any

import requests

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
API_TIMEOUT_SECONDS = 60

# Optional MITRE filter ("" = everything)
NAME_CONTAINS = ""

# Export endpoint max 50 ruleIds per call
EXPORT_CHUNK_SIZE = 50

# A rule that has fired before but not within this many days is flagged as "Quiet"
STALE_DAYS = 30

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
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
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]


def info(msg: str) -> None:
    print(f"{ANSI_GREEN}[INFO]{ANSI_RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{ANSI_YELLOW}[WARN]{ANSI_RESET} {msg}")


def fail(msg: str, resp: requests.Response | None = None) -> None:
    print(f"[ERROR] {msg}")
    if resp is not None:
        print(f"Status: {resp.status_code}")
        print(resp.text)
    sys.exit(1)


# =========================================================
# 2) ARGUMENTS
# =========================================================
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build an Exabeam MITRE ATT&CK coverage report.")
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

    def authenticate(self) -> None:
        resp = requests.post(
            f"{self.base_url}/auth/v1/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            headers={"accept": "application/json", "content-type": "application/x-www-form-urlencoded"},
            timeout=TOKEN_TIMEOUT_SECONDS,
        )
        if not resp.ok:
            fail("Token request failed (check credentials and --region)", resp)
        token = resp.json().get("access_token")
        if not token:
            fail("Token response missing access_token")
        self.token = token

    def get_mitre_techniques(self, name_contains: str) -> dict:
        params = {"nameContains": name_contains} if name_contains else None
        resp = requests.get(f"{self.base_url}/mitre/v1/techniques", headers=self._headers(),
                            params=params, timeout=API_TIMEOUT_SECONDS)
        if not resp.ok:
            fail("MITRE techniques request failed", resp)
        return resp.json()

    def list_correlation_rules(self) -> Any:
        resp = requests.get(f"{self.base_url}/correlation-rules/v2/rules", headers=self._headers(),
                            timeout=API_TIMEOUT_SECONDS)
        if not resp.ok:
            fail("Correlation rules list request failed", resp)
        return resp.json()

    def export_rule_definitions(self, rule_ids: list[str]) -> list[dict]:
        headers = {**self._headers(), "content-type": "application/json"}
        all_defs: list[dict] = []
        for i in range(0, len(rule_ids), EXPORT_CHUNK_SIZE):
            batch = rule_ids[i:i + EXPORT_CHUNK_SIZE]
            resp = requests.post(f"{self.base_url}/correlation-rules/v2/rules/export", headers=headers,
                                 json={"ruleIds": batch}, timeout=API_TIMEOUT_SECONDS)
            if not resp.ok:
                fail("Correlation rules export request failed", resp)
            defs = resp.json().get("ruleDefinitions", [])
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

    order = ["Rule auto-disabled", "Rule stopped firing", "Coverage lost", "Technique degraded", "Rule disabled",
             "Rule removed", "Coverage gained", "Technique improved", "Rule added", "Rule enabled",
             "Rule started firing", "Rule status changed"]
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


NAV_COLOURS = {TS_VALIDATED: "#34d399", TS_QUIET: "#fbbf24", TS_UNVALIDATED: "#fb923c"}


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


def card(label: str, value: Any, hint: str, tone: str = "", delta: str = "") -> str:
    delta_html = f'<div class="delta">{esc(delta)}</div>' if delta else ""
    return f"""
      <div class="card">
        <div class="label">{esc(label)}</div>
        <div class="value {tone}">{esc(value)}</div>{delta_html}
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


def build_matrix_data(all_mitre: list[dict], tech_status: dict[str, dict]) -> list[dict]:
    """Columns of parent techniques per tactic, with sub-technique detail for the heatmap."""
    alias: dict[str, tuple[str, str]] = {}
    for tid, name in TACTIC_ORDER:
        for a in (tid, name, name.replace(" ", "-")):
            alias[tactic_key(a)] = (tid, name)

    subs_by_parent: dict[str, list[dict]] = {}
    for r in all_mitre:
        if r["isSubtechnique"]:
            t = tech_status[r["techniqueId"]]
            subs_by_parent.setdefault(r["parentTechniqueId"], []).append({
                "id": r["techniqueId"], "name": r["name"], "status": t["status"],
                "rules": [x["ruleName"] for x in t["rules"]],
            })

    columns: dict[str, dict] = {}
    for tid, name in TACTIC_ORDER:
        columns[tid] = {"id": tid, "name": name, "techs": []}

    for r in all_mitre:
        if r["isSubtechnique"]:
            continue
        t = tech_status[r["techniqueId"]]
        tech = {
            "id": r["techniqueId"], "name": r["name"], "link": r["externalLink"],
            "status": t["status"], "rolled": t["rolled"], "viaSub": t["viaSub"],
            "rules": [{"name": x["ruleName"], "status": x["status"], "last": x["lastTriggeredAt"]} for x in t["rules"]],
            "subs": subs_by_parent.get(r["techniqueId"], []),
        }
        for raw in [x.strip() for x in (r["tactics"] or "").split(",") if x.strip()] or ["Unmapped"]:
            tid, name = alias.get(tactic_key(raw), (raw, raw.replace("-", " ").title()))
            columns.setdefault(tid, {"id": tid, "name": name, "techs": []})["techs"].append(tech)

    out = [c for c in columns.values() if c["techs"]]
    for c in out:
        c["techs"].sort(key=lambda t: t["name"].lower())
    return out


HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Exabeam MITRE Coverage Report</title>
<style>
  :root {
    --bg: #0b0f14; --panel: #0f1720; --panel2: #111b26; --border: #223042;
    --text: #e7eef8; --muted: #9fb1c6;
    --good: #34d399; --warn: #fbbf24; --orange: #fb923c; --bad: #fb7185; --none: #1a2533;
    --shadow: rgba(0,0,0,0.35); --radius: 16px;
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    --sans: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
  }
  body {
    margin:0; font-family: var(--sans); color: var(--text);
    background: radial-gradient(1200px 600px at 15% 10%, #122033, transparent 60%),
                radial-gradient(900px 500px at 85% 0%, #101a26, transparent 55%), var(--bg);
  }
  .wrap { max-width: 1400px; margin: 0 auto; padding: 20px 18px 60px; }
  .topbar {
    display:flex; align-items:center; justify-content:space-between; gap: 14px;
    padding: 14px 16px; border: 1px solid var(--border);
    background: linear-gradient(180deg, var(--panel), rgba(15,23,32,0.65));
    box-shadow: 0 10px 28px var(--shadow); border-radius: var(--radius);
  }
  .brand { display:flex; align-items:center; gap: 12px; min-width: 260px; }
  .logo { width: 44px; height: 44px; border-radius: 12px; background: linear-gradient(135deg, #1a2a3a, #0e1620);
          border: 1px dashed #2b3c52; display:flex; align-items:center; justify-content:center; overflow:hidden; }
  .logo img { width:100%; height:100%; object-fit:contain; display:block; }
  .logo .fallback { color: var(--muted); font-size: 11px; font-family: var(--mono); }
  .title { display:flex; flex-direction:column; line-height:1.15; }
  .title h1 { margin:0; font-size: 16px; letter-spacing: 0.2px; }
  .title .sub { margin-top:4px; font-size: 12px; color: var(--muted); font-family: var(--mono); }
  .meta { text-align:right; color: var(--muted); font-size: 12px; font-family: var(--mono); }

  .grid { margin-top: 18px; display:grid; grid-template-columns: repeat(12, 1fr); gap: 14px; }
  .card { grid-column: span 3; padding: 14px; border: 1px solid var(--border);
          background: linear-gradient(180deg, var(--panel2), rgba(17,27,38,0.75));
          border-radius: var(--radius); box-shadow: 0 10px 24px var(--shadow); }
  .card .label { color: var(--muted); font-size: 12px; margin-bottom: 8px; }
  .card .value { font-size: 28px; font-weight: 700; letter-spacing: 0.2px; }
  .card .delta { margin-top: 4px; font-size: 12px; font-family: var(--mono); color: var(--muted); }
  .card .hint { margin-top: 10px; font-size: 12px; color: var(--muted); }
  .value.good { color: var(--good); } .value.warn { color: var(--warn); }
  .value.orange { color: var(--orange); } .value.bad { color: var(--bad); }

  .panel { grid-column: span 12; padding: 14px 14px 6px; border: 1px solid var(--border);
           background: linear-gradient(180deg, var(--panel), rgba(15,23,32,0.7));
           border-radius: var(--radius); box-shadow: 0 10px 24px var(--shadow); min-width: 0; }
  .panel.half { grid-column: span 6; }
  .panel h2 { margin: 2px 0 8px; font-size: 14px; letter-spacing: 0.2px; }
  .panel .sub { margin: 0 0 10px; color: var(--muted); font-size: 12px; }
  .controls { display:flex; flex-wrap:wrap; gap: 10px; margin: 8px 0 12px; align-items:center; }
  .controls input[type=text] { flex: 1; min-width: 240px; background: #0b121a; color: var(--text);
    border: 1px solid var(--border); border-radius: 12px; padding: 10px 12px; outline: none;
    font-family: var(--mono); font-size: 12px; }
  .controls label { color: var(--muted); font-size: 12px; display:flex; gap:6px; align-items:center; }
  .pill { border: 1px solid var(--border); color: var(--muted); border-radius: 999px; padding: 8px 10px;
          font-family: var(--mono); font-size: 12px; background: rgba(0,0,0,0.15); }

  .table-wrap { overflow-x: auto; max-height: 560px; overflow-y: auto; margin: 10px 0 16px; border-radius: 14px; }
  table.data-table { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 12px; }
  table.data-table thead th { text-align:left; background: #0b121a; color: var(--muted);
    border-bottom: 1px solid var(--border); padding: 10px; position: sticky; top: 0; z-index: 2; white-space: nowrap; }
  table.data-table tbody td { padding: 9px 10px; border-bottom: 1px solid rgba(34,48,66,0.6); vertical-align: top; }
  table.data-table tbody tr:hover { background: rgba(125,211,252,0.06); }

  .legend { display:flex; flex-wrap:wrap; gap: 14px; font-size: 12px; color: var(--muted); margin: 4px 0 10px; }
  .legend span { display:flex; align-items:center; gap:6px; }
  .sw { width: 12px; height: 12px; border-radius: 3px; display:inline-block; }
  .s-validated { background: var(--good); color: #062018; }
  .s-quiet { background: var(--warn); color: #241a02; }
  .s-unvalidated { background: var(--orange); color: #2a1404; }
  .s-none { background: var(--none); color: var(--muted); }
  .matrix { display:flex; gap: 6px; overflow-x:auto; padding-bottom: 10px; }
  .col { min-width: 132px; flex: 1 0 132px; }
  .col h3 { margin: 0 0 6px; font-size: 11px; font-weight: 600; color: var(--text); min-height: 28px; }
  .col h3 small { display:block; color: var(--muted); font-weight: 400; font-family: var(--mono); }
  .cell { font-size: 10.5px; line-height: 1.25; padding: 5px 6px; border-radius: 6px; margin-bottom: 4px;
          cursor: pointer; border: 1px solid transparent; }
  .cell:hover { border-color: #e7eef8; }
  .cell.viasub { background-image: repeating-linear-gradient(135deg, rgba(0,0,0,0.18) 0 4px, transparent 4px 8px); }
  .cell .tid { font-family: var(--mono); opacity: 0.8; }
  .cell .cnt { float: right; font-family: var(--mono); font-weight: 700; }
  #techDetail { font-size: 12px; margin: 8px 0 14px; padding: 12px; border: 1px solid var(--border);
                border-radius: 12px; background: #0b121a; display:none; }
  #techDetail a { color: #7dd3fc; }
  #techDetail ul { margin: 6px 0; padding-left: 18px; }
  .tag { font-family: var(--mono); font-size: 11px; padding: 1px 6px; border-radius: 6px; }

  @media (max-width: 980px) { .card { grid-column: span 6; } .panel.half { grid-column: span 12; } .meta { display:none; } }
  @media (max-width: 560px) { .card { grid-column: span 12; } }
  .footer-note { margin: 8px 0 10px; color: var(--muted); font-size: 12px; font-family: var(--mono); }
</style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <div class="logo" title="Put a logo.png next to this HTML file to display it.">
          <img src="logo.png" alt="Logo" onerror="this.style.display='none'; this.nextElementSibling.style.display='block';" />
          <span class="fallback" style="display:none;">LOGO</span>
        </div>
        <div class="title">
          <h1>MITRE Coverage Report</h1>
          <div class="sub">Exabeam Correlation Rules • Region: %%REGION%% • Generated: %%GENERATED%% • Quiet after %%STALE%% days</div>
        </div>
      </div>
      <div class="meta">%%COMPARE_META%%</div>
    </div>

    <div class="grid">
      %%CARDS%%
      %%CHANGES%%

      <div class="panel">
        <h2>ATT&amp;CK coverage matrix</h2>
        <p class="sub">Each cell is a technique, coloured by its best mapped rule. Hatched cells are covered only through a sub-technique. Click a cell for details.</p>
        <div class="legend">
          <span><i class="sw s-validated"></i>Validated - a rule fired in the last %%STALE%% days</span>
          <span><i class="sw s-quiet"></i>Quiet - rules fired before, not recently</span>
          <span><i class="sw s-unvalidated"></i>Unvalidated - rules have never fired</span>
          <span><i class="sw s-none"></i>Not covered</span>
        </div>
        <div class="controls">
          <label><input type="checkbox" id="rollup" checked onchange="renderMatrix()"> Count sub-technique coverage toward parent</label>
          <label><input type="checkbox" id="hideNone" onchange="renderMatrix()"> Hide not covered</label>
        </div>
        <div id="techDetail"></div>
        <div class="matrix" id="matrix"></div>
      </div>

      %%HEALTH_PANELS%%

      <div class="panel half">
        <h2>Rules per tactic</h2>
        %%TACTIC_TABLE%%
        <div class="footer-note">uniqueRules = distinct rules per tactic. mappingRows = total mappings per tactic.</div>
      </div>
      <div class="panel half">
        <h2>Top techniques by mapping count</h2>
        %%TECH_COUNTS_TABLE%%
      </div>

      %%PRIORITY_PANEL%%
      %%DATA_PANELS%%
    </div>
  </div>

<script id="matrixData" type="application/json">%%MATRIX_JSON%%</script>
<script>
const MATRIX = JSON.parse(document.getElementById('matrixData').textContent);
const LABEL = {validated: 'Validated', quiet: 'Quiet', unvalidated: 'Unvalidated', none: 'Not covered'};

function escHtml(s) {
  return String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
}

function renderMatrix() {
  const rollup = document.getElementById('rollup').checked;
  const hideNone = document.getElementById('hideNone').checked;
  const root = document.getElementById('matrix');
  root.innerHTML = '';
  MATRIX.forEach((col, ci) => {
    const techs = col.techs.filter(t => !hideNone || (rollup ? t.rolled : t.status) !== 'none');
    const covered = col.techs.filter(t => (rollup ? t.rolled : t.status) !== 'none').length;
    const div = document.createElement('div');
    div.className = 'col';
    let html = `<h3>${escHtml(col.name)}<small>${covered}/${col.techs.length} covered</small></h3>`;
    techs.forEach((t, ti) => {
      const st = rollup ? t.rolled : t.status;
      const via = rollup && t.viaSub ? ' viasub' : '';
      const subCov = t.subs.filter(s => s.status !== 'none').length;
      const cnt = t.rules.length ? `<span class="cnt">${t.rules.length}</span>` : '';
      const subTxt = t.subs.length ? ` <span class="tid">(${subCov}/${t.subs.length} subs)</span>` : '';
      const idx = col.techs.indexOf(t);
      html += `<div class="cell s-${st}${via}" onclick="showTech(${ci},${idx})" title="${escHtml(t.id)} ${escHtml(t.name)} - ${LABEL[st]}">`
           + `${cnt}<span class="tid">${escHtml(t.id)}</span><br>${escHtml(t.name)}${subTxt}</div>`;
    });
    div.innerHTML = html;
    root.appendChild(div);
  });
}

function showTech(ci, ti) {
  const t = MATRIX[ci].techs[ti];
  const el = document.getElementById('techDetail');
  const ruleList = rs => rs.length
    ? '<ul>' + rs.map(r => `<li>${escHtml(r.name)} <span class="tag s-${statusClass(r.status)}">${escHtml(r.status)}</span>${r.last ? ' last fired ' + escHtml(r.last) : ''}</li>`).join('') + '</ul>'
    : '<div class="footer-note">No rules mapped directly.</div>';
  const subs = t.subs.length
    ? '<ul>' + t.subs.map(s => `<li><span class="tag s-${s.status}">${LABEL[s.status]}</span> ${escHtml(s.id)} ${escHtml(s.name)}${s.rules.length ? ' - ' + s.rules.map(escHtml).join(', ') : ''}</li>`).join('') + '</ul>'
    : '';
  el.innerHTML = `<strong>${escHtml(t.id)} ${escHtml(t.name)}</strong> <span class="tag s-${t.status}">${LABEL[t.status]}</span>`
    + (t.link ? ` <a href="${escHtml(t.link)}" target="_blank" rel="noopener">MITRE page</a>` : '')
    + `<div style="margin-top:8px;color:var(--muted)">Rules mapped to this technique:</div>${ruleList(t.rules)}`
    + (subs ? `<div style="margin-top:8px;color:var(--muted)">Sub-techniques:</div>${subs}` : '');
  el.style.display = 'block';
  el.scrollIntoView({block: 'nearest', behavior: 'smooth'});
}

function statusClass(ruleStatus) {
  return {Active: 'validated', Quiet: 'quiet', NeverFired: 'unvalidated', Unknown: 'unvalidated'}[ruleStatus] || 'none';
}

function filterTable(tableId, query) {
  const q = (query || '').toLowerCase().trim();
  const table = document.getElementById(tableId);
  if (!table || !table.tBodies || !table.tBodies[0]) return;
  for (const row of table.tBodies[0].rows) {
    row.style.display = row.innerText.toLowerCase().includes(q) ? '' : 'none';
  }
}

renderMatrix();
</script>
</body>
</html>
"""


def build_html_report(path: str, ctx: dict) -> None:
    k = ctx["kpis"]
    prev_kpis = ctx["prev"]["kpis"] if ctx["prev"] else None
    stale = ctx["stale_days"]

    cards = "".join([
        card("Enabled rules", k["enabledRules"],
             f"{k['testModeRules']} in test mode • {k['rulesReturned']} rules returned by API", "good",
             delta_text(k["enabledRules"], prev_kpis, "enabledRules")),
        card("Parent techniques covered", f"{k['parentsCoveredPct']:.1f}%",
             f"{k['parentsCoveredInclSubs']}/{k['parentsTotal']} incl. via sub-techniques • {k['parentsCovered']} mapped directly",
             "warn", delta_text(k["parentsCoveredPct"], prev_kpis, "parentsCoveredPct", " pts")),
        card("Validated coverage", f"{k['validatedPct']:.1f}%",
             f"{k['parentsValidated']}/{k['parentsTotal']} parent techniques have a rule that fired in the last {stale} days",
             "good" if k["validatedPct"] >= k["parentsCoveredPct"] * 0.75 else "warn",
             delta_text(k["validatedPct"], prev_kpis, "validatedPct", " pts")),
        card("Sub-techniques covered", f"{k['subsCoveredPct']:.1f}%", f"{k['subsCovered']}/{k['subsTotal']}", "",
             delta_text(k["subsCoveredPct"], prev_kpis, "subsCoveredPct", " pts")),
        card("Rules gone quiet", k["rulesQuiet"],
             f"Fired before, but not in the last {stale} days - check log sources and rule logic",
             "warn" if k["rulesQuiet"] else "good", delta_text(k["rulesQuiet"], prev_kpis, "rulesQuiet")),
        card("Rules never fired", k["rulesNeverFired"], "Enabled but never triggered - unvalidated detections",
             "orange" if k["rulesNeverFired"] else "good", delta_text(k["rulesNeverFired"], prev_kpis, "rulesNeverFired")),
        card("Rules auto-disabled", k["rulesAutoDisabled"], "Turned off by the platform - not counted as coverage",
             "bad" if k["rulesAutoDisabled"] else "good", delta_text(k["rulesAutoDisabled"], prev_kpis, "rulesAutoDisabled")),
        card("Rule hygiene issues", k["noMitreTag"] + k["exportMissing"],
             f"{k['noMitreTag']} with no MITRE tags • {k['exportMissing']} missing from export"
             + (f" • {k['unknownTechniques']} mapped to unknown techniques" if k["unknownTechniques"] else ""),
             "warn" if (k["noMitreTag"] + k["exportMissing"]) else "good"),
    ])

    if k["rulesUnknown"]:
        cards += card("Trigger data unavailable", k["rulesUnknown"],
                      "Enabled rules where the API returned no trigger history - treated as unvalidated", "warn")

    # Changes since last run
    changes_html = ""
    if ctx["prev"]:
        prev_when = esc(ctx["prev"].get("generatedAt", ""))
        changes = ctx["changes"]
        body = to_html_table(changes, "tblChanges") if changes else '<div class="footer-note">Nothing changed.</div>'
        changes_html = f"""
      <div class="panel">
        <h2>Changes since last run ({prev_when})</h2>
        <p class="sub">Rules that stopped firing or were auto-disabled are listed first - these are the most likely signs that a log source or rule has broken.</p>
        {body}
      </div>"""
        compare_meta = f"<div>Compared with run:</div><div>{prev_when}</div>"
    else:
        compare_meta = "<div>No previous run to compare with.</div><div>Run again later to see changes.</div>"

    # Detection health panels
    health = ctx["health_enabled"]
    quiet = sorted([h for h in health if h["status"] == RS_QUIET], key=lambda h: h["daysSinceLastTrigger"])
    never = sorted([h for h in health if h["status"] == RS_NEVER],
                   key=lambda h: (h["ruleAgeDays"] == "", -(h["ruleAgeDays"] or 0)))
    auto = ctx["health_auto_disabled"]
    noisy = sorted([h for h in health if h["avgTriggersPerDay"] != ""],
                   key=lambda h: h["avgTriggersPerDay"], reverse=True)[:15]
    hcols = ["ruleName", "severity", "lastTriggeredAt", "daysSinceLastTrigger", "timesTriggered", "mitreMappings", "testMode"]
    ncols = ["ruleName", "severity", "createdAt", "ruleAgeDays", "mitreMappings", "testMode"]

    health_html = f"""
      <div class="panel half">
        <h2>Gone quiet ({len(quiet)})</h2>
        <p class="sub">Fired before but not in the last {stale} days. Most recently stopped first - these are the likeliest to be broken.</p>
        {to_html_table(quiet, "tblQuiet", cols=hcols)}
      </div>
      <div class="panel half">
        <h2>Never fired ({len(never)})</h2>
        <p class="sub">Enabled rules with no recorded trigger. Oldest first - these are the best candidates for validation testing.</p>
        {to_html_table(never, "tblNever", cols=ncols)}
      </div>
      <div class="panel half">
        <h2>Noisiest rules</h2>
        <p class="sub">Average triggers per day since the rule was created - candidates for tuning.</p>
        {to_html_table(noisy, "tblNoisy", cols=["ruleName", "avgTriggersPerDay", "timesTriggered", "timesSuppressed", "suppressedPct", "lastTriggeredAt"])}
      </div>
      <div class="panel half">
        <h2>Auto-disabled ({len(auto)})</h2>
        <p class="sub">Rules the platform switched off. They are not counted as coverage.</p>
        {to_html_table(auto, "tblAuto", cols=["ruleName", "severity", "lastTriggeredAt", "timesTriggered", "author"])}
      </div>"""

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

    data_html = "".join([
        filterable_panel("All MITRE techniques", "status = best status of any mapped rule.", ctx["all_mitre_view"],
                         "tblAllMitre", "Filter (validated, T1110, credential-access, Brute Force)..."),
        filterable_panel("Rule health", f"Every rule returned by the API. Quiet = no trigger for {stale}+ days.",
                         ctx["health_all"], "tblHealth", "Filter (Quiet, NeverFired, rule name)..."),
        filterable_panel("Current coverage", "Each row maps one rule to one technique.", ctx["coverage"],
                         "tblCoverage", "Filter (rule name, TA0006, T1003)..."),
        filterable_panel("Current gaps", "Uncovered techniques plus rule hygiene issues.", ctx["gaps"],
                         "tblGaps", "Filter (NotCovered, NoMitreTag, T1556)..."),
    ])

    matrix_json = json.dumps(ctx["matrix"], separators=(",", ":")).replace("</", "<\\/")

    html = HTML_TEMPLATE
    for token, value in {
        "%%REGION%%": esc(ctx["region"]),
        "%%GENERATED%%": esc(ctx["generated"]),
        "%%STALE%%": str(stale),
        "%%COMPARE_META%%": compare_meta,
        "%%CARDS%%": cards,
        "%%CHANGES%%": changes_html,
        "%%HEALTH_PANELS%%": health_html,
        "%%TACTIC_TABLE%%": to_html_table(ctx["tactic_summary"], "tblTacticSummary"),
        "%%TECH_COUNTS_TABLE%%": to_html_table(ctx["tech_counts"], "tblTechCounts", max_rows=50),
        "%%PRIORITY_PANEL%%": priority_html,
        "%%DATA_PANELS%%": data_html,
        "%%MATRIX_JSON%%": matrix_json,
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
        "html": os.path.join(out_dir, f"mitre_coverage_report_{region}_{ts}.html"),
        "snapshot": os.path.join(out_dir, "snapshot.json"),
    }
    info(f"Output folder: {out_dir}")

    # Optional logo: ./assets/logo.png, falling back to the one next to this script
    for logo in (os.path.join(os.getcwd(), "assets", "logo.png"), os.path.join(SCRIPT_DIR, "assets", "logo.png")):
        if os.path.exists(logo):
            shutil.copyfile(logo, os.path.join(out_dir, "logo.png"))
            break

    priorities = load_priorities(args.priority_file)

    # --- Fetch (or replay) raw data ---
    if args.replay:
        info(f"Replaying raw API responses from {args.replay}")
        mitre_raw = load_raw(args.replay, "mitre")
        rules_raw = load_raw(args.replay, "rules")
        export_raw = load_raw(args.replay, "export")
    else:
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

    unknown_keys = sorted({c["techniqueKey"] for c in coverage if c["techniqueKey"] and c["techniqueKey"] not in universe})
    for tid in unknown_keys:
        rule_names = sorted({c["ruleName"] for c in coverage if c["techniqueKey"] == tid})
        rule_gaps.append({"issueType": "UnknownTechnique", "ruleId": "", "ruleName": "; ".join(rule_names),
                          "notes": f"Rules map to {tid}, which is not in the MITRE technique list (deprecated or typo?)"})

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

    build_html_report(paths["html"], {
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
        "matrix": build_matrix_data(all_mitre, tech_status),
    })

    for label, key in (("All techniques", "all_mitre"), ("Coverage", "coverage"), ("Gaps", "gaps"),
                       ("Rule health", "health"), ("Navigator layer", "navigator"), ("HTML report", "html")):
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
    main()
