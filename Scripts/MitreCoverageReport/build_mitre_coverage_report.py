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
import io
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


def build_matrix_data(all_mitre: list[dict], tech_status: dict[str, dict], descriptions: dict[str, str]) -> list[dict]:
    """Columns of parent techniques per tactic, each with its sub-techniques, for the matrix."""
    alias: dict[str, tuple[str, str]] = {}
    for tid, name in TACTIC_ORDER:
        for a in (tid, name, name.replace(" ", "-")):
            alias[tactic_key(a)] = (tid, name)
    alias[tactic_key("Defense Evasion")] = ("TA0005", "Stealth")

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
        tech = {
            "id": r["techniqueId"], "name": r["name"], "link": r["externalLink"],
            "desc": descriptions.get(r["techniqueId"], ""),
            "status": t["status"], "rolled": t["rolled"], "viaSub": t["viaSub"],
            "score": tech_score(t["status"], list(direct.values())),
            "rolledScore": tech_score(t["rolled"], list(rolled.values())),
            "rules": rule_view(t["rules"]),
            "subs": subs,
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
    "ruleCount", "activeRules", "quietRules", "neverFiredRules", "lastFired", "rules", "mitreUrl",
]


def build_matrix_csv_rows(matrix: list[dict]) -> list[dict]:
    """One row per technique per tactic, in ATT&CK matrix order (tactic, then technique, then its sub-techniques)."""
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
            "lastFired": last, "rules": "; ".join(sorted(x["name"] for x in t["rules"])), "mitreUrl": t["link"],
        }

    for col in matrix:
        for t in sorted(col["techs"], key=lambda x: x["id"]):
            rows.append(row(col, t, "", t["rolled"], t["rolledScore"]))
            for s in t["subs"]:
                rows.append(row(col, s, t["id"], s["status"], s["score"]))
    return rows


HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Exabeam MITRE Coverage Report</title>
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
    --bad: #f0506e;
    --radius: 2px;
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    --sans: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
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

  /* Tabs (Outcomes Navigator style) */
  .tabs { display:flex; gap: 2px; margin-bottom: 18px; flex-wrap: wrap; }
  .tab { background: var(--panel-2); color: var(--text-2); border: 0; border-top: 2px solid transparent;
         padding: 16px 22px; font: 500 13px var(--sans); cursor: pointer; }
  .tab:hover { color: var(--text); background: #12161f; }
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
  .card .value.score svg.shield { width: 30px; height: 30px; color: #9b1fc0; }
  .helplink { color: var(--link); text-decoration: none; }
  .helplink:hover { text-decoration: underline; }
  table.factors { width: 100%; border-collapse: collapse; margin-top: 14px; border: 1px solid #30323e; font-size: 13px; }
  table.factors th, table.factors td { padding: 14px 16px; border-bottom: 1px solid #30323e; text-align: left; }
  table.factors th { color: var(--muted); font-weight: 500; }
  table.factors td:last-child, table.factors th:last-child { text-align: right; white-space: nowrap; }
  table.factors tr.total td { font-weight: 600; color: var(--text); border-top: 1px solid #4e4f56; }
  .meter { margin-top: 10px; height: 3px; background: var(--track); }
  .meter > i { display:block; height: 100%; background: var(--accent); }
  .value.good { color: var(--band-high); } .value.blue { color: #3d8fe8; }
  .value.purple { color: #b45ad6; } .value.bad { color: var(--bad); } .value.warn { color: #f0b429; }

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
  ::-webkit-scrollbar-thumb { background: #2a2f3c; }
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
  .switch .knob { width: 30px; height: 16px; border-radius: 999px; background: #2a2f3c; position: relative; transition: background .15s; }
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
  .tile.scored { background: var(--tile-scored); border-color: var(--tile-scored); }
  .tile.nocov { background: transparent; border: 1px dashed var(--tile-border); }
  .tile:hover { border-color: var(--link); border-style: solid; }
  .tile.sel { background: var(--tile-selected); border: 1px solid var(--tile-selected); }
  .tile .body { flex: 1; min-width: 0; padding: 12px 14px 8px 16px; }
  .tile.nocov .body { padding-bottom: 12px; }
  .tile .tname { font-size: 13px; font-weight: 600; color: var(--text); line-height: 1.4; }
  .tile.nocov .tname { font-weight: 400; color: var(--muted); }
  /* Sub-technique expander - the side handle used by the MITRE ATT&CK Navigator */
  .tile .expander { width: 18px; flex: none; display:flex; align-items:center; justify-content:center;
                    border-left: 1px solid rgba(255,255,255,0.08); color: var(--muted); font-size: 10px;
                    writing-mode: vertical-rl; letter-spacing: 1px; }
  .tile .expander:hover { color: var(--text); background: rgba(255,255,255,0.06); }
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
  .s-validated { background: rgba(49,167,23,0.18); color: #6fd35a; }
  .s-quiet { background: rgba(31,114,208,0.22); color: #6fb0f5; }
  .s-unvalidated { background: rgba(155,31,192,0.22); color: #cf86ea; }
  .s-none { background: rgba(163,170,181,0.12); color: var(--muted); }

  /* Technique popover (Outcomes Navigator style) */
  .pop { position: absolute; z-index: 30; width: 380px; display: none; padding: 20px 22px 18px;
         background: var(--pop); border: 1px solid var(--pop-border); border-radius: var(--radius);
         box-shadow: 0 16px 40px rgba(0,0,0,0.55); }
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
  .overlay { position: fixed; inset: 0; z-index: 40; background: rgba(2,3,8,0.7); display: none;
             align-items: flex-start; justify-content: center; padding: 6vh 16px; overflow-y: auto; }
  .overlay.open { display: flex; }
  .modal { position: relative; width: min(820px, 100%); background: var(--pop); border: 1px solid var(--pop-border);
           border-radius: var(--radius); padding: 24px 26px; box-shadow: 0 24px 60px rgba(0,0,0,0.6); }
  .modal .ptitle { font-size: 19px; font-weight: 600; color: var(--text); padding-right: 30px; }
  .modal .pid { margin-top: 6px; font-size: 12px; color: var(--muted-2); }
  .modal .row { display:flex; align-items:center; gap: 14px; flex-wrap: wrap; margin-top: 14px; }
  .modal .row .num { font-size: 28px; font-weight: 600; color: var(--text); }
  .modal .row .bar.big { flex: 1; min-width: 200px; margin: 0; }
  .modal p.desc { font-size: 13px; line-height: 1.6; color: var(--text-2); margin: 16px 0 6px; }
  .modal h4 { margin-top: 22px; }
  .modal table.data-table { background: rgba(0,0,0,0.15); }
  .modal table.data-table thead th { background: #1a1b23; }
  .modal table.data-table tbody td { border-bottom-color: #30323e; }
  .modal .note { color: var(--muted); font-size: 12px; }
  .modal a { color: var(--link); }

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
          <img src="logo.png" alt="Logo" onerror="this.style.display='none'; this.nextElementSibling.style.display='block';" />
          <span class="fallback" style="display:none;">LOGO</span>
        </div>
        <div class="title">
          <h1>MITRE ATT&amp;CK Coverage Report</h1>
          <div class="sub">Exabeam Correlation Rules • Region: %%REGION%% • Generated: %%GENERATED%%</div>
        </div>
      </div>
      <div class="meta">%%COMPARE_META%%</div>
    </div>

    <div class="tabs" role="tablist">
      <button class="tab" data-tab="coverage">MITRE ATT&amp;CK&reg; Coverage</button>
      <button class="tab" data-tab="health">Detection Health</button>
      <button class="tab" data-tab="changes">Changes<span class="count">%%CHANGE_COUNT%%</span></button>
      <button class="tab" data-tab="data">Data Tables</button>
    </div>

    <section class="tabpane" id="tab-coverage">
      <div class="grid">%%COVERAGE_CARDS%%</div>

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
      </div>
      <div class="toolbar">
        <div class="group">
          <button class="btn btn-outline" onclick="expandAll(true)">Expand all sub-techniques</button>
          <button class="btn btn-outline" onclick="expandAll(false)">Collapse all</button>
        </div>
        <div class="group">
          <label class="switch"><input type="checkbox" id="rollup" checked onchange="renderMatrix()"><span class="knob"></span>Count sub-technique coverage</label>
          <label class="switch"><input type="checkbox" id="showNone" checked onchange="renderMatrix()"><span class="knob"></span>Show uncovered techniques</label>
          <button class="btn btn-outline" onclick="exportCsv()">
            <svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>
            Export MITRE ATT&amp;CK Coverage (CSV)
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

    <section class="tabpane" id="tab-health">
      <div class="grid">%%HEALTH_CARDS%%%%HEALTH_PANELS%%</div>
    </section>

    <section class="tabpane" id="tab-changes">
      <div class="grid">%%CHANGES%%</div>
    </section>

    <section class="tabpane" id="tab-data">
      <div class="grid">
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
    </section>
  </div>

  <div class="pop" id="pop" role="dialog" aria-modal="false"></div>
  <div class="overlay" id="overlay" onclick="if (event.target === this) closeModal()">
    <div class="modal" id="modal" role="dialog" aria-modal="true"></div>
  </div>

<script id="matrixData" type="application/json">%%MATRIX_JSON%%</script>
<script id="matrixCsv" type="application/json">%%MATRIX_CSV%%</script>
<script>
const MATRIX = JSON.parse(document.getElementById('matrixData').textContent);
const CSV_NAME = %%MATRIX_CSV_NAME%%;
const SCORE = %%SCORE_JSON%%;
const LABEL = {validated: 'Validated', quiet: 'Quiet', unvalidated: 'Unvalidated', none: 'Not covered'};
const RULE_CLASS = {Active: 'validated', Quiet: 'quiet', NeverFired: 'unvalidated', Unknown: 'unvalidated'};
const RULE_LABEL = {Active: 'Active', Quiet: 'Quiet', NeverFired: 'Never fired', Unknown: 'Unknown'};
const ICON = {
  shield: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z"/></svg>',
  rules: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/></svg>',
  subs: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 4v10a3 3 0 0 0 3 3h13"/><path d="M16 13l4 4-4 4"/></svg>',
  ext: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14L21 3"/></svg>',
};
const expanded = new Set();
let selectedTile = null;
let current = null;   // {ci, ti, si} of the technique in the popover / modal

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

function tileHtml(t, key, isSub) {
  const v = view(t);
  const cls = v.status === 'none' ? 'nocov' : v.viaSub ? 'plain' : 'scored';
  const showNone = document.getElementById('showNone').checked;
  const subs = isSub ? [] : t.subs.filter(s => showNone || s.status !== 'none');
  const open = !isSub && expanded.has(t.id) && subs.length;
  const handle = !isSub && t.subs.length
    ? `<div class="expander" data-expand="${escHtml(t.id)}" title="${open ? 'Hide' : 'Show'} ${t.subs.length} sub-techniques">${open ? '&#9650;' : '&#9660;'} ${t.subs.length}</div>` : '';
  let html = `<div class="tile ${cls}" data-key="${key}">`
    + `<div class="body">${isSub ? `<div class="tid">${escHtml(t.id)}</div>` : ''}<div class="tname">${escHtml(t.name)}</div>`
    + `${v.status === 'none' ? '' : barHtml(v.score)}</div>${handle}</div>`;
  if (open) {
    html += '<div class="subs">' + t.subs.map((s, si) =>
      (showNone || s.status !== 'none') ? tileHtml(s, key + ':' + si, true) : '').join('') + '</div>';
  }
  return html;
}

function renderMatrix() {
  closePop();
  const showNone = document.getElementById('showNone').checked;
  const root = document.getElementById('matrix');
  root.innerHTML = MATRIX.map((col, ci) => {
    const covered = col.techs.filter(t => view(t).status !== 'none').length;
    let html = `<div class="col"><h3>${escHtml(col.name)}<small>${col.techs.length} Techniques &bull; ${covered} covered</small></h3>`;
    col.techs.forEach((t, ti) => {
      if (!showNone && view(t).status === 'none') return;
      html += tileHtml(t, ci + ':' + ti, false);
    });
    return html + '</div>';
  }).join('');
}

function expandAll(on) {
  expanded.clear();
  if (on) MATRIX.forEach(col => col.techs.forEach(t => { if (t.subs.length) expanded.add(t.id); }));
  renderMatrix();
}

/* ---------- Popover ---------- */
function ruleCounts(rules) {
  const active = rules.filter(r => r.status === 'Active').length;
  return `${rules.length} rule${rules.length === 1 ? '' : 's'}` + (rules.length ? ` &bull; ${active} active` : '');
}
function openPop(tile, ci, ti, si) {
  const t = lookup(ci, ti, si);
  const v = view(t);
  const isSub = si !== undefined;
  current = {ci, ti, si};
  const subLine = isSub ? '' :
    `<span class="${t.subs.length ? '' : 'muted'}">${ICON.subs}${t.subs.filter(s => s.status !== 'none').length}/${t.subs.length} sub-techniques covered</span>`;
  const pop = document.getElementById('pop');
  pop.innerHTML =
      `<button class="xbtn" onclick="closePop()" aria-label="Close">&times;</button>`
    + `<div class="ptitle">${escHtml(isSub ? t.fullName : t.name)}</div>`
    + `<div class="pid">${escHtml(t.id)} &bull; ${escHtml(MATRIX[ci].name)}</div>`
    + barHtml(v.score, true)
    + (t.desc ? `<div class="pdesc">${escHtml(t.desc)}</div>` : '')
    + `<div class="plabel">Coverage</div>`
    + `<div class="pstats"><span>${ICON.shield}${v.score}</span><span class="tag s-${v.status}">${LABEL[v.status]}${v.viaSub ? ' via sub-technique' : ''}</span>`
    + `<span>${ICON.rules}${ruleCounts(t.rules)}</span>${subLine}</div>`
    + `<div class="pactions">`
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
function openModal() {
  if (!current) return;
  const {ci, ti, si} = current;
  const t = lookup(ci, ti, si);
  const v = view(t);
  const isSub = si !== undefined;
  let subs = '';
  if (!isSub && t.subs.length) {
    const rows = t.subs.map(s => `<tr><td style="font-family:var(--mono)">${escHtml(s.id)}</td>`
      + `<td>${s.link ? `<a href="${escHtml(s.link)}" target="_blank" rel="noopener">${escHtml(s.name)}</a>` : escHtml(s.name)}</td>`
      + `<td><span class="tag s-${s.status}">${LABEL[s.status]}</span></td><td>${s.score}</td>`
      + `<td>${s.rules.length ? s.rules.map(r => escHtml(r.name)).join('<br>') : '<span class="note">-</span>'}</td></tr>`).join('');
    subs = `<h4>Sub-techniques (${t.subs.filter(s => s.status !== 'none').length}/${t.subs.length} covered)</h4>`
      + `<div class="table-wrap" style="max-height:none"><table class="data-table"><thead><tr><th>ID</th><th>Sub-technique</th><th>Status</th><th>Score</th><th>Rules</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }
  const tactics = MATRIX.filter(c => c.techs.some(x => x.id === (isSub ? MATRIX[ci].techs[ti].id : t.id))).map(c => c.name);
  document.getElementById('modal').innerHTML =
      `<button class="xbtn" onclick="closeModal()" aria-label="Close">&times;</button>`
    + `<div class="ptitle">${escHtml(isSub ? t.fullName : t.name)}</div>`
    + `<div class="pid">${escHtml(t.id)}${isSub ? ' &bull; sub-technique of ' + escHtml(MATRIX[ci].techs[ti].id) : ''} &bull; ${tactics.map(escHtml).join(', ')}</div>`
    + `<div class="row"><span class="num">${v.score}</span>${barHtml(v.score, true)}<span class="tag s-${v.status}">${LABEL[v.status]}${v.viaSub ? ' via sub-technique' : ''}</span></div>`
    + (t.desc ? `<p class="desc">${escHtml(t.desc)}</p>` : '')
    + (t.link ? `<a class="btn btn-ghost" style="padding-left:0" href="${escHtml(t.link)}" target="_blank" rel="noopener">${ICON.ext}View ${escHtml(t.id)} on attack.mitre.org</a>` : '')
    + `<h4>Correlation rules (${t.rules.length})</h4>${rulesTable(t.rules)}`
    + subs;
  closePop();
  document.getElementById('overlay').classList.add('open');
}
function closeModal() { document.getElementById('overlay').classList.remove('open'); }

function openScoreHelp() {
  const fmt = n => Number(n).toLocaleString();
  document.getElementById('modal').innerHTML =
      `<button class="xbtn" onclick="closeModal()" aria-label="Close">&times;</button>`
    + `<div class="ptitle">MITRE ATT&amp;CK Coverage Score Explanation</div>`
    + `<p class="desc">The overall score is calculated the same way as the Exabeam Outcomes Navigator score: the scores of all techniques are added up, `
    + `then divided by the number of techniques. The result is rounded to the nearest whole number.</p>`
    + `<table class="factors"><thead><tr><th>Factor</th><th>Value</th></tr></thead><tbody>`
    + `<tr><td>Sum of scores of all techniques</td><td>${fmt(SCORE.sum)}</td></tr>`
    + `<tr><td>Total number of techniques</td><td>${fmt(SCORE.techniques)}</td></tr>`
    + `<tr class="total"><td>Total average MITRE ATT&amp;CK Coverage Score</td><td>${SCORE.score}</td></tr>`
    + `</tbody></table>`
    + `<h4>How each technique is scored</h4>`
    + `<p class="desc" style="margin-top:0">Unlike the Outcomes Navigator, which scores the data and content available for a technique, this report scores `
    + `whether the correlation rules mapped to it actually fire:</p>`
    + `<table class="factors"><thead><tr><th>Technique state</th><th>Score</th></tr></thead><tbody>`
    + `<tr><td><span class="tag s-validated">Validated</span> a mapped rule fired in the last ${SCORE.staleDays} days</td><td>75 - 100</td></tr>`
    + `<tr><td><span class="tag s-quiet">Quiet</span> mapped rules fired before, but not recently</td><td>50 - 74</td></tr>`
    + `<tr><td><span class="tag s-unvalidated">Unvalidated</span> mapped rules have never fired</td><td>20 - 49</td></tr>`
    + `<tr><td><span class="tag s-none">Not covered</span> no enabled rule is mapped</td><td>0</td></tr>`
    + `</tbody></table>`
    + `<p class="desc">Each additional rule in the same state adds 5 points within its band. A parent technique takes the best score of its own rules `
    + `and its sub-techniques' rules. Only enabled correlation rules are counted.</p>`
    + `<div style="text-align:right;margin-top:18px"><button class="btn btn-primary" onclick="closeModal()">Close</button></div>`;
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

/* ---------- CSV export ---------- */
function exportCsv() {
  const csv = JSON.parse(document.getElementById('matrixCsv').textContent);
  const blob = new Blob(['\\ufeff' + csv], {type: 'text/csv;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = CSV_NAME;
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

renderMatrix();
showTab((location.hash || '#coverage').slice(1));
</script>
</body>
</html>
"""


ICON_SHIELD = ('<svg class="shield" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
               'stroke-linejoin="round"><path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z"/></svg>')


def build_html_report(path: str, ctx: dict) -> None:
    k = ctx["kpis"]
    prev_kpis = ctx["prev"]["kpis"] if ctx["prev"] else None
    stale = ctx["stale_days"]

    score_delta = delta_text(k["coverageScore"], prev_kpis, "coverageScore")
    score_delta_html = f'<div class="delta">{esc(score_delta)}</div>' if score_delta else ""
    coverage_cards = f"""
      <div class="card">
        <div class="label">MITRE ATT&amp;CK Coverage Score</div>
        <div class="value score">{ICON_SHIELD}{k["coverageScore"]}</div>{score_delta_html}
        <div class="meter"><i style="width:{k['coverageScore']}%"></i></div>
        <div class="hint">Average of {k["coverageScoreTechniques"]} technique scores •
          <a href="#" class="helplink" onclick="openScoreHelp(); return false;">How was this calculated?</a></div>
      </div>""" + "".join([
        card("Parent techniques covered", f"{k['parentsCoveredPct']:.1f}%",
             f"{k['parentsCoveredInclSubs']}/{k['parentsTotal']} incl. via sub-techniques • {k['parentsCovered']} mapped directly",
             "", delta_text(k["parentsCoveredPct"], prev_kpis, "parentsCoveredPct", " pts"), meter=k["parentsCoveredPct"]),
        card("Validated coverage", f"{k['validatedPct']:.1f}%",
             f"{k['parentsValidated']}/{k['parentsTotal']} parent techniques have a rule that fired in the last {stale} days",
             "good", delta_text(k["validatedPct"], prev_kpis, "validatedPct", " pts"), meter=k["validatedPct"]),
        card("Sub-techniques covered", f"{k['subsCoveredPct']:.1f}%", f"{k['subsCovered']}/{k['subsTotal']}", "",
             delta_text(k["subsCoveredPct"], prev_kpis, "subsCoveredPct", " pts"), meter=k["subsCoveredPct"]),
    ])

    health_cards = "".join([
        card("Enabled rules", k["enabledRules"],
             f"{k['testModeRules']} in test mode • {k['rulesReturned']} rules returned by API • "
             f"{k['rulesActive']} fired in the last {stale} days", "",
             delta_text(k["enabledRules"], prev_kpis, "enabledRules")),
        card("Rules gone quiet", k["rulesQuiet"],
             f"Fired before, but not in the last {stale} days - check log sources and rule logic",
             "blue" if k["rulesQuiet"] else "good", delta_text(k["rulesQuiet"], prev_kpis, "rulesQuiet")),
        card("Rules never fired", k["rulesNeverFired"], "Enabled but never triggered - unvalidated detections",
             "purple" if k["rulesNeverFired"] else "good", delta_text(k["rulesNeverFired"], prev_kpis, "rulesNeverFired")),
        card("Rules auto-disabled", k["rulesAutoDisabled"], "Turned off by the platform - not counted as coverage",
             "bad" if k["rulesAutoDisabled"] else "good", delta_text(k["rulesAutoDisabled"], prev_kpis, "rulesAutoDisabled")),
        card("Rule hygiene issues", k["noMitreTag"] + k["exportMissing"] + k["unknownTechniques"],
             f"{k['noMitreTag']} with no MITRE tags • {k['exportMissing']} missing from export"
             f" • {k['unknownTechniques']} mapped to retired techniques",
             "warn" if (k["noMitreTag"] + k["exportMissing"] + k["unknownTechniques"]) else "good"),
    ])
    if k["rulesUnknown"]:
        health_cards += card("Trigger data unavailable", k["rulesUnknown"],
                             "Enabled rules where the API returned no trigger history - treated as unvalidated", "warn")

    # Changes since last run
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
                         "tblAllMitre", "Filter (validated, T1110, TA0006, Brute Force)..."),
        filterable_panel("Rule health", f"Every rule returned by the API. Quiet = no trigger for {stale}+ days.",
                         ctx["health_all"], "tblHealth", "Filter (Quiet, NeverFired, rule name)..."),
        filterable_panel("Current coverage", "Each row maps one rule to one technique.", ctx["coverage"],
                         "tblCoverage", "Filter (rule name, TA0006, T1003)..."),
        filterable_panel("Current gaps", "Uncovered techniques plus rule hygiene issues.", ctx["gaps"],
                         "tblGaps", "Filter (NotCovered, NoMitreTag, UnknownTechnique, T1556)..."),
    ])

    def embed(value: Any) -> str:
        return json.dumps(value, separators=(",", ":")).replace("</", "<\\/")

    html = HTML_TEMPLATE
    for token, value in {
        "%%REGION%%": esc(ctx["region"]),
        "%%GENERATED%%": esc(ctx["generated"]),
        "%%STALE%%": str(stale),
        "%%COMPARE_META%%": compare_meta,
        "%%CHANGE_COUNT%%": change_count,
        "%%COVERAGE_CARDS%%": coverage_cards,
        "%%HEALTH_CARDS%%": health_cards,
        "%%CHANGES%%": changes_html,
        "%%HEALTH_PANELS%%": health_html,
        "%%TACTIC_TABLE%%": to_html_table(ctx["tactic_summary"], "tblTacticSummary"),
        "%%TECH_COUNTS_TABLE%%": to_html_table(ctx["tech_counts"], "tblTechCounts", max_rows=50),
        "%%PRIORITY_PANEL%%": priority_html,
        "%%DATA_PANELS%%": data_html,
        "%%MATRIX_CSV_NAME%%": embed(ctx["matrix_csv_name"]),
        "%%SCORE_JSON%%": embed({"score": k["coverageScore"], "sum": k["coverageScoreSum"],
                                 "techniques": k["coverageScoreTechniques"], "staleDays": stale}),
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
    matrix = build_matrix_data(all_mitre, tech_status, mitre_descriptions(mitre_raw))
    # Same method as the Outcomes Navigator: average technique score across all (parent) techniques
    unique_scores = {t["id"]: t["rolledScore"] for col in matrix for t in col["techs"]}
    score_sum = sum(unique_scores.values())

    unknown_keys = sorted({c["techniqueKey"] for c in coverage if c["techniqueKey"] and c["techniqueKey"] not in universe})
    for tid in unknown_keys:
        rule_names = sorted({c["ruleName"] for c in coverage if c["techniqueKey"] == tid})
        rule_gaps.append({"issueType": "UnknownTechnique", "ruleId": "", "ruleName": "; ".join(rule_names),
                          "notes": f"Rules map to {tid}, which is not in the MITRE technique list "
                                   "(retired or renumbered in a newer ATT&CK release?) - remap these rules"})

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
    matrix_rows = build_matrix_csv_rows(matrix)
    write_csv(paths["matrix"], matrix_rows, MATRIX_CSV_COLUMNS)
    matrix_csv = io.StringIO()
    csv_writer = csv.DictWriter(matrix_csv, fieldnames=MATRIX_CSV_COLUMNS, lineterminator="\r\n")
    csv_writer.writeheader()
    csv_writer.writerows(matrix_rows)
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
        "matrix": matrix,
        "matrix_csv": matrix_csv.getvalue(),
        "matrix_csv_name": os.path.basename(paths["matrix"]),
    })

    for label, key in (("All techniques", "all_mitre"), ("Coverage", "coverage"), ("Gaps", "gaps"),
                       ("Rule health", "health"), ("ATT&CK matrix", "matrix"), ("Navigator layer", "navigator"),
                       ("HTML report", "html")):
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
