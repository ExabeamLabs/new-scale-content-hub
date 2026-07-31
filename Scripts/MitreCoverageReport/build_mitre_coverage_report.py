import requests
import csv
import json
import sys
import os
import re
import shutil
from datetime import datetime, timezone
from typing import Any

# -----------------------------
# ANSI colour codes (terminal)
# -----------------------------
ANSI_GREEN = "\033[92m"
ANSI_RESET = "\033[0m"

# =========================================================
# 1) CONFIGURATION
# =========================================================
REGION = "eu"

# Keep placeholders in public repos
CLIENT_ID = "XYZ"
CLIENT_SECRET = "XYZ"

BASE_URL = f"https://api.{REGION}.exabeam.cloud"
AUTH_URL = f"{BASE_URL}/auth/v1/token"
MITRE_TECHNIQUES_URL = f"{BASE_URL}/mitre/v1/techniques"

CORR_RULES_LIST_URL = f"{BASE_URL}/correlation-rules/v2/rules"
CORR_RULES_EXPORT_URL = f"{BASE_URL}/correlation-rules/v2/rules/export"

TOKEN_TIMEOUT_SECONDS = 30
API_TIMEOUT_SECONDS = 60

# Optional MITRE filter ("" = everything)
NAME_CONTAINS = ""

# Only enabled rules for coverage
ENABLED_ONLY = True

# Export endpoint max 50 ruleIds per call
EXPORT_CHUNK_SIZE = 50

# Output root
OUT_ROOT = os.path.join(os.getcwd(), "output")
os.makedirs(OUT_ROOT, exist_ok=True)
ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
OUT_DIR = os.path.join(OUT_ROOT, ts)
os.makedirs(OUT_DIR, exist_ok=True)

PATH_ALL_MITRE = os.path.join(OUT_DIR, f"all_mitre_techniques_{REGION}_{ts}.csv")
PATH_COVERAGE = os.path.join(OUT_DIR, f"current_coverage_{REGION}_{ts}.csv")
PATH_GAPS = os.path.join(OUT_DIR, f"current_gaps_{REGION}_{ts}.csv")
PATH_HTML = os.path.join(OUT_DIR, f"mitre_coverage_report_{REGION}_{ts}.html")

# Optional logo (copied into OUT_DIR as logo.png for HTML to reference)
ASSETS_LOGO = os.path.join(os.getcwd(), "assets", "logo.png")
OUT_LOGO = os.path.join(OUT_DIR, "logo.png")


# =========================================================
# 2) AUTH: GET ACCESS TOKEN
# =========================================================
def get_access_token() -> str:
    payload = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
    }

    resp = requests.post(AUTH_URL, data=payload, headers=headers, timeout=TOKEN_TIMEOUT_SECONDS)
    try:
        resp.raise_for_status()
    except requests.HTTPError:
        print("[ERROR] Token request failed")
        print(f"Status: {resp.status_code}")
        print(resp.text)
        sys.exit(1)

    j = resp.json()
    token = j.get("access_token")
    if not token:
        print("[ERROR] Token response missing access_token")
        print(json.dumps(j, indent=2))
        sys.exit(1)

    return token


def auth_headers(access_token: str) -> dict:
    return {
        "accept": "application/json",
        "authorization": f"Bearer {access_token}",
    }


# =========================================================
# 3) MITRE: GET + FLATTEN
# =========================================================
def get_mitre_techniques(access_token: str) -> dict:
    params = {}
    if NAME_CONTAINS:
        params["nameContains"] = NAME_CONTAINS

    resp = requests.get(
        MITRE_TECHNIQUES_URL,
        headers=auth_headers(access_token),
        params=params,
        timeout=API_TIMEOUT_SECONDS,
    )
    try:
        resp.raise_for_status()
    except requests.HTTPError:
        print("[ERROR] MITRE techniques request failed")
        print(f"Status: {resp.status_code}")
        print(resp.text)
        sys.exit(1)

    return resp.json()


def flatten_mitre(data: dict) -> list[dict]:
    """
    Output rows:
      techniqueId, name, isSubtechnique, parentTechniqueId, tactics, externalLink
    Sub-techniques become their own rows.
    """
    rows: list[dict] = []
    if not isinstance(data, dict):
        return rows

    for tech_id, tech in data.items():
        if not isinstance(tech, dict):
            continue

        rows.append({
            "techniqueId": tech_id,
            "name": tech.get("name", ""),
            "isSubtechnique": False,
            "parentTechniqueId": "",
            "tactics": ",".join(tech.get("tactics", []) or []),
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
                "tactics": ",".join(tech.get("tactics", []) or []),
                "externalLink": sub.get("externalLink", ""),
            })

    rows = [r for r in rows if r["techniqueId"]]
    rows.sort(key=lambda r: (r["parentTechniqueId"] or r["techniqueId"], r["isSubtechnique"], r["techniqueId"]))
    return rows


# =========================================================
# 4) CORRELATION RULES: LIST + FILTER ENABLED
# =========================================================
def normalize_rules_list(payload: Any) -> tuple[list[dict], str | None]:
    if isinstance(payload, list):
        return ([r for r in payload if isinstance(r, dict)], None)

    if isinstance(payload, dict):
        rules_list = None
        for k in ("rules", "items", "data", "results"):
            v = payload.get(k)
            if isinstance(v, list):
                rules_list = v
                break

        next_token = (
            payload.get("nextPageToken")
            or payload.get("next_page_token")
            or payload.get("nextToken")
            or payload.get("cursor")
        )

        if rules_list is None:
            return ([], None)

        return ([r for r in rules_list if isinstance(r, dict)], next_token)

    return ([], None)


def is_rule_enabled(rule: dict) -> bool:
    if isinstance(rule.get("enabled"), bool):
        return rule["enabled"]

    status = (rule.get("status") or rule.get("state") or rule.get("ruleStatus") or "").strip().lower()
    if status:
        if "enabled" in status:
            return True
        if "disabled" in status or "stopped" in status:
            return False

    return False


def get_rule_id(rule: dict) -> str:
    for k in ("id", "ruleId", "uuid"):
        v = rule.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def get_rule_name(rule: dict) -> str:
    for k in ("name", "ruleName", "title"):
        v = rule.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def list_all_correlation_rules(access_token: str) -> list[dict]:
    all_rules: list[dict] = []
    token = None

    while True:
        params = {}
        if token:
            params["pageToken"] = token
            params["cursor"] = token
            params["nextPageToken"] = token

        resp = requests.get(
            CORR_RULES_LIST_URL,
            headers=auth_headers(access_token),
            params=params if params else None,
            timeout=API_TIMEOUT_SECONDS,
        )
        try:
            resp.raise_for_status()
        except requests.HTTPError:
            print("[ERROR] Correlation rules list request failed")
            print(f"Status: {resp.status_code}")
            print(resp.text)
            sys.exit(1)

        rules, next_token = normalize_rules_list(resp.json())
        all_rules.extend(rules)

        if next_token:
            token = next_token
            continue

        break

    # de-dupe by id
    seen = set()
    deduped = []
    for r in all_rules:
        rid = get_rule_id(r) or id(r)
        if rid in seen:
            continue
        seen.add(rid)
        deduped.append(r)

    return deduped


# =========================================================
# 5) EXPORT: RULE DEFINITIONS (chunked)
# =========================================================
def chunked(lst: list[str], size: int) -> list[list[str]]:
    return [lst[i:i + size] for i in range(0, len(lst), size)]


def export_rule_definitions(access_token: str, rule_ids: list[str]) -> list[dict]:
    headers = {
        **auth_headers(access_token),
        "content-type": "application/json",
    }

    all_defs: list[dict] = []

    for batch in chunked(rule_ids, EXPORT_CHUNK_SIZE):
        resp = requests.post(
            CORR_RULES_EXPORT_URL,
            headers=headers,
            json={"ruleIds": batch},
            timeout=API_TIMEOUT_SECONDS,
        )
        try:
            resp.raise_for_status()
        except requests.HTTPError:
            print("[ERROR] Correlation rules export request failed")
            print(f"Status: {resp.status_code}")
            print(resp.text)
            sys.exit(1)

        j = resp.json()
        defs = j.get("ruleDefinitions", [])
        if isinstance(defs, list):
            all_defs.extend([d for d in defs if isinstance(d, dict)])

    return all_defs


# =========================================================
# 6) BUILD CURRENT COVERAGE + GAPS
# =========================================================
def build_coverage_and_rule_gaps(
    enabled_rules: list[dict],
    exported_defs: list[dict]
) -> tuple[list[dict], list[dict], list[str]]:
    enabled_by_name = {get_rule_name(r): r for r in enabled_rules if get_rule_name(r)}
    enabled_names = set(enabled_by_name.keys())
    exported_names = set()

    coverage_rows: list[dict] = []
    rule_gap_rows: list[dict] = []

    for d in exported_defs:
        rule_name = (d.get("name") or "").strip()
        if not rule_name:
            continue
        exported_names.add(rule_name)

        src = enabled_by_name.get(rule_name)
        rule_id = get_rule_id(src) if src else ""
        enabled_flag = str(is_rule_enabled(src)) if src else ""

        mitre_list = d.get("mitre", [])
        if not mitre_list:
            rule_gap_rows.append({
                "issueType": "NoMitreTag",
                "ruleId": rule_id,
                "ruleName": rule_name,
                "notes": "Enabled rule has no mitre[] mappings",
            })
            continue

        if not isinstance(mitre_list, list):
            rule_gap_rows.append({
                "issueType": "InvalidMitreFormat",
                "ruleId": rule_id,
                "ruleName": rule_name,
                "notes": "mitre field was not a list",
            })
            continue

        for m in mitre_list:
            if not isinstance(m, dict):
                continue
            coverage_rows.append({
                "ruleId": rule_id,
                "ruleName": rule_name,
                "enabled": enabled_flag,
                "tacticKey": m.get("tacticKey", ""),
                "tactic": m.get("tactic", ""),
                "techniqueKey": m.get("techniqueKey", ""),
                "technique": m.get("technique", ""),
            })

    missing_names = sorted(list(enabled_names - exported_names))
    for name in missing_names:
        src = enabled_by_name.get(name)
        rule_gap_rows.append({
            "issueType": "ExportMissing",
            "ruleId": get_rule_id(src) if src else "",
            "ruleName": name,
            "notes": "Enabled rule was requested for export but definition was not returned",
        })

    return coverage_rows, rule_gap_rows, missing_names


def build_technique_gaps(all_mitre_rows: list[dict], covered_technique_keys: set[str]) -> list[dict]:
    gaps: list[dict] = []
    for r in all_mitre_rows:
        if r["techniqueId"] not in covered_technique_keys:
            gaps.append({
                "issueType": "NotCovered",
                "techniqueId": r["techniqueId"],
                "name": r["name"],
                "isSubtechnique": str(r["isSubtechnique"]),
                "parentTechniqueId": r["parentTechniqueId"],
                "tactics": r["tactics"],
                "externalLink": r["externalLink"],
                "notes": "",
            })
    return gaps


# =========================================================
# 7) CSV HELPERS
# =========================================================
def write_csv(path: str, rows: list[dict], fieldnames: list[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


# =========================================================
# 8) HTML REPORT (single-file dashboard)
# =========================================================
def extract_rule_name_from_notes(notes: str) -> str:
    m = re.search(r"ruleName=([^|]+)\s*\|", str(notes))
    return m.group(1).strip() if m else ""


def read_csv_dicts(path: str) -> list[dict]:
    out: list[dict] = []
    with open(path, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            out.append(dict(row))
    return out


def to_html_table(rows: list[dict], table_id: str, max_rows: int = 1000) -> str:
    if not rows:
        return f'<div class="footer-note">No rows.</div>'

    # cap rows for browser performance
    rows2 = rows[:max_rows]
    cols = list(rows2[0].keys())

    def esc(x: Any) -> str:
        return (str(x) if x is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    thead = "".join([f"<th>{esc(c)}</th>" for c in cols])
    tbody_parts = []
    for row in rows2:
        tds = "".join([f"<td>{esc(row.get(c,''))}</td>" for c in cols])
        tbody_parts.append(f"<tr>{tds}</tr>")
    tbody = "".join(tbody_parts)

    return f"""
<table class="data-table" id="{table_id}">
  <thead><tr>{thead}</tr></thead>
  <tbody>{tbody}</tbody>
</table>
"""


def build_html_report(
    out_html_path: str,
    path_all_mitre: str,
    path_coverage: str,
    path_gaps: str,
    region: str
) -> None:
    all_mitre = read_csv_dicts(path_all_mitre)
    coverage = read_csv_dicts(path_coverage)
    gaps = read_csv_dicts(path_gaps)

    # Covered technique set from coverage techniqueKey
    covered_set = set([r.get("techniqueKey", "").strip() for r in coverage if r.get("techniqueKey", "").strip()])

    # Add "covered" tick column to all mitre
    all_mitre2 = []
    for r in all_mitre:
        rr = dict(r)
        tid = rr.get("techniqueId", "").strip()
        rr = {"covered": ("✓" if tid in covered_set else ""), **rr}
        all_mitre2.append(rr)

    # name lookup (for top technique counts)
    name_lookup = {}
    for r in all_mitre:
        tid = (r.get("techniqueId") or "").strip()
        nm = (r.get("name") or "").strip()
        if tid and tid not in name_lookup:
            name_lookup[tid] = nm

    # Enabled rules estimate: union of ruleName in coverage + any ruleName parsed from gaps notes
    rule_names_coverage = set([r.get("ruleName", "").strip() for r in coverage if r.get("ruleName", "").strip()])
    rule_names_gaps = set()
    for r in gaps:
        notes = r.get("notes", "")
        rn = extract_rule_name_from_notes(notes)
        if rn:
            rule_names_gaps.add(rn)
    enabled_rules_est = len(rule_names_coverage.union(rule_names_gaps))

    # MITRE universe counts
    total_mitre_rows = len(all_mitre2)
    parent_total = sum(1 for r in all_mitre2 if str(r.get("isSubtechnique", "")).lower() in ("false", "0", "", "none"))
    # If the CSV writes True/False, above catches False. If it writes "True", it won't count as parent.
    # This matches your prior output style.
    sub_total = total_mitre_rows - parent_total

    # coverage unique counts
    unique_techniques_covered = len(covered_set)
    covered_parents = len({t for t in covered_set if "." not in t})
    covered_subs = len({t for t in covered_set if "." in t})

    coverage_pct = (unique_techniques_covered / total_mitre_rows * 100) if total_mitre_rows else 0
    parents_pct = (covered_parents / parent_total * 100) if parent_total else 0
    subs_pct = (covered_subs / sub_total * 100) if sub_total else 0

    # gaps counts
    no_mitre_tag_count = sum(1 for r in gaps if r.get("issueType") == "NoMitreTag")
    export_missing_count = sum(1 for r in gaps if r.get("issueType") == "ExportMissing")
    not_covered_count = sum(1 for r in gaps if r.get("issueType") == "NotCovered")

    # Rules per tactic (unique rules per tacticKey)
    tactic_map = {}
    for r in coverage:
        tk = (r.get("tacticKey") or "").strip()
        tname = (r.get("tactic") or "").strip()
        rn = (r.get("ruleName") or "").strip()
        if not tk or not rn:
            continue
        key = (tk, tname)
        tactic_map.setdefault(key, set()).add(rn)

    # mapping rows per tactic
    tactic_rows_map = {}
    for r in coverage:
        tk = (r.get("tacticKey") or "").strip()
        tname = (r.get("tactic") or "").strip()
        if not tk:
            continue
        key = (tk, tname)
        tactic_rows_map[key] = tactic_rows_map.get(key, 0) + 1

    tactic_summary = []
    for (tk, tn), ruleset in tactic_map.items():
        tactic_summary.append({
            "tacticKey": tk,
            "tactic": tn,
            "uniqueRules": len(ruleset),
            "mappingRows": tactic_rows_map.get((tk, tn), 0),
        })
    tactic_summary.sort(key=lambda x: (x["uniqueRules"], x["mappingRows"]), reverse=True)

    # Top techniques by mapping count (include technique name)
    tech_counts = {}
    for r in coverage:
        tid = (r.get("techniqueKey") or "").strip()
        if not tid:
            continue
        tech_counts[tid] = tech_counts.get(tid, 0) + 1

    tech_counts_rows = []
    for tid, cnt in sorted(tech_counts.items(), key=lambda kv: kv[1], reverse=True):
        tech_counts_rows.append({
            "techniqueKey": tid,
            "techniqueName": name_lookup.get(tid, ""),
            "mappingCount": cnt,
        })

    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")

    tactic_summary_tbl = to_html_table(tactic_summary, "tblTacticSummary", max_rows=1000)
    tech_counts_tbl = to_html_table(tech_counts_rows, "tblTechCounts", max_rows=200)
    all_mitre_tbl = to_html_table(all_mitre2, "tblAllMitre", max_rows=1000)
    coverage_tbl = to_html_table(coverage, "tblCoverage", max_rows=1000)
    gaps_tbl = to_html_table(gaps, "tblGaps", max_rows=1000)

    html_out = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Exabeam MITRE Coverage Report</title>
<style>
  :root {{
    --bg: #0b0f14;
    --panel: #0f1720;
    --panel2: #111b26;
    --border: #223042;
    --text: #e7eef8;
    --muted: #9fb1c6;
    --good: #34d399;
    --warn: #fbbf24;
    --bad: #fb7185;
    --shadow: rgba(0,0,0,0.35);
    --radius: 16px;
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    --sans: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
  }}
  body {{
    margin:0;
    font-family: var(--sans);
    background: radial-gradient(1200px 600px at 15% 10%, #122033, transparent 60%),
                radial-gradient(900px 500px at 85% 0%, #101a26, transparent 55%),
                var(--bg);
    color: var(--text);
  }}
  .wrap {{ max-width: 1320px; margin: 0 auto; padding: 20px 18px 60px; }}
  .topbar {{
    display:flex; align-items:center; justify-content:space-between; gap: 14px;
    padding: 14px 16px; border: 1px solid var(--border);
    background: linear-gradient(180deg, var(--panel), rgba(15,23,32,0.65));
    box-shadow: 0 10px 28px var(--shadow); border-radius: var(--radius);
  }}
  .brand {{ display:flex; align-items:center; gap: 12px; min-width: 260px; }}
  .logo {{
    width: 44px; height: 44px; border-radius: 12px;
    background: linear-gradient(135deg, #1a2a3a, #0e1620);
    border: 1px dashed #2b3c52;
    display:flex; align-items:center; justify-content:center;
    overflow:hidden;
  }}
  .logo img {{ width:100%; height:100%; object-fit:contain; display:block; }}
  .logo .fallback {{
    color: var(--muted);
    font-size: 11px;
    font-family: var(--mono);
  }}
  .title {{ display:flex; flex-direction:column; line-height:1.15; }}
  .title h1 {{ margin:0; font-size: 16px; letter-spacing: 0.2px; }}
  .title .sub {{ margin-top:4px; font-size: 12px; color: var(--muted); font-family: var(--mono); }}
  .meta {{ text-align:right; color: var(--muted); font-size: 12px; font-family: var(--mono); }}

  .grid {{ margin-top: 18px; display:grid; grid-template-columns: repeat(12, 1fr); gap: 14px; }}
  .card {{
    grid-column: span 3; padding: 14px 14px;
    border: 1px solid var(--border);
    background: linear-gradient(180deg, var(--panel2), rgba(17,27,38,0.75));
    border-radius: var(--radius);
    box-shadow: 0 10px 24px var(--shadow);
  }}
  .card .label {{ color: var(--muted); font-size: 12px; margin-bottom: 8px; }}
  .card .value {{ font-size: 28px; font-weight: 700; letter-spacing: 0.2px; }}
  .card .hint {{ margin-top: 10px; font-size: 12px; color: var(--muted); }}
  .value.good {{ color: var(--good); }}
  .value.warn {{ color: var(--warn); }}
  .value.bad  {{ color: var(--bad); }}

  .panel {{
    grid-column: span 12;
    padding: 14px 14px 6px;
    border: 1px solid var(--border);
    background: linear-gradient(180deg, var(--panel), rgba(15,23,32,0.7));
    border-radius: var(--radius);
    box-shadow: 0 10px 24px var(--shadow);
  }}
  .panel h2 {{ margin: 2px 0 8px; font-size: 14px; letter-spacing: 0.2px; }}
  .panel .sub {{ margin: 0 0 10px; color: var(--muted); font-size: 12px; }}
  .controls {{ display:flex; flex-wrap:wrap; gap: 10px; margin: 8px 0 12px; }}
  .controls input {{
    flex: 1; min-width: 240px;
    background: #0b121a; color: var(--text);
    border: 1px solid var(--border); border-radius: 12px;
    padding: 10px 12px; outline: none;
    font-family: var(--mono); font-size: 12px;
  }}
  .pill {{
    border: 1px solid var(--border);
    color: var(--muted);
    border-radius: 999px;
    padding: 8px 10px;
    font-family: var(--mono);
    font-size: 12px;
    background: rgba(0,0,0,0.15);
  }}

  table.data-table {{
    width: 100%;
    border-collapse: collapse;
    font-family: var(--mono);
    font-size: 12px;
    margin: 10px 0 16px;
    overflow: hidden;
    border-radius: 14px;
  }}
  table.data-table thead th {{
    text-align:left;
    background: #0b121a;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
    padding: 10px 10px;
    position: sticky;
    top: 0;
    z-index: 2;
  }}
  table.data-table tbody td {{
    padding: 9px 10px;
    border-bottom: 1px solid rgba(34,48,66,0.6);
    vertical-align: top;
  }}
  table.data-table tbody tr:hover {{ background: rgba(125,211,252,0.06); }}

  @media (max-width: 980px) {{
    .card {{ grid-column: span 6; }}
    .meta {{ display:none; }}
  }}
  @media (max-width: 560px) {{
    .card {{ grid-column: span 12; }}
  }}
  .footer-note {{ margin-top: 8px; color: var(--muted); font-size: 12px; font-family: var(--mono); }}
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
          <div class="sub">Exabeam Correlation Rules • Region: {region} • Generated: {generated}</div>
        </div>
      </div>
      <div class="meta">
        <div>Artifacts:</div>
        <div>{os.path.basename(path_all_mitre)}</div>
        <div>{os.path.basename(path_coverage)}</div>
        <div>{os.path.basename(path_gaps)}</div>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <div class="label">Enabled rules (estimated)</div>
        <div class="value good">{enabled_rules_est}</div>
        <div class="hint">Union of rules in coverage + rules flagged in gaps</div>
      </div>

      <div class="card">
        <div class="label">MITRE universe (rows)</div>
        <div class="value">{total_mitre_rows}</div>
        <div class="hint">Parents: {parent_total} • Sub-techniques: {sub_total}</div>
      </div>

      <div class="card">
        <div class="label">Unique techniques covered</div>
        <div class="value warn">{unique_techniques_covered}</div>
        <div class="hint">Parents: {covered_parents}/{parent_total} ({parents_pct:.1f}%) • Subs: {covered_subs}/{sub_total} ({subs_pct:.1f}%)</div>
      </div>

      <div class="card">
        <div class="label">Coverage rows (rule×MITRE)</div>
        <div class="value">{len(coverage)}</div>
        <div class="hint">Each row is one mapping (not one rule)</div>
      </div>

      <div class="card">
        <div class="label">Techniques not covered</div>
        <div class="value bad">{not_covered_count}</div>
        <div class="hint">Strict: requires explicit techniqueKey mapping</div>
      </div>

      <div class="card">
        <div class="label">Rules with no MITRE tags</div>
        <div class="value warn">{no_mitre_tag_count}</div>
        <div class="hint">Enabled rules with empty mitre[] in export</div>
      </div>

      <div class="card">
        <div class="label">Rules missing from export</div>
        <div class="value {"bad" if export_missing_count else "good"}">{export_missing_count}</div>
        <div class="hint">If non-zero: export did not return defs</div>
      </div>

      <div class="card">
        <div class="label">Overall coverage (unique/total)</div>
        <div class="value warn">{coverage_pct:.1f}%</div>
        <div class="hint">{unique_techniques_covered} / {total_mitre_rows}</div>
      </div>

      <div class="panel">
        <h2>Coverage overview</h2>
        <p class="sub">Widgets stacked vertically.</p>

        <div class="panel">
          <h2>Rules per tactic</h2>
          {tactic_summary_tbl}
          <div class="footer-note">uniqueRules = distinct ruleName per tactic. mappingRows = total mappings per tactic.</div>
        </div>

        <div class="panel" style="margin-top:14px;">
          <h2>Top techniques by mapping count</h2>
          {tech_counts_tbl}
          <div class="footer-note">Includes technique name (from ALL MITRE TECHNIQUES).</div>
        </div>
      </div>

      <div class="panel">
        <h2>ALL MITRE TECHNIQUES (preview)</h2>
        <p class="sub">Preview capped to 1000 rows. New column: <span class="pill">covered</span> = ✓ when active coverage exists.</p>
        <div class="controls">
          <input type="text" placeholder="Filter (e.g. ✓, T1110, TA0006, Brute Force)..." oninput="filterTable('tblAllMitre', this.value)">
          <span class="pill">Rows shown: {min(len(all_mitre2), 1000)} / {len(all_mitre2)}</span>
        </div>
        {all_mitre_tbl}
      </div>

      <div class="panel">
        <h2>CURRENT COVERAGE (preview)</h2>
        <p class="sub">Each row is a mapping from a rule to a technique. Preview capped to 1000 rows.</p>
        <div class="controls">
          <input type="text" placeholder="Filter (rule name, TA0006, T1003)..." oninput="filterTable('tblCoverage', this.value)">
          <span class="pill">Rows shown: {min(len(coverage), 1000)} / {len(coverage)}</span>
        </div>
        {coverage_tbl}
      </div>

      <div class="panel">
        <h2>CURRENT GAPS (preview)</h2>
        <p class="sub">NotCovered techniques + rule hygiene issues. Preview capped to 1000 rows.</p>
        <div class="controls">
          <input type="text" placeholder="Filter (NotCovered, NoMitreTag, T1556)..." oninput="filterTable('tblGaps', this.value)">
          <span class="pill">Rows shown: {min(len(gaps), 1000)} / {len(gaps)}</span>
        </div>
        {gaps_tbl}
      </div>
    </div>
  </div>

<script>
function filterTable(tableId, query) {{
  const q = (query || '').toLowerCase().trim();
  const table = document.getElementById(tableId);
  if (!table || !table.tBodies || !table.tBodies[0]) return;
  const rows = table.tBodies[0].rows;
  for (let i = 0; i < rows.length; i++) {{
    const txt = rows[i].innerText.toLowerCase();
    rows[i].style.display = txt.includes(q) ? '' : 'none';
  }}
}}
</script>
</body>
</html>
"""

    with open(out_html_path, "w", encoding="utf-8") as f:
        f.write(html_out)


# =========================================================
# 9) MAIN
# =========================================================
if __name__ == "__main__":
    # Print paths FIRST
    print(f"{ANSI_GREEN}[INFO]{ANSI_RESET} Output folder:             {OUT_DIR}")
    print(f"{ANSI_GREEN}[INFO]{ANSI_RESET} Writing ALL MITRE TECHNIQUES to: {PATH_ALL_MITRE}")
    print(f"{ANSI_GREEN}[INFO]{ANSI_RESET} Writing CURRENT COVERAGE to:      {PATH_COVERAGE}")
    print(f"{ANSI_GREEN}[INFO]{ANSI_RESET} Writing CURRENT GAPS to:          {PATH_GAPS}")
    print(f"{ANSI_GREEN}[INFO]{ANSI_RESET} Writing HTML REPORT to:           {PATH_HTML}")

    # Copy logo if present
    if os.path.exists(ASSETS_LOGO):
        shutil.copyfile(ASSETS_LOGO, OUT_LOGO)
        print(f"{ANSI_GREEN}[INFO]{ANSI_RESET} Copied logo to:                   {OUT_LOGO}")
    else:
        print(f"{ANSI_GREEN}[INFO]{ANSI_RESET} No logo found at assets/logo.png (optional).")

    token = get_access_token()

    # --- MITRE universe ---
    mitre_raw = get_mitre_techniques(token)
    all_mitre_rows = flatten_mitre(mitre_raw)
    write_csv(
        PATH_ALL_MITRE,
        all_mitre_rows,
        ["techniqueId", "name", "isSubtechnique", "parentTechniqueId", "tactics", "externalLink"],
    )

    # --- Correlation rules inventory ---
    all_rules = list_all_correlation_rules(token)
    enabled_rules = [r for r in all_rules if is_rule_enabled(r)] if ENABLED_ONLY else all_rules

    enabled_ids = [get_rule_id(r) for r in enabled_rules]
    enabled_ids = [rid for rid in enabled_ids if rid]

    print(f"\n{ANSI_GREEN}[INFO]{ANSI_RESET} Rules returned by API: {len(all_rules)}")
    print(f"{ANSI_GREEN}[INFO]{ANSI_RESET} Enabled rules (after filter): {len(enabled_rules)}")
    print(f"{ANSI_GREEN}[INFO]{ANSI_RESET} Enabled rule IDs collected: {len(enabled_ids)}")

    if not enabled_ids:
        print("\n[ERROR] No enabled rule IDs found. Likely enabled-detection field mismatch.")
        print("Fix is_rule_enabled() to match your /correlation-rules/v2/rules payload.")
        sys.exit(1)

    # --- Export enabled rule definitions (chunked) ---
    exported_defs = export_rule_definitions(token, enabled_ids)
    print(f"{ANSI_GREEN}[INFO]{ANSI_RESET} Rule definitions returned by export: {len(exported_defs)}")

    # --- Coverage + rule-level gaps ---
    coverage_rows, rule_gap_rows, missing_export_names = build_coverage_and_rule_gaps(enabled_rules, exported_defs)

    write_csv(
        PATH_COVERAGE,
        coverage_rows,
        ["ruleId", "ruleName", "enabled", "tacticKey", "tactic", "techniqueKey", "technique"],
    )

    covered_technique_keys = {r["techniqueKey"] for r in coverage_rows if r.get("techniqueKey")}
    technique_gap_rows = build_technique_gaps(all_mitre_rows, covered_technique_keys)

    # --- Combine gaps into ONE gaps CSV ---
    gaps_rows: list[dict] = []
    gaps_rows.extend(technique_gap_rows)

    for g in rule_gap_rows:
        gaps_rows.append({
            "issueType": g["issueType"],
            "techniqueId": "",
            "name": "",
            "isSubtechnique": "",
            "parentTechniqueId": "",
            "tactics": "",
            "externalLink": "",
            "notes": f"ruleId={g.get('ruleId','')} | ruleName={g.get('ruleName','')} | {g.get('notes','')}",
        })

    write_csv(
        PATH_GAPS,
        gaps_rows,
        ["issueType", "techniqueId", "name", "isSubtechnique", "parentTechniqueId", "tactics", "externalLink", "notes"],
    )

    # --- HTML report ---
    build_html_report(PATH_HTML, PATH_ALL_MITRE, PATH_COVERAGE, PATH_GAPS, REGION)

    # --- Summary ---
    parents = sum(1 for r in all_mitre_rows if not r["isSubtechnique"])
    subs = sum(1 for r in all_mitre_rows if r["isSubtechnique"])
    no_mitre_count = sum(1 for r in rule_gap_rows if r["issueType"] == "NoMitreTag")
    export_missing_count = sum(1 for r in rule_gap_rows if r["issueType"] == "ExportMissing")

    print(
        f"\n{ANSI_GREEN}[SUMMARY]{ANSI_RESET} "
        f"MITRE rows={len(all_mitre_rows)} (techniques={parents}, sub-techniques={subs}) | "
        f"Enabled rules={len(enabled_rules)} | "
        f"Coverage rows (rule×MITRE)={len(coverage_rows)} | "
        f"Rules w/ no MITRE tag={no_mitre_count} | "
        f"Rules missing from export={export_missing_count} | "
        f"Techniques not covered={len(technique_gap_rows)}"
    )

    if missing_export_names:
        print(f"\n{ANSI_GREEN}[INFO]{ANSI_RESET} First 10 rules missing from export:")
        for n in missing_export_names[:10]:

            print(f" - {n}")
