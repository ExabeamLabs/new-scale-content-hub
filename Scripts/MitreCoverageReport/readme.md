# Exabeam MITRE Coverage Report

A single Python script that:
1) Pulls MITRE technique metadata from Exabeam
2) Pulls your correlation rules, their trigger history, and their MITRE mappings
3) Produces CSVs, an ATT&CK Navigator layer, a **single self-contained HTML dashboard** showing coverage, gaps, and detection health, and a **Word executive briefing**

<img width="1450" height="1270" alt="image" src="https://github.com/user-attachments/assets/b922f5e6-a2e9-450b-bafd-7aea64ce40be" />

## What the report shows

- **ATT&CK coverage matrix** – every technique coloured by the best rule mapped to it:
  - **Validated** – a mapped rule has fired within the last 30 days
  - **Quiet** – mapped rules have fired before, but not recently
  - **Unvalidated** – mapped rules have never fired
  - **Not covered** – no enabled rule maps to it

  The matrix follows the Exabeam Outcomes Navigator layout and score bands:
  - 75–100 = validated (green)
  - 50–74 = quiet (blue)
  - 20–49 = unvalidated (purple)
  - 0 = not covered (dashed tile)

  Within a band, each extra rule in that state adds 5 points. The overall **MITRE ATT&CK Coverage Score** is the average across all techniques, the same formula the Outcomes Navigator uses (see "How was this calculated?" in the report).

  Click a technique for a summary popover, then **See Details** for its full description, mapped rules and sub-techniques. The handle on the right of a tile expands its sub-techniques. **Export MITRE ATT&CK Coverage** downloads the matrix as CSV, sorted by tactic, with platforms, threat groups and MITRE links. The export follows any filters you have applied.
- **Tailoring to your organisation** – on first open (or with **Tailor report**), choose:
  - **Your sector**: technique tiles show how many threat groups that target your sector use them. A **Priority gaps** panel ranks the uncovered or unvalidated techniques those groups use.
  - **Your platforms** (Windows, macOS, Linux, cloud and so on): techniques that can't apply to your environment are hidden and left out of the score, like hidden techniques in the Outcomes Navigator.

  Platforms and threat groups come from the latest MITRE ATT&CK Enterprise release. The script downloads it at most every 30 days and caches it in `.cache/`. MITRE doesn't tag groups by sector, so sectors are matched from keywords in each group's description. The report lists the groups behind every count so you can check them. Choices are remembered in the browser.
- **Executive briefing (Word)** – every run also writes a dark-themed, Exabeam-branded `.docx` summary for leadership. It covers:
  - the coverage score and posture rating
  - the gap between techniques covered and techniques validated
  - detection health, including the rules that went quiet most recently
  - coverage by tactic
  - threat exposure, filtered to your sector with `--sector`
  - an Echo validation plan that ranks never-fired rules for log replay
  - recommended actions for the next 30 days
- **Detection health**:
  - **Gone quiet**: rules that used to fire but haven't in 30 days. This often means a log source or parser has broken.
  - **Never fired**: rules that have never been validated.
  - **Noisiest rules**: candidates for tuning.
  - **Auto-disabled**: rules the platform switched off.
- **Changes since last run** – each run is compared with the previous run for the same region, highlighting rules that stopped firing, rules that were auto-disabled, and coverage gained or lost.
- **Rule hygiene** – rules with no MITRE tags, rules missing from export, and mappings to unknown/deprecated techniques.

## Install

Use Python 3.10 or later.

WINDOWS

    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt

MAC / LINUX

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

## Run

Provide API credentials as environment variables (recommended), as flags, or type them when prompted:

WINDOWS (PowerShell)

    $env:EXABEAM_CLIENT_ID = "..."
    $env:EXABEAM_CLIENT_SECRET = "..."
    python .\build_mitre_coverage_report.py --region eu

MAC / LINUX

    export EXABEAM_CLIENT_ID=...
    export EXABEAM_CLIENT_SECRET=...
    python3 ./build_mitre_coverage_report.py --region eu

### Options

| Option | Default | Description |
|---|---|---|
| `--region` | `eu` | API region (`api.<region>.exabeam.cloud`). Also `EXABEAM_REGION`. |
| `--base-url` | | Override the API base URL entirely. |
| `--client-id` / `--client-secret` | | Credentials (prefer the `EXABEAM_CLIENT_ID` / `EXABEAM_CLIENT_SECRET` env vars). |
| `--stale-days` | `30` | A rule that has fired before but not within this many days is "Quiet". |
| `--out-dir` | `./output` | Root folder; each run gets a timestamped subfolder. |
| `--include-disabled` | off | Count disabled rules towards coverage. |
| `--name-contains` | | Only include MITRE techniques whose name contains this text. |
| `--priority-file` | | CSV with `techniqueId,priority[,source]` to rank gaps (lower number = higher priority). |
| `--compare` | latest run | Snapshot file or run folder to compare against. |
| `--no-compare` | off | Skip the comparison with a previous run. |
| `--save-raw` | off | Save raw API responses (`raw_*.json`) into the run folder. |
| `--replay` | | Rebuild the report from a folder of `raw_*.json` files without calling the API. |
| `--sector` | | Sector for the Word briefing's threat section, e.g. `"Healthcare"`. Viewers choose their own in the HTML report. |
| `--no-word` | off | Skip the Word executive briefing. |
| `--attack-data` | `auto` | MITRE ATT&CK platform/threat-group data: `auto` (cached, refreshed every 30 days), `refresh` (always download), `off`. |
| `--attack-cache` | `.cache/attack_context.json` | Where the MITRE ATT&CK data is cached. |

## Troubleshooting

99% of the time if you are having an issue it's because you are hitting the wrong region with the API. The script uses `eu` by default, but you may need one of the following with `--region`:

<img width="241" height="321" alt="image" src="https://github.com/user-attachments/assets/6d191120-7c68-406d-b9d4-acfe62fa5e69" />
<img width="488" height="84" alt="image" src="https://github.com/user-attachments/assets/a68afd59-6719-4eb7-ace1-b4c7e0837a49" />

If the numbers look wrong, run with `--save-raw` and check the `raw_*.json` files. Note that they contain your rule definitions, so share them with care.

## Output

```text
output/
└── 20261014_102908Z/
    ├── all_mitre_techniques_<region>_<ts>.csv   # every technique + status
    ├── current_coverage_<region>_<ts>.csv       # one row per rule -> technique mapping
    ├── current_gaps_<region>_<ts>.csv           # uncovered techniques + rule hygiene issues
    ├── rule_health_<region>_<ts>.csv            # every rule: status, last fired, trigger counts
    ├── attack_matrix_<region>_<ts>.csv          # matrix by tactic: score, status, rules, MITRE URL
    ├── navigator_layer_<region>_<ts>.json       # load into https://mitre-attack.github.io/attack-navigator/
    ├── mitre_coverage_report_<region>_<ts>.html # the dashboard
    ├── mitre_executive_briefing_<region>_<ts>.docx # executive summary (dark theme - view in Word's Print Layout)
    ├── snapshot.json                            # used to compare the next run with this one
    └── logo.png                                 # copied from assets/logo.png (if present)
```

## Notes

- Coverage counts enabled rules only (use `--include-disabled` to change this). Auto-disabled rules are reported separately.
- A parent technique counts as covered if any of its sub-techniques is covered. The matrix has a toggle to show direct mappings only.
- "Never fired" doesn't necessarily mean broken: some behaviours are rare. It does mean that the detection hasn't been proven to work.
- Trigger data comes from the `lastTriggeredAt` / `timesTriggered` fields on `/correlation-rules/v2/rules`.
- MITRE ATT&CK data is downloaded from MITRE's GitHub (`mitre-attack/attack-stix-data`, about 55 MB). If it can't be reached, the report is still built, but without platform and sector filters.

© 2023 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. https://attack.mitre.org/resources/terms-of-use/
ATT&CK is subject to the license linked here and the following copyright: © 2023 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. MITRE ATT&CK and ATT&CK are trademarks of The MITRE Corporation. Exabeam is not affiliated with, sponsored, or endorsed by The MITRE Corporation.
