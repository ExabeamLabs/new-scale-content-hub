# Exabeam MITRE Coverage Report

A single Python script that:
1) Pulls MITRE technique metadata from Exabeam
2) Pulls your correlation rules, their trigger history, and their MITRE mappings
3) Produces CSVs, an ATT&CK Navigator layer, and a **single self-contained HTML dashboard** showing coverage, gaps, and detection health

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

  Within a band, each extra rule in that state adds 5 points. Click any technique to open a panel with the rules and sub-techniques behind it.
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
    ├── navigator_layer_<region>_<ts>.json       # load into https://mitre-attack.github.io/attack-navigator/
    ├── mitre_coverage_report_<region>_<ts>.html # the dashboard
    ├── snapshot.json                            # used to compare the next run with this one
    └── logo.png                                 # copied from assets/logo.png (if present)
```

## Notes

- Coverage counts enabled rules only (use `--include-disabled` to change this). Auto-disabled rules are reported separately.
- A parent technique counts as covered if any of its sub-techniques is covered. The matrix has a toggle to show direct mappings only.
- "Never fired" doesn't necessarily mean broken: some behaviours are rare. It does mean that the detection hasn't been proven to work.
- Trigger data comes from the `lastTriggeredAt` / `timesTriggered` fields on `/correlation-rules/v2/rules`.
