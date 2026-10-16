# Exabeam MITRE Coverage Report

A Python script that measures how well your Exabeam correlation rules cover MITRE ATT&CK. Each run:

1. Pulls the MITRE technique list from Exabeam.
2. Pulls your correlation rules, their trigger history and their MITRE mappings.
3. Writes a **self-contained HTML dashboard**, a **Word executive briefing**, CSVs and an ATT&CK Navigator layer.

The report goes beyond "is a rule mapped?" and asks **"has that rule actually fired?"** Coverage that has never been proven is reported separately from coverage that is working.

## What the report shows

### HTML dashboard

| Tab | What it shows |
|---|---|
| **MITRE ATT&CK Coverage** | Technique matrix in the Outcomes Navigator layout (see below). |
| **Focus** | What to work on next (see below). |
| **Attack Surface** *(beta)* | Coverage by data source (see below). |
| **Threat Groups** | Threat groups known to target a chosen sector, the techniques they use most, and your coverage of each group. |
| **Detection Health** | Rules that have gone quiet, never fired, are noisiest or were auto-disabled. |
| **Changes** | What changed since the previous run for the same region. |
| **Data Tables** | Every technique, rule, mapping and gap, filterable. |

**MITRE ATT&CK Coverage** uses the Outcomes Navigator score bands for each technique:

| Score | Status | Meaning |
|---|---|---|
| 75–100 | Validated | A mapped rule fired in the last 30 days. |
| 50–74 | Quiet | Mapped rules fired before, but not recently. |
| 20–49 | Unvalidated | Mapped rules have never fired. |
| 0 | Not covered | No enabled rule is mapped. |

Within a band, each extra rule in the same state adds 5 points. The overall **Coverage Score** is the average across all techniques, the same aggregation the Outcomes Navigator uses. Click a technique for its details, rules, sub-techniques and the threat groups that use it. The matrix can be exported as CSV.

**Focus** ranks techniques into three lanes by how many threat groups use them:

- **Fix**: rules have gone quiet.
- **Build**: no detection content.
- **Prove**: rules have never fired.

It also shows a top-10 list for the next cycle and exports to CSV.

**Attack Surface** *(beta)* shows, for each data source (by vendor, product, product category and platform):

- event volume
- which rules use the source and whether they fire
- the techniques the source validates
- **starved rules**: rules whose query matches no data, so they cannot fire
- cloud collector health

Use **Tailor report** to choose your sector and the platforms in your environment. Techniques that cannot apply to your platforms are hidden and left out of the score, and threat-group context is ranked for your sector. Choices are saved in your browser.

### Word executive briefing

A short, branded `.docx` for leadership. It covers:

- coverage score and posture
- covered vs. validated techniques
- detection health
- coverage by tactic
- threat exposure for a chosen sector
- a validation plan for never-fired rules, for example by replaying sample logs with a log-replay tool such as Echo
- recommended actions

## Requirements

- Python 3.10 or later.
- An Exabeam New-Scale API key (client ID and secret) with **read** access to:

| API | Used for |
|---|---|
| Correlation rules (list and export) | Rules, trigger history, MITRE mappings |
| MITRE ATT&CK techniques | Technique list |
| Search *(optional)* | Attack Surface tab |
| Cloud Collectors *(optional)* | Attack Surface tab |

  If Search or Cloud Collector access is missing, the run still completes and the Attack Surface tab explains what could not be collected.
- Internet access to `raw.githubusercontent.com` *(optional)*. MITRE's public ATT&CK dataset provides platforms and threat groups. Without it, the report is built without platform and sector filters.

## Install

Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

### 1. Provide credentials

Use environment variables so the secret never appears in your command history or in a file. If they are not set, the script asks for them when it starts.

Windows (PowerShell):

```powershell
$env:EXABEAM_CLIENT_ID = "<your client id>"
$env:EXABEAM_CLIENT_SECRET = "<your client secret>"
```

macOS / Linux:

```bash
export EXABEAM_CLIENT_ID="<your client id>"
read -s EXABEAM_CLIENT_SECRET && export EXABEAM_CLIENT_SECRET
```

### 2. Run the report

Set `--region` to the region of your Exabeam tenant, for example `us-west`, `us-east`, `eu`, `uk`, `ca`, `au`, `sg`, `jp`, `ch` or `sa`.

```powershell
python .\build_mitre_coverage_report.py --region us-west
```

On macOS / Linux use `python3 ./build_mitre_coverage_report.py ...`. The examples below use the Windows form.

The report is written to a new timestamped folder under `.\output\`. Open `mitre_coverage_report_<region>_<timestamp>.html` in a browser.

### Examples

Tailor the Word briefing's threat section to a sector:

```powershell
python .\build_mitre_coverage_report.py --region us-west --sector "Financial services"
```

Available sectors:

- Healthcare
- Financial services
- Government
- Energy & utilities
- Manufacturing & industrial
- Technology & IT services
- Telecommunications
- Defense & aerospace
- Education & research
- Retail & hospitality
- Media & entertainment
- Legal & professional services
- Transportation & logistics
- Non-profit & NGOs

Faster run that skips the per-rule Search queries:

```powershell
python .\build_mitre_coverage_report.py --region us-west --no-surface-deep
```

Coverage report only, without Attack Surface or the Word briefing:

```powershell
python .\build_mitre_coverage_report.py --region us-west --no-surface --no-word
```

Use a 14-day window for "quiet" rules and 14 days of events for the Attack Surface tab:

```powershell
python .\build_mitre_coverage_report.py --region us-west --stale-days 14 --surface-days 14
```

Keep the raw API responses for troubleshooting, then rebuild the report from them later without calling the API:

```powershell
python .\build_mitre_coverage_report.py --region us-west --save-raw
python .\build_mitre_coverage_report.py --region us-west --replay .\output\<run folder>
```

Track changes over time: run on a schedule, for example weekly with Windows Task Scheduler or cron. Each run is compared with the previous run for the same region and output folder automatically.

```powershell
python .\build_mitre_coverage_report.py --region us-west --out-dir D:\Reports\mitre
```

### Options

| Option | Default | Description |
|---|---|---|
| `--region` | `eu` | API region (`api.<region>.exabeam.cloud`). Also read from `EXABEAM_REGION`. |
| `--base-url` | | Override the API base URL entirely. |
| `--client-id` / `--client-secret` | | Credentials. Prefer the `EXABEAM_CLIENT_ID` / `EXABEAM_CLIENT_SECRET` environment variables, because command-line arguments can be saved in shell history. |
| `--stale-days` | `30` | A rule that fired before, but not within this many days, is "Quiet". |
| `--out-dir` | `./output` | Root folder. Each run gets a timestamped subfolder. |
| `--include-disabled` | off | Count disabled rules towards coverage. |
| `--name-contains` | | Only include MITRE techniques whose name contains this text. |
| `--priority-file` | | CSV with `techniqueId,priority[,source]` to rank gaps (lower number = higher priority). |
| `--compare` | latest run | Snapshot file or run folder to compare against. |
| `--no-compare` | off | Skip the comparison with a previous run. |
| `--sector` | | Sector for the Word briefing's threat section. Each viewer picks their own in the HTML report. |
| `--no-word` | off | Skip the Word executive briefing. |
| `--no-surface` | off | Skip the Attack Surface queries. |
| `--surface-days` | `7` | Days of events used for the Attack Surface tab. |
| `--no-surface-deep` | off | Do not run each rule's query against Search. Faster, but only rules that name a product are linked to data sources. |
| `--surface-max-seconds` | `900` | Time budget for the per-rule Search queries. |
| `--attack-data` | `auto` | MITRE ATT&CK dataset: `auto` (cached, refreshed every 30 days), `refresh` (always download) or `off`. |
| `--attack-cache` | `.cache/attack_context.json` | Where the MITRE ATT&CK dataset is cached. |
| `--save-raw` | off | Save the raw API responses (`raw_*.json`) in the run folder. |
| `--replay` | | Rebuild the report from a folder of `raw_*.json` files without calling the API. |

## Output

```text
output/
└── <timestamp>/
    ├── mitre_coverage_report_<region>_<ts>.html      # interactive dashboard
    ├── mitre_executive_briefing_<region>_<ts>.docx   # executive summary
    ├── attack_matrix_<region>_<ts>.csv               # matrix by tactic: score, status, rules, platforms, MITRE URL
    ├── all_mitre_techniques_<region>_<ts>.csv        # every technique and its status
    ├── current_coverage_<region>_<ts>.csv            # one row per rule -> technique mapping
    ├── current_gaps_<region>_<ts>.csv                # uncovered techniques and rule hygiene issues
    ├── rule_health_<region>_<ts>.csv                 # every rule: status, last fired, trigger counts
    ├── navigator_layer_<region>_<ts>.json            # load into https://mitre-attack.github.io/attack-navigator/
    ├── snapshot.json                                 # used to compare the next run with this one
    └── logo.png
```

## Handling the output

The output describes your detection content and its gaps. Treat it as sensitive:

- **Do not commit output to source control.** The included `.gitignore` excludes `output/`, `raw_*.json` and `.cache/`.
- **Raw files are the most sensitive.** `raw_*.json` files (only written with `--save-raw`) contain your full rule definitions, and `raw_surface.json` includes samples of correlation-rule trigger events. Share them only with people who should see that information.
- **Only API calls leave your machine.** The HTML report is self-contained and makes no external requests when opened, apart from links you choose to click. Nothing is sent anywhere other than your Exabeam tenant's API and, to download the public ATT&CK dataset, `raw.githubusercontent.com`.

## Troubleshooting

- **Authentication or 404 errors:** check `--region`. It must match the region of your tenant.

  <img width="241" height="321" alt="Exabeam API regions" src="https://github.com/user-attachments/assets/6d191120-7c68-406d-b9d4-acfe62fa5e69" />
  <img width="488" height="84" alt="Exabeam API base URL" src="https://github.com/user-attachments/assets/a68afd59-6719-4eb7-ace1-b4c7e0837a49" />
- **Attack Surface tab is empty or shows errors:** the API key may lack Search or Cloud Collector read access. The tab's *Collection notes* panel shows the API response. Run with `--save-raw` to keep the full responses in `raw_surface.json`.
- **"Word briefing skipped":** run `pip install -r requirements.txt` to install `python-docx`.
- **Numbers look wrong:** run with `--save-raw` and check the `raw_*.json` files.

## Notes

- Coverage counts enabled correlation rules only (use `--include-disabled` to change this). Auto-disabled rules are reported separately.
- A parent technique counts as covered if any of its sub-techniques is covered. The matrix has a toggle to show direct mappings only.
- "Never fired" does not necessarily mean broken, because some behaviours are rare. It does mean the detection has not been proven to work.
- Trigger data comes from the `lastTriggeredAt` and `timesTriggered` fields of `/correlation-rules/v2/rules`.
- MITRE does not tag threat groups by sector. Sectors are matched from keywords in each group's MITRE description, and the report lists the groups behind every count so they can be checked.
- Events generated by Exabeam itself (vendor `Exabeam`, for example `Correlation Rule` and `Audit Log`) are not counted as data sources.

---

© 2023 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. https://attack.mitre.org/resources/terms-of-use/
ATT&CK is subject to the license linked here and the following copyright: © 2023 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. MITRE ATT&CK and ATT&CK are trademarks of The MITRE Corporation. Exabeam is not affiliated with, sponsored, or endorsed by The MITRE Corporation.
