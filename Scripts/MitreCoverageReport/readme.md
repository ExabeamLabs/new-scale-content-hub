# Exabeam MITRE Coverage Report

This tool reads the correlation rules in your Exabeam tenant and shows how well they cover the **MITRE ATT&CK** framework, the industry-standard list of attacker techniques.

It goes further than checking whether a rule is mapped to a technique. It also checks **whether that rule has actually fired**. Detections that have never fired are shown separately from detections that are proven to work.

Each run produces:

- **An interactive HTML report** that opens in any web browser. It includes:
  - an ATT&CK coverage matrix
  - a **Focus** list of what to work on next
  - threat groups that target your sector
  - detection health
  - coverage by data source *(beta)*
- **A Word executive briefing**: a short summary for leadership.
- **CSV files** and an **ATT&CK Navigator layer**, for further analysis.

No programming knowledge is needed. Follow the steps below once to set up, then [run the report](#run-the-report) whenever you want an up-to-date view.

---

## One-time setup

### Step 1: Install Python

The tool needs **Python 3.10 or newer**. Check whether you already have it.

**Windows:** open **PowerShell** (press the Start key, type `powershell`, press Enter) and run:

```powershell
python --version
```

**Mac:** open **Terminal** (press `Cmd + Space`, type `terminal`, press Enter) and run:

```bash
python3 --version
```

If you see `Python 3.10` or higher (for example `Python 3.12.4`), go to Step 2. Otherwise, install Python:

- **Windows:**
  1. Download the installer from [python.org/downloads](https://www.python.org/downloads/) and run it.
  2. **On the first screen, tick "Add python.exe to PATH"** before clicking *Install Now*.
  3. Close PowerShell and open it again.
  4. Run `python --version` to check.
- **Mac:**
  1. Download the macOS installer from [python.org/downloads](https://www.python.org/downloads/) and run it.
  2. Close Terminal and open it again.
  3. Run `python3 --version` to check.

> "pip" (Python's package installer) comes with Python, so there is nothing else to install.

### Step 2: Download this tool

1. On the GitHub page for this repository, click the green **Code** button, then **Download ZIP**.
2. Unzip the file.
3. Open the folder `Scripts` → `MitreCoverageReport`. This is the tool's folder. It contains `build_mitre_coverage_report.py`.

You can move the `MitreCoverageReport` folder anywhere you like.

**Windows tip:** put it somewhere with a short path, for example `C:\Tools\MitreCoverageReport`. Windows has a 260-character limit on file paths. A deep folder, such as one inside a long OneDrive or Downloads path, can make Step 4 fail.

### Step 3: Open a terminal in the tool's folder

**Windows:** open the `MitreCoverageReport` folder in File Explorer, click the address bar at the top, type `powershell` and press Enter. A PowerShell window opens, already in that folder.

**Mac:** open Terminal, type `cd ` (with a space after it), drag the `MitreCoverageReport` folder from Finder into the Terminal window, then press Enter.

### Step 4: Install the tool's dependencies

This creates a private copy of Python inside the tool's folder (in `.venv`) and installs the two libraries the tool needs into it. Nothing else on your computer is changed.

**Windows (PowerShell):**

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

**Mac (Terminal):**

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

### Step 5: Get an Exabeam API key

You need a **client ID** and **client secret** for the Exabeam API. An Exabeam administrator can create these in the platform's API key settings. The key needs **read** access to:

| API | Needed for |
|---|---|
| Correlation rules | Everything (required) |
| MITRE ATT&CK techniques | Everything (required) |
| Search | The Attack Surface tab (optional) |
| Cloud Collectors | The Attack Surface tab (optional) |

Treat the client secret like a password. Never paste it into a file or a shared chat.

You also need to know your tenant's **region**, for example `us-west`, `us-east`, `eu`, `uk`, `ca`, `au`, `sg`, `jp`, `ch` or `sa`. Ask your Exabeam administrator if you aren't sure. See also [Troubleshooting](#troubleshooting).

---

## Run the report

Each time you want a report, open a terminal in the tool's folder (Step 3), then run the command below. Replace `us-west` with your region and `Healthcare` with your sector (see the next section).

**Windows (PowerShell):**

```powershell
.venv\Scripts\python build_mitre_coverage_report.py --region us-west --sector "Healthcare"
```

**Mac (Terminal):**

```bash
.venv/bin/python build_mitre_coverage_report.py --region us-west --sector "Healthcare"
```

The tool asks for your **client ID** and **client secret**. The secret is not shown as you type or paste it. That is normal. Press Enter after each one.

A run usually takes a few minutes. The first run also downloads MITRE's public ATT&CK dataset (about 55 MB), which is then reused for 30 days. When it finishes, it prints where the report was saved: a new date-stamped folder inside `output`. Open that folder and:

- double-click **`mitre_coverage_report_….html`** to open the interactive report in your browser
- open **`mitre_executive_briefing_….docx`** in Microsoft Word for the executive summary

### Choose your sector for the Word briefing

The **HTML report** can be tailored at any time. Click **Tailor report** to pick a sector and the platforms in your environment.

The **Word briefing is different**. It is written once, when the report runs, and cannot be filtered afterwards. Its threat section covers:

- **the sector you give with `--sector`**: for example, the techniques used by threat groups that target healthcare, and the groups themselves
- **all sectors**, if you leave `--sector` out. That is much less specific.

The Word briefing always covers all platforms (Windows, macOS, Linux, cloud and so on). Platform filtering is only available in the HTML report.

Use one of these sector names exactly, inside quotes:

| | | |
|---|---|---|
| `"Healthcare"` | `"Financial services"` | `"Government"` |
| `"Energy & utilities"` | `"Manufacturing & industrial"` | `"Technology & IT services"` |
| `"Telecommunications"` | `"Defense & aerospace"` | `"Education & research"` |
| `"Retail & hospitality"` | `"Media & entertainment"` | `"Legal & professional services"` |
| `"Transportation & logistics"` | `"Non-profit & NGOs"` | |

If you mistype a sector, the tool warns you, lists the valid names, and builds the briefing for all sectors.

### Run it regularly

Each run is compared with the previous one. The **Changes** tab shows rules that stopped firing, rules that were auto-disabled, and coverage gained or lost. Running the report weekly is a good way to catch a broken log source or rule early.

### Updating to a newer version

1. Download the new ZIP (Step 2).
2. Copy your old `output` folder into the new `MitreCoverageReport` folder, so the next run can compare with your previous reports.
3. Repeat Steps 3 and 4 in the new folder.

To see which version you have, run the tool with `--version`. The version is also printed when the tool starts and shown at the bottom of each report.

### Upgrading from version 1

Version 1 of this script asked you to edit the region, client ID and secret into the script file. **That is no longer needed.** The tool asks for the credentials when it runs, and the region is set with `--region`. Don't put credentials in the script, especially if you keep it in a git repository. The command, file name and `output` folder are unchanged.

---

## What's in the report

| HTML tab | What it shows |
|---|---|
| **MITRE ATT&CK Coverage** | Every technique as a tile, coloured by how well it is covered. Click a tile for its details, the rules mapped to it, and the threat groups that use it. **Export MITRE ATT&CK Coverage** downloads it as CSV. |
| **Focus** | What to work on next, in three lanes: **Fix** (rules that have gone quiet), **Build** (no detection yet) and **Prove** (rules that have never fired). Ranked by how many threat groups use each technique. |
| **Attack Surface** *(beta)* | Your data sources: what is sending data, which rules use each source, and whether those rules fire. Also shows cloud collector health and rules that receive no data at all. |
| **Threat Groups** | Threat groups known to target your sector, the techniques they use most, and how much of each group's activity you cover. |
| **Detection Health** | Rules that have gone quiet, never fired, are noisiest, or were switched off by the platform. |
| **Changes** | What changed since the previous run. |
| **Data Tables** | Every technique, rule and gap, with filters. |

Technique scores follow the Exabeam Outcomes Navigator colour bands:

| Score | Colour | Meaning |
|---|---|---|
| 75–100 | Green | **Validated**: a mapped rule fired in the last 30 days |
| 50–74 | Blue | **Quiet**: mapped rules fired before, but not recently |
| 20–49 | Purple | **Unvalidated**: mapped rules have never fired |
| 0 | Dashed tile | **Not covered**: no enabled rule is mapped |

The **MITRE ATT&CK Coverage Score** at the top is the average across all techniques. Click **How was this calculated?** in the report for the breakdown.

The report opens in dark mode. Use the **Light mode** button at the top right to switch. Your browser remembers the choice, as it does your sector and platform choices. The HTML file is fully self-contained, so you can email or share it on its own.

The **Word briefing** summarises:

- the coverage score
- covered vs. proven detections
- detection health and coverage by tactic
- threat exposure for your sector
- a validation plan for rules that have never fired, for example by replaying sample logs with a log-replay tool such as Echo
- recommended next steps

---

## Keep the output private

The report describes your detections **and your gaps**, so handle it like any other sensitive security document:

- **Share with care.** Share the report only with people who should see it, and don't upload it anywhere public.
- **Keep it out of source control.** If you keep the tool in your own git repository, the included `.gitignore` already excludes the `output` folder.
- **Only API calls leave your computer.** The tool talks only to your Exabeam tenant's API and downloads MITRE's public ATT&CK data from GitHub. The HTML report doesn't load anything from the internet when you open it.

---

## Troubleshooting

**`python` is not recognised (Windows) or `command not found` (Mac)**
- **Windows:** re-run the Python installer, choose *Modify*, and make sure *Add Python to environment variables* is ticked. Then close and reopen PowerShell. You can also try `py` instead of `python` in Step 4.
- **Mac:** use `python3`, not `python`.

**`No such file or directory` / `cannot find the path`**
Your terminal is not in the tool's folder. Repeat Step 3.

**Step 4 fails on Windows with `OSError: [Errno 2] No such file or directory` and a hint about "Long Path support"**
The folder path is too long for Windows.
1. Delete the `.venv` folder.
2. Move `MitreCoverageReport` to a short path, for example `C:\Tools\MitreCoverageReport`.
3. Repeat Steps 3 and 4.

**`.venv\Scripts\python` (or `.venv/bin/python`) not found**
Step 4 hasn't been run in this folder yet. Run it again.

**Token request failed, 401 or 404 errors**
Usually the wrong `--region`. It must match your tenant's region:

<img width="241" height="321" alt="Exabeam API regions" src="https://github.com/user-attachments/assets/6d191120-7c68-406d-b9d4-acfe62fa5e69" />
<img width="488" height="84" alt="Exabeam API base URL" src="https://github.com/user-attachments/assets/a68afd59-6719-4eb7-ace1-b4c7e0837a49" />

It can also mean the client ID or secret was pasted incorrectly. Run the command again and re-enter them.

**"Could not reach …" or a certificate error on a corporate network**
Your network may need a proxy, or it may inspect HTTPS traffic. Ask your IT team for the proxy address and/or your organisation's CA certificate file, then set them before running.

Windows (PowerShell):

```powershell
$env:HTTPS_PROXY = "http://proxy.example.com:8080"            # if a proxy is required
$env:REQUESTS_CA_BUNDLE = "C:\path\to\your-company-ca.pem"     # if HTTPS is inspected
```

Mac (Terminal):

```bash
export HTTPS_PROXY="http://proxy.example.com:8080"            # if a proxy is required
export REQUESTS_CA_BUNDLE="/path/to/your-company-ca.pem"      # if HTTPS is inspected
```

These settings last until you close the window. Setting them also helps if Step 4 cannot download the libraries.

**"is not a valid Exabeam API address" or "is not a known Exabeam region"**
The `--region` value is misspelled. Use one of `us-west`, `us-east`, `eu`, `uk`, `ca`, `au`, `sg`, `jp`, `ch` or `sa`.

**The Attack Surface tab is empty or shows errors**
The API key probably lacks Search or Cloud Collector read access. The tab's *Collection notes* panel shows the reason. The rest of the report is unaffected.

**"Word briefing skipped"**
The dependencies weren't installed into `.venv`. Repeat Step 4.

**The run takes a long time**
Most of the time goes on the Attack Surface checks, which run one search per rule. Add `--no-surface-deep` for a faster run, or `--no-surface` to skip that tab entirely.

**The Word briefing looks different in Google Docs or Pages**
The briefing is designed for Microsoft Word. Other editors can move tables and colours around.

**Asking for help**
Include:
- the version (run with `--version`)
- your operating system
- the command you ran, with any secrets removed
- the error message

Never share your client secret. Don't post the `output` folder or any `raw_*.json` files publicly, because they describe your detections and gaps.

---

## Advanced options

<details>
<summary>Command-line options, scheduled runs and troubleshooting files</summary>

### Options

Add any of these to the run command.

| Option | Default | What it does |
|---|---|---|
| `--region` | `eu` | Your tenant's API region (`api.<region>.exabeam.cloud`). |
| `--sector` | all sectors | Sector for the Word briefing's threat section. See [Choose your sector](#choose-your-sector-for-the-word-briefing). |
| `--stale-days` | `30` | A rule that fired before, but not within this many days, is "Quiet". |
| `--out-dir` | `./output` | Where reports are saved. Each run gets its own date-stamped folder. |
| `--no-word` | off | Don't create the Word briefing. |
| `--no-surface` | off | Skip the Attack Surface tab. |
| `--no-surface-deep` | off | Faster Attack Surface: don't run each rule's search to see which data sources feed it. |
| `--surface-days` | `7` | Days of data used for the Attack Surface tab. |
| `--surface-max-seconds` | `900` | Time limit for the per-rule searches. |
| `--include-disabled` | off | Also count disabled rules as coverage. |
| `--compare` | previous run | Compare against a specific earlier run folder. |
| `--no-compare` | off | Don't compare with the previous run. |
| `--priority-file` | | CSV with `techniqueId,priority[,source]` to rank gaps by your own priorities. |
| `--attack-data` | `auto` | MITRE ATT&CK dataset (platforms and threat groups): `auto` (cached, refreshed every 30 days), `refresh` (always download) or `off`. |
| `--attack-cache` | `.cache/attack_context.json` | Where the MITRE ATT&CK dataset is cached. |
| `--name-contains` | | Only include MITRE techniques whose name contains this text. |
| `--base-url` | | Use a custom API base URL instead of `--region`. |
| `--save-raw` | off | Also save the raw API responses (`raw_*.json`). These are useful for troubleshooting, but they contain your full rule definitions, so share them with care. |
| `--replay` | | Rebuild a report from a folder of `raw_*.json` files without connecting to Exabeam. |

### Scheduled (unattended) runs

To run on a schedule, for example weekly with Windows Task Scheduler or cron, the tool can't ask for credentials. Instead, provide them as environment variables, `EXABEAM_CLIENT_ID` and `EXABEAM_CLIENT_SECRET`, using your operating system's secure secret storage or your scheduler's credential features. **Never write the secret into a script or a file in this folder.** The region can also be set with `EXABEAM_REGION`.

Use a fixed `--out-dir` so that each run can be compared with the last one.

### Output files

```text
output/
└── <date-stamp>/
    ├── mitre_coverage_report_<region>_<ts>.html      # interactive report - open in a browser
    ├── mitre_executive_briefing_<region>_<ts>.docx   # executive summary - open in Word
    ├── attack_matrix_<region>_<ts>.csv               # every technique by tactic: score, status, rules, platforms, MITRE link
    ├── all_mitre_techniques_<region>_<ts>.csv        # every technique and its status
    ├── current_coverage_<region>_<ts>.csv            # one row per rule -> technique mapping
    ├── current_gaps_<region>_<ts>.csv                # uncovered techniques and rule hygiene issues
    ├── rule_health_<region>_<ts>.csv                 # every rule: status, last fired, trigger counts
    ├── navigator_layer_<region>_<ts>.json            # load into https://mitre-attack.github.io/attack-navigator/
    └── snapshot.json                                 # used to compare the next run with this one
```

### How it works

- **What counts as coverage:**
  - Only enabled correlation rules count as coverage.
  - A parent technique counts as covered if any of its sub-techniques is covered.
  - "Never fired" doesn't necessarily mean broken (some behaviours are rare), but the detection hasn't been proven.
- **Data sources:**
  - Firing data comes from the `lastTriggeredAt` and `timesTriggered` fields of the correlation rules API.
  - Platforms and threat groups come from MITRE's public ATT&CK dataset (about 55 MB, cached for 30 days).
- **Sectors:** MITRE doesn't tag threat groups by sector, so sectors are matched from keywords in each group's description. The report lists the groups behind every number so they can be checked.
- **Attack Surface:**
  - It uses a grouped Search query on `vendor`, `product`, `product_category` and `platform`, plus the Cloud Collector API.
  - Events generated by Exabeam itself (vendor `Exabeam`, such as `Correlation Rule`) aren't counted as data sources.

</details>

---

© 2023 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. https://attack.mitre.org/resources/terms-of-use/
ATT&CK is subject to the license linked here and the following copyright: © 2023 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. MITRE ATT&CK and ATT&CK are trademarks of The MITRE Corporation. Exabeam is not affiliated with, sponsored, or endorsed by The MITRE Corporation.
