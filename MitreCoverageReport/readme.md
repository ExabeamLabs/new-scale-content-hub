# Exabeam MITRE Coverage Report (CSV + HTML)

This repo contains a single Python script that:
1) Pulls MITRE technique metadata from Exabeam
2) Pulls your correlation rules + exports enabled rule definitions
3) Produces **three CSVs** and a **single self-contained HTML dashboard** showing coverage and gaps

---
## Repo layout


```text
.
├── assets/
│ └── logo.png # Optional: your logo (copied into each output folder)
├── output/
│ └── 20260128_104225Z/
│ ├── all_mitre_techniques_<region>_<ts>.csv
│ ├── current_coverage_<region>_<ts>.csv
│ ├── current_gaps_<region>_<ts>.csv
│ ├── logo.png # Copied from assets/logo.png (if present)
│ └── mitre_coverage_report_<region>_<ts>.html
├── build_mitre_coverage_report.py # (Optional/alt name) script entrypoint in some versions
├── requirements.txt
└── readme.md

## Install Dependencies (requierments.txt)

WINDOWS

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

MAC

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

## Run The Script

WINDOWS

python .\MITRECoverageScriptV1.0.py

MAC

python3 ./MITRECoverageScriptV1.0.py
