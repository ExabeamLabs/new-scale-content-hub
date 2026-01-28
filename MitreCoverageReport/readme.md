# Exabeam MITRE Coverage Report (CSV + HTML)

This repo contains a single Python script that:
1) Pulls MITRE technique metadata from Exabeam
2) Pulls your correlation rules + exports enabled rule definitions
3) Produces **three CSVs** and a **single self-contained HTML dashboard** showing coverage and gaps

<img width="1450" height="1270" alt="image" src="https://github.com/user-attachments/assets/b922f5e6-a2e9-450b-bafd-7aea64ce40be" />

## Troubleshooting

99% of the time if you are having an issue it's because you are hitting the wrong region with the API, the script is set to EU by default but you may well need one of the following in the region variable..

<img width="241" height="321" alt="image" src="https://github.com/user-attachments/assets/6d191120-7c68-406d-b9d4-acfe62fa5e69" />
<img width="488" height="84" alt="image" src="https://github.com/user-attachments/assets/a68afd59-6719-4eb7-ace1-b4c7e0837a49" />

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
