#!/usr/bin/env python3
import csv
import os
import requests

TABLE_ID_ENV = "EXABEAM_TABLE_ID"
INPUT_CSV_ENV = "JAMF_CSV_FRIENDLY"
OUTPUT_CSV_ENV = "JAMF_CSV_EXABEAM"

def get_token(exabeam_url: str) -> str:
    r = requests.post(
        f"{exabeam_url}/auth/v1/token",
        headers={"Content-Type": "application/json"},
        json={
            "client_id": os.environ["EXABEAM_API_KEY"],
            "client_secret": os.environ["EXABEAM_API_SECRET"],
            "grant_type": "client_credentials",
        },
        timeout=30,
        verify=True,
    )
    r.raise_for_status()
    return r.json()["access_token"]

def get_mapping(exabeam_url: str, token: str, table_id: str) -> dict[str, str]:
    r = requests.get(
        f"{exabeam_url}/context-management/v1/tables/{table_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
        verify=True,
    )
    r.raise_for_status()
    data = r.json()
    return {a["displayName"]: a["id"] for a in data.get("attributes", [])}

def main():
    exabeam_url = (os.environ.get("EXABEAM_URL") or "").rstrip("/")
    table_id = os.environ.get(TABLE_ID_ENV) or ""
    input_csv = os.environ.get(INPUT_CSV_ENV) or ""
    output_csv = os.environ.get(OUTPUT_CSV_ENV) or ""

    if not exabeam_url:
        raise SystemExit("EXABEAM_URL is not set")
    if not table_id:
        raise SystemExit(f"{TABLE_ID_ENV} is not set")
    if not input_csv:
        raise SystemExit(f"{INPUT_CSV_ENV} is not set")
    if not output_csv:
        raise SystemExit(f"{OUTPUT_CSV_ENV} is not set")

    token = get_token(exabeam_url)
    mapping = get_mapping(exabeam_url, token, table_id)

    with open(input_csv, newline="") as fin:
        reader = csv.DictReader(fin)
        in_fields = reader.fieldnames or []
        out_fields = [mapping.get(f, f) for f in in_fields]
        rows = list(reader)

    with open(output_csv, "w", newline="") as fout:
        writer = csv.DictWriter(fout, fieldnames=out_fields)
        writer.writeheader()
        for row in rows:
            out_row = {mapping.get(k, k): v for k, v in row.items()}
            writer.writerow(out_row)

    print(f"Mapped CSV written: {output_csv}")
    print("Headers:", out_fields)

if __name__ == "__main__":
    main()
