# Author: Exabeam Labs
# Version: 1.2
# Date updated: Sept 21 2026
# Action Name: Format_Report_HTML
# Description: Format a VirusTotal report as HTML, including only fields with values.

import html
import json
import sys

FIELD_LABELS = {
    "ip": "IP Address",
    "url": "URL",
    "domain": "Domain",
    "is_public": "Public IP",
    "reputation_score": "Reputation Score",
    "malicious_reports": "Malicious Reports",
    "suspicious_reports": "Suspicious Reports",
    "harmless_reports": "Harmless Reports",
    "country": "Country",
    "asn": "ASN",
    "as_owner": "AS Owner",
}


def _has_value(value):
    return value is not None and value != "" and value != "Unknown"


def _label_for(field_name):
    return FIELD_LABELS.get(field_name, field_name.replace("_", " ").title())


def _response_blocks(report):
    blocks = report if isinstance(report, list) else [report]
    response_blocks = []
    for block in blocks:
        if not isinstance(block, dict):
            raise ValueError("Each report must be a JSON object.")
        data = block.get("data")
        if isinstance(data, list):
            response_blocks.extend(
                item for item in data if isinstance(item, dict)
            )
        else:
            response_blocks.append(block)
    return response_blocks


def main(report):
    if isinstance(report, str):
        report = json.loads(report)

    if not isinstance(report, (dict, list)):
        raise ValueError("The report must be a JSON object or array of objects.")

    response_blocks = _response_blocks(report)
    for response in response_blocks:
        status_code = response.get("status_code", 500)
        if status_code != 200:
            error = html.escape(str(response.get("error", "Unknown error")))
            return {
                "status_code": status_code,
                "html": f"<h4>VirusTotal request failed</h4><p>{error}</p>",
            }

    block_html = []
    for response in response_blocks:
        data = response.get("data", {})
        if not isinstance(data, dict):
            raise ValueError("The report data must be a JSON object.")
        fields = [("Source", "VirusTotal")]
        fields.extend(
            (_label_for(field_name), value)
            for field_name, value in data.items()
            if _has_value(value)
        )
        items = "\n".join(
            f"<li><b>{html.escape(label)}:</b> {html.escape(str(value))}</li>"
            for label, value in fields
        )
        block_html.append(f"<ul>\n{items}\n</ul>")

    html_block = "<h4>Threat Intelligence Summary</h4>\n"
    html_block += "\n<hr>\n".join(block_html)
    return {"status_code": 200, "html": html_block}


if __name__ == "__main__":
    input_report = sys.stdin.read() if not sys.argv[1:] else sys.argv[1]
    print(json.dumps(main(input_report)))