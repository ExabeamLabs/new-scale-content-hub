# Author: Exabeam Labs
# Version: 1.0
# Date updated: Oct 12 2026
# Action Name: IPQualityScore_Format_Report_HTML
# Description: Format one or more IPQualityScore reports as HTML, including only fields with values.

import html
import json
import sys

# The first key found in a report's data determines its section heading
INDICATOR_TYPES = [
    ("ip", "IP Address"),
    ("url", "URL"),
    ("email", "Email"),
    ("phone", "Phone"),
]

FIELD_LABELS = {
    "ip": "IP Address",
    "url": "URL",
    "email": "Email",
    "phone": "Phone",
    "is_public": "Public IP",
    "fraud_score": "Fraud Score",
    "risk_score": "Risk Score",
    "vpn": "VPN",
    "tor": "TOR",
    "active_vpn": "Active VPN",
    "active_tor": "Active TOR",
    "isp": "ISP",
    "asn": "ASN",
    "voip": "VOIP",
    "dns_valid": "DNS Valid",
    "risky_tld": "Risky TLD",
    "smtp_score": "SMTP Score",
    "ip_address": "IP Address",
    "final_url": "Final URL",
    "page_status_code": "Page Status Code",
    "request_id": "IPQS Request ID",
}


def _has_value(value):
    return value is not None and value != "" and value not in ("Unknown", "N/A") and value != []


def _label_for(field_name):
    return FIELD_LABELS.get(field_name, field_name.replace("_", " ").title())


def _display(value):
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)


def _indicator_heading(data):
    for field_name, label in INDICATOR_TYPES:
        if _has_value(data.get(field_name)):
            return f"{label}: {data[field_name]}"
    return "IPQualityScore Result"


def _response_blocks(report):
    blocks = report if isinstance(report, list) else [report]
    response_blocks = []
    for block in blocks:
        if isinstance(block, str):
            block = json.loads(block)
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
    if not response_blocks:
        return {"status_code": 400, "html": "<h4>IPQualityScore</h4><p>No reports provided.</p>"}

    block_html = []
    failed_status_codes = []
    for response in response_blocks:
        status_code = response.get("status_code", 500)
        if status_code != 200:
            failed_status_codes.append(status_code)
            error = html.escape(str(response.get("error", "Unknown error")))
            block_html.append(f"<p><b>Lookup failed ({status_code}):</b> {error}</p>")
            continue

        data = response.get("data", {})
        if not isinstance(data, dict):
            raise ValueError("The report data must be a JSON object.")
        fields = [("Source", "IPQualityScore")]
        fields.extend(
            (_label_for(field_name), _display(value))
            for field_name, value in data.items()
            if _has_value(value)
        )
        items = "\n".join(
            f"<li><b>{html.escape(label)}:</b> {html.escape(value)}</li>"
            for label, value in fields
        )
        heading = html.escape(_indicator_heading(data))
        block_html.append(f"<h5>{heading}</h5>\n<ul>\n{items}\n</ul>")

    html_block = "<h4>IPQualityScore Threat Intelligence Summary</h4>\n"
    html_block += "\n<hr>\n".join(block_html)

    # 200 if at least one report succeeded, otherwise the first failure's status
    if len(failed_status_codes) == len(response_blocks):
        return {"status_code": failed_status_codes[0], "html": html_block, "failed_count": len(failed_status_codes)}
    return {"status_code": 200, "html": html_block, "failed_count": len(failed_status_codes)}


if __name__ == "__main__":
    input_report = sys.stdin.read() if not sys.argv[1:] else sys.argv[1]
    print(json.dumps(main(input_report)))
