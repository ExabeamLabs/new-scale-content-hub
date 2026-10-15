# Author: Exabeam Labs
# Version: 1.0
# Date updated: Oct 14 2026
# Action Name: GreyNoise_Format_Report_HTML
# Description: Format one or more GreyNoise IP reputation reports as HTML, including only fields with values.

import html
import json
import sys

FIELD_LABELS = {
    "ip": "IP Address",
    "verdict": "Verdict",
    "noise": "Seen Scanning (Noise)",
    "riot": "Known Business Service (RIOT)",
    "rdns": "Reverse DNS",
    "asn": "ASN",
    "cves": "CVEs",
    "vpn": "VPN",
    "vpn_service": "VPN Service",
    "tor": "Tor Exit Node",
    "recommend_block_tags": "Tags Recommending Block",
    "link": "GreyNoise Visualizer",
}


def _has_value(value):
    return value is not None and value != "" and value != []


def _label_for(field_name):
    return FIELD_LABELS.get(field_name, field_name.replace("_", " ").title())


def _format_value(field_name, value):
    if field_name == "link":
        url = html.escape(str(value), quote=True)
        return f'<a href="{url}">{url}</a>'
    if isinstance(value, list):
        return html.escape(", ".join(str(v) for v in value))
    return html.escape(str(value))


def _response_blocks(report):
    blocks = report if isinstance(report, list) else [report]
    for block in blocks:
        if not isinstance(block, dict):
            raise ValueError("Each report must be a JSON object.")
    return blocks


def main(report):
    if isinstance(report, str):
        report = json.loads(report)

    if not isinstance(report, (dict, list)):
        raise ValueError("The report must be a JSON object or array of objects.")

    response_blocks = _response_blocks(report)
    if not response_blocks:
        return {"status_code": 400, "html": "<h4>GreyNoise</h4><p>No reports provided.</p>"}

    block_html = []
    succeeded = 0
    for response in response_blocks:
        status_code = response.get("status_code", 500)
        if status_code != 200:
            error = html.escape(str(response.get("error", "Unknown error")))
            block_html.append(f"<p><b>GreyNoise request failed ({status_code}):</b> {error}</p>")
            continue

        data = response.get("data", {})
        if not isinstance(data, dict):
            raise ValueError("The report data must be a JSON object.")
        succeeded += 1
        items = [f"<li><b>Source:</b> GreyNoise</li>"]
        items.extend(
            f"<li><b>{html.escape(_label_for(field_name))}:</b> {_format_value(field_name, value)}</li>"
            for field_name, value in data.items()
            if _has_value(value)
        )
        block_html.append("<ul>\n" + "\n".join(items) + "\n</ul>")

    html_block = "<h4>GreyNoise IP Reputation Summary</h4>\n"
    html_block += "\n<hr>\n".join(block_html)

    # Report success if any lookup worked; otherwise surface the first failure code
    status_code = 200 if succeeded else response_blocks[0].get("status_code", 500)
    return {"status_code": status_code, "html": html_block}


if __name__ == "__main__":
    input_report = sys.stdin.read() if not sys.argv[1:] else sys.argv[1]
    print(json.dumps(main(input_report)))
