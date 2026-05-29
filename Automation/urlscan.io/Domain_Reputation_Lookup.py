#urlscan.io Domain Reputation Lookup

import requests
import sys
import json
import time
import wmill

URLSCAN_BASE = "https://urlscan.io/api/v1"


# ─────────────────────────────────────────────
# 1. Submit a scan
# ─────────────────────────────────────────────
def submit_scan(api_key: str, domain: str) -> str:
    """Submit a URL scan for the domain and return the scan UUID."""
    url = f"{URLSCAN_BASE}/scan/"
    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json",
    }
    payload = {
        "url": f"https://{domain}",
        "visibility": "public",       # "public" | "unlisted" | "private"
    }

    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    data = response.json()

    scan_uuid = data.get("uuid")
    if not scan_uuid:
        raise ValueError(f"No UUID returned by scan submission: {data}")

    print(f"[+] Scan submitted. UUID: {scan_uuid}")
    print(f"    View online: {data.get('result', '')}")
    return scan_uuid


# ─────────────────────────────────────────────
# 2. Poll for scan result
# ─────────────────────────────────────────────
def fetch_scan_result(scan_uuid: str, api_key: str, max_wait: int = 60, interval: int = 5) -> dict:
    """Poll the result endpoint until the scan is complete, then return the result."""
    url = f"{URLSCAN_BASE}/result/{scan_uuid}/"
    headers = {"API-Key": api_key}
 
    print(f"[*] Waiting for scan to complete (up to {max_wait}s) ...")
    elapsed = 0
    while elapsed < max_wait:
        time.sleep(interval)
        elapsed += interval
        response = requests.get(url, headers=headers)
 
        if response.status_code == 200:
            print(f"[+] Scan complete after ~{elapsed}s.")
            return response.json()
        elif response.status_code == 404:
            print(f"    [{elapsed}s] Still processing ...")
        else:
            response.raise_for_status()
 
    raise TimeoutError(f"Scan did not complete within {max_wait} seconds. Try fetching later:\n  {url}")
 

# ─────────────────────────────────────────────
# 3. Search historical scans (no new scan)
# ─────────────────────────────────────────────
def search_existing_scans(domain: str, size: int = 5) -> dict:
    """Search urlscan.io for existing scans of the domain."""
    url = f"{URLSCAN_BASE}/search/"
    params = {
        "q": f"domain:{domain}",
        "size": size,
    }
    response = requests.get(url, params=params)
    response.raise_for_status()
    return response.json()


# ─────────────────────────────────────────────
# 4. Print helpers
# ─────────────────────────────────────────────
def print_scan_result(domain: str, data: dict) -> None:
    """Parse and print key reputation fields from a scan result."""
    verdicts   = data.get("verdicts", {})
    page       = data.get("page", {})
    lists      = data.get("lists", {})
    meta       = data.get("meta", {})
    stats      = data.get("stats", {})
    task       = data.get("task", {})

    print(f"\n{'='*65}")
    print(f"  Reputation Report — {domain}")
    print(f"{'='*65}")

    # ── Overall verdict ──
    overall = verdicts.get("overall", {})
    print(f"\n[Verdict]")
    print(f"  Score       : {overall.get('score', 'N/A')}  "
          f"(0 = clean, >50 = suspicious, >75 = malicious)")
    print(f"  Malicious   : {overall.get('malicious', False)}")
    print(f"  Tags        : {', '.join(overall.get('tags', [])) or 'none'}")

    # ── Engine verdicts ──
    for engine in ("urlscan", "community"):
        ev = verdicts.get(engine, {})
        if ev:
            print(f"\n[{engine.capitalize()} Verdict]")
            print(f"  Score       : {ev.get('score', 'N/A')}")
            print(f"  Malicious   : {ev.get('malicious', False)}")
            cats = ev.get("categories", [])
            if cats:
                print(f"  Categories  : {', '.join(cats)}")
            brands = ev.get("brands", [])
            if brands:
                print(f"  Brands      : {', '.join(brands)}")

    # ── Page info ──
    print(f"\n[Page Info]")
    print(f"  Final URL   : {page.get('url', 'N/A')}")
    print(f"  Domain      : {page.get('domain', 'N/A')}")
    print(f"  IP Address  : {page.get('ip', 'N/A')}")
    print(f"  Country     : {page.get('country', 'N/A')}")
    print(f"  Server      : {page.get('server', 'N/A')}")
    print(f"  ASN         : {page.get('asn', 'N/A')}  {page.get('asnname', '')}")
    print(f"  Status      : {page.get('status', 'N/A')}")
    print(f"  Title       : {page.get('title', 'N/A')}")

    # ── TLS / HTTPS ──
    tls = page.get("tlsIssuer") or page.get("tlsValidFrom")
    if tls:
        print(f"\n[TLS]")
        print(f"  Issuer      : {page.get('tlsIssuer', 'N/A')}")
        print(f"  Valid From  : {page.get('tlsValidFrom', 'N/A')}")
        print(f"  Valid Until : {page.get('tlsValidTo', 'N/A')}")

    # ── IPs & domains contacted ──
    ips = lists.get("ips", [])
    domains = lists.get("domains", [])
    if ips:
        print(f"\n[IPs Contacted]  ({len(ips)} total)")
        print(f"  {', '.join(ips[:10])}" + (" ..." if len(ips) > 10 else ""))
    if domains:
        print(f"\n[Domains Contacted]  ({len(domains)} total)")
        for d in domains[:10]:
            print(f"  {d}")
        if len(domains) > 10:
            print(f"  ... and {len(domains)-10} more")

    # ── Certificates ──
    certs = lists.get("certificates", [])
    if certs:
        print(f"\n[Certificates]  ({len(certs)} total)")
        for cert in certs[:3]:
            print(f"  Subject : {cert.get('subjectName', 'N/A')}  "
                  f"Issuer: {cert.get('issuer', 'N/A')}")

    # ── Request / resource stats ──
    if stats:
        print(f"\n[Stats]")
        print(f"  Total requests   : {stats.get('requests', {}).get('total', 'N/A')}")
        print(f"  Unique countries : {stats.get('uniqCountries', 'N/A')}")
        print(f"  Console messages : {stats.get('consoleMsgs', 'N/A')}")

    # ── Screenshot ──
    screenshot = task.get("screenshotURL") or data.get("screenshot")
    if screenshot:
        print(f"\n[Screenshot]  {screenshot}")

    print(f"\n{'='*65}\n")


def print_search_results(domain: str, data: dict) -> None:
    """Print a summary of historical scan results."""
    results = data.get("results", [])
    total   = data.get("total", 0)

    print(f"\n{'='*65}")
    print(f"  Historical Scans — {domain}  (total found: {total})")
    print(f"{'='*65}")

    if not results:
        print("  No previous scans found for this domain.")
        return

    for idx, r in enumerate(results, 1):
        page   = r.get("page", {})
        task   = r.get("task", {})
        result = r.get("result", "")
        stats  = r.get("stats", {})

        print(f"\n  Scan #{idx}")
        print(f"    Date      : {task.get('time', 'N/A')}")
        print(f"    URL       : {page.get('url', 'N/A')}")
        print(f"    IP        : {page.get('ip', 'N/A')}")
        print(f"    Country   : {page.get('country', 'N/A')}")
        print(f"    ASN       : {page.get('asn', 'N/A')}  {page.get('asnname', '')}")
        print(f"    Verdicts  : malicious={stats.get('malicious', 'N/A')}")
        if result:
            print(f"    Result    : {result}")


# ─────────────────────────────────────────────
# 5. Main
# ─────────────────────────────────────────────
def main(domain: str, new_scan: bool):
    # ── Config — edit here or pass via CLI ──────────────────────────
    API_KEY = wmill.get_variable("f/exabeam/URLSCAN/URLSCAN/api_key")
    DOMAIN = domain
    # Set to True to submit a fresh scan; False to search existing scans only
    SUBMIT_NEW_SCAN = new_scan
    # ─────────────────────────────────────────────────────────────────

    print(f"[*] Target domain : {DOMAIN}")
    print(f"[*] Mode          : {'Submit new scan' if SUBMIT_NEW_SCAN else 'Search existing scans'}")

    if SUBMIT_NEW_SCAN:
        # ── New scan ──────────────────────────────────────────────
        try:
            scan_uuid = submit_scan(API_KEY, DOMAIN)
        except requests.HTTPError as e:
            print(f"[ERROR] Scan submission failed: {e.response.status_code} {e.response.text}")
            sys.exit(1)

        try:
            result = fetch_scan_result(scan_uuid, API_KEY)
        except TimeoutError as e:
            print(f"[ERROR] {e}")
            sys.exit(1)
        except requests.HTTPError as e:
            print(f"[ERROR] Result fetch failed: {e.response.status_code} {e.response.text}")
            sys.exit(1)

        print_scan_result(DOMAIN, result)

        # Optionally dump full JSON
        #print(json.dumps(result, indent=2))

    else:
        # ── Search existing scans ─────────────────────────────────
        print(f"[*] Searching urlscan.io for existing scans of: {DOMAIN}")
        try:
            results = search_existing_scans(DOMAIN)
        except requests.HTTPError as e:
            print(f"[ERROR] Search failed: {e.response.status_code} {e.response.text}")
            sys.exit(1)

        print_search_results(DOMAIN, results)


if __name__ == "__main__":
    main()
