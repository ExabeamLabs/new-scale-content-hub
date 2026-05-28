# Exabeam New-Scale — Windmill Automation Library

A collection of SOAR automation scripts and playbooks built for use with [Windmill](https://www.windmill.dev), designed to extend and automate response workflows within **Exabeam New-Scale** (Threat Centre, Case Management, and beyond).

These automations were built by the SOC team to bridge the gap between Exabeam detection and real-world response — connecting threat intelligence, firewall enforcement, and case documentation into end-to-end automated playbooks.

---

## What Is Windmill?

[Windmill](https://www.windmill.dev) is a workflow automation platform designed for developers and security teams. Think of it as the glue layer between your security tools — you write small Python (or TypeScript, Go, Bash) scripts, chain them together into flows, and Windmill handles the orchestration, scheduling, secrets management, and execution.

In a SOC context, it's a practical alternative to heavyweight commercial SOAR platforms. You get:

- **Flows** — multi-step playbooks where each step is a script, and outputs from one step feed into the next
- **Scripts** — individual actions written in Python or other languages, with auto-generated UI forms
- **Secrets management** — credentials stored securely, never hardcoded
- **Webhooks** — trigger playbooks from external tools (like Exabeam alerts) via HTTP
- **Scheduling** — run automations on a cron schedule
- **Audit logs** — full execution history of every playbook run

Windmill runs within your own environment, keeping your data and credentials fully under your control.

> Large enterprise security teams with 50+ analysts have migrated from platforms like Palo Alto Cortex XSOAR and Tines to Windmill, drawn by the flexibility of writing real code rather than working within the constraints of a proprietary playbook editor.

---

## Why Windmill + Exabeam?

Exabeam New-Scale provides exceptional detection and case management, but response actions — blocking an IP, updating a firewall, posting enriched case notes — still require reaching out to other tools. Windmill fills that gap.

The integration approach used here:

```
Exabeam Alert / Case
        │
        │  Webhook trigger (HTTP POST to Windmill)
        ▼
  Windmill Flow (Playbook)
        │
        ├─ Step 1: Threat Intelligence Enrichment (e.g. VirusTotal)
        ├─ Step 2: Response Action (e.g. firewall block via WinRM/PowerShell)
        └─ Step 3: Write enriched case note back to Exabeam Threat Centre
```

Each step is an independent, reusable script. Mix and match them to build the playbook your use case needs.

---

## Automations in This Library

### 🔒 Exabeam Case Note Writer
**File:** `exabeam_case_note.py`

Posts a richly formatted HTML case note into an Exabeam Threat Centre case. Summarises threat intelligence findings and response actions taken, with proper headings, bullet lists, and bold text — not plain block text.

**The key trick:** Exabeam's case notes API renders HTML directly. Passing HTML tags in the `note` field gives you fully formatted notes in the UI. Most users don't realise this and end up posting unreadable plain text blobs.

**Typical use:** Final step in a playbook — writes the full action summary back to the case so analysts have a complete audit trail without manual effort.

---

### 🖥️ Remote PowerShell Runner (WinRM)
**File:** `winrm_powershell_runner.py`

Connects to any Windows host over WinRM and executes a PowerShell script with named arguments. Originally built to trigger firewall block scripts, but fully generic — works with any `.ps1` script you point it at.

**Typical use:** Middle step in a playbook — receives an IP or entity from an enrichment step, passes it to a local PowerShell script on a Windows host (firewall management server, domain controller, EDR console host), and returns the result.

**Use cases include:**
- Blocking/unblocking IPs on firewalls (FortiGate, Palo Alto, Windows Firewall)
- Disabling Active Directory accounts
- Triggering EDR isolation or scan actions
- Any Windows-based remediation script

---

## Example Playbook: Automated IP Threat Response

This is the full end-to-end playbook these scripts were built for:

```
[Trigger]
Exabeam alert fires on suspicious outbound connection to unknown IP
Webhook fires → Windmill flow starts
        │
        ▼
[Step 1] VirusTotal IP Enrichment
  Input:  IP address from the alert
  Output: Reputation score, malicious/suspicious/harmless report counts,
          country, ASN, AS owner
        │
        │  IF malicious_reports > threshold → continue
        │  ELSE → stop flow, post "no action" note to case
        ▼
[Step 2] Remote PowerShell Runner (WinRM)
  Input:  IP address, firewall credentials (from Windmill Secrets)
  Action: Connects to firewall management host, runs block script
  Output: Execution result (success/failure, stdout, stderr)
        │
        ▼
[Step 3] Exabeam Case Note Writer
  Input:  VT enrichment result + PowerShell execution result + case_id
  Action: Builds formatted HTML case note, POSTs to Exabeam Threat Centre
  Output: Note visible in the case timeline for analyst review
```

**End result:** From alert to blocked IP to documented case note — automated, auditable, no analyst keyboard required.

---

## Getting Started

### Prerequisites

- A running Windmill instance
- An Exabeam New-Scale tenant with API credentials
- Python support enabled in your Windmill workspace (enabled by default)

### Setting Up Secrets

Never hardcode credentials. Store all secrets in Windmill:

1. Go to **Windmill → Variables → New Variable → Secret**
2. Add secrets for: `exabeam_client_id`, `exabeam_client_secret`, `winrm_password`, etc.
3. Reference them in flow steps as `$var:SECRET_NAME`

### Importing a Script

1. Copy the `.py` file content into a new **Windmill Script**
2. Set the language to **Python**
3. The `# requirements:` comment at the top of each script tells Windmill which pip packages to install automatically
4. Save and test with the auto-generated UI form

### Building a Flow

1. Create a new **Windmill Flow**
2. Add steps in sequence, selecting your scripts
3. Wire outputs to inputs: in the flow editor, map e.g. `results.vt_result` from Step 1 into the `vt_result` parameter of Step 3
4. Add a webhook trigger to fire the flow from Exabeam

---

## SOC Use Cases

These building blocks support a range of SOC response scenarios:

| Scenario | Steps Involved |
|----------|---------------|
| Malicious IP — auto block + document | VT enrichment → WinRM firewall block → Exabeam case note |
| Phishing — disable compromised account | AD lookup → WinRM account disable → Exabeam case note |
| IOC sweep — check and document | VT/TI enrichment → conditional branch → Exabeam case note |
| Alert triage support | Enrichment only → Exabeam case note with intel summary |
| Scheduled threat intel refresh | Scheduled flow → enrichment → bulk case updates |

The modular design means each script works standalone or as part of a larger chain. You don't have to use all steps — run just the case note writer on its own if that's all you need.

---

## Useful Links

| Resource | Link |
|----------|------|
| Windmill Documentation | https://www.windmill.dev/docs/intro |
| Windmill — SOAR Use Case Blog | https://www.windmill.dev/blog/windmill-for-soar-case-study |
| Windmill GitHub | https://github.com/windmill-labs/windmill |
| Windmill Secrets & Variables | https://www.windmill.dev/docs/core_concepts/variables_and_secrets |
| Windmill Flow Editor | https://www.windmill.dev/docs/flows/flow_editor |
| Exabeam New-Scale Docs | https://docs.exabeam.com/new-scale-security-operations-platform/ |
| Exabeam New-Scale Content Hub | https://github.com/ExabeamLabs/new-scale-content-hub |

---

## Contributing

Scripts in this library are designed to be generic and reusable. If you build a new action or extend an existing one:

- Keep credentials as parameters (never hardcoded)
- Use placeholder defaults in examples (no real IPs, hostnames, or org names)
- Comment generously — especially anything non-obvious about how the target API behaves
- Include a `README.md` alongside any new script

---

## Licence

MIT — adapt as needed, credit appreciated but not required.
