# Windmill Action: Remote PowerShell Script Runner (via WinRM)

A generic Windmill action that connects to any Windows host over WinRM and executes a PowerShell script with named arguments. Built for SOAR automation but useful for any remote Windows task.

- Create simple netuser Powershell scripts and fully automate your AD SOAR responses
- Pull back any system information
- Run local Defender commands
- Connect directly to Firewalls to add IP's to blocklists etc
- Anything you have or can write in Powershell can be run and you can pass variables via switches in the Powershell call (as per below) 

---

## What This Does

This action lets your Windmill playbook reach out to a Windows machine and run a PowerShell script — passing in whatever arguments that script needs, and capturing the full output for audit and downstream use.

Originally built to trigger firewall remediation scripts as part of a SOAR playbook, but it's deliberately generic. Use it for:

- **Firewall response** — block/unblock IPs (FortiGate, Palo Alto, Windows Firewall)
- **Active Directory response** — disable compromised accounts, reset passwords
- **EDR/AV response** — isolate a host, trigger a scan, pull forensic data
- **Any custom remediation script** you've written in PowerShell

---

## How It Works

```
Windmill Playbook Step
        │
        ▼
[This Script]
  Opens WinRM session to target Windows host (NTLM auth)
        │
        ▼
  Runs: powershell -NoProfile -ExecutionPolicy Bypass -File <script_path> -Arg1 val1 -Arg2 val2 ...
        │
        ▼
  Captures stdout, stderr, exit code
        │
        ▼
  Returns formatted summary → available to downstream steps
```

WinRM (Windows Remote Management) is Microsoft's built-in remote management protocol — enabled and managed natively on Windows, no third-party agent needed.

---

## Prerequisites

### On the target Windows machine

WinRM must be enabled and configured. Run these commands **as Administrator** on the target host:

```powershell
# Enable WinRM
Enable-PSRemoting -Force

# Allow connections from your Windmill host IP (replace with your actual IP/range)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.1.0/24" -Force

# Confirm WinRM is listening
Test-WSMan
```

If you're connecting from a non-domain-joined machine, you may also need:

```powershell
# Allow Basic or NTLM auth (NTLM is on by default, this is a sanity check)
Set-Item WSMan:\localhost\Service\Auth\Ntlm -Value $true
```

### Firewall

Port **5985** (HTTP WinRM) must be open between your Windmill instance and the target host. If using HTTPS WinRM, port **5986** instead.

### Service Account

Use a dedicated service account with **least-privilege** access — it only needs rights to:
- Authenticate via WinRM
- Execute the specific script(s) you're targeting

Avoid using domain admin or local administrator accounts for automation.

---

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `password` | `str` | ✅ | Password for the Windows service account. **Store as a Windmill Secret.** |
| `target` | `str` | ✅ | IP address or hostname of the target Windows machine. |
| `username` | `str` | ✅ | Windows account to authenticate as. Format: `DOMAIN\\username` or `username` for local accounts. |
| `script_path` | `str` | ✅ | Full path to the PowerShell script **on the remote machine**. e.g. `C:\Scripts\Invoke-Action.ps1` |
| `script_args` | `dict` | ⬜ | Named arguments to pass to the script. Keys = parameter names, values = argument values. |

### `script_args` Examples

For a firewall block script:
```python
{
    "Action": "block",
    "IPAddress": "1.2.3.4",
    "Group": "blocklist",
    "Port": "443"
}
```

For an AD account disable script:
```python
{
    "Username": "jsmith",
    "Reason": "Automated SOC response - account compromise"
}
```

For a host isolation script:
```python
{
    "HostName": "WORKSTATION01",
    "IsolationMode": "full"
}
```

Each key/value pair becomes `-Key value` on the PowerShell command line, matching your script's `[Parameter]` block.

---

## Output

Returns a formatted string:

```
=== WinRM PowerShell Execution Summary ===
Target Host:  192.168.1.50
Username:     DOMAIN\ServiceAccount
Script Path:  C:\Scripts\Invoke-Action.ps1

Script Arguments:
  -Action: block
  -IPAddress: 1.2.3.4

Return Code: 0  (0 = success)

--- STDOUT ---
Successfully added 1.2.3.4 to blocklist.

--- STDERR ---
<empty>
```

This output is available to downstream Windmill steps — for example, passing it as `fortigate_result` into the [Exabeam case note writer](../exabeam-case-note/).

---

## Secrets Management

Never put passwords directly in the Windmill flow editor as plain text. Use Windmill's built-in secrets:

1. Go to **Windmill → Variables → New Variable → Secret**
2. Store your `password` value there
3. In the flow editor, set the `password` input to reference that secret: `$var:MY_SECRET_NAME`

---

## Playbook Context

This script is designed as the **middle step** in an automated SOAR playbook:

```
[Step 1] Enrichment (e.g. VirusTotal IP lookup)
         → Determines if action is needed
              ↓
[Step 2] THIS SCRIPT — Remote PowerShell Action
         ← Inputs: target, script_path, script_args (populated from Step 1 output)
         → Output: execution summary string
              ↓
[Step 3] Case Note Writer (e.g. Exabeam Threat Centre note)
         ← Input: result from this step
```

---

## Customisation

**Different auth method?** Change `transport="ntlm"` in the `winrm.Session()` call:
- `"basic"` — simple auth (requires HTTPS/5986)
- `"kerberos"` — Kerberos tickets (requires domain-joined Windmill host)
- `"credssp"` — for double-hop scenarios

**HTTPS WinRM?** Change the endpoint to port 5986 and add `server_cert_validation="ignore"` (self-signed) or point to your cert.

**Positional arguments?** The current args loop builds named `-Key Value` pairs. If your script uses positional args, replace the loop with an ordered list.

---

## Dependencies

```
# requirements:
# pywinrm
```

This comment at the top of the script tells Windmill to install `pywinrm` automatically — no manual pip install needed.

---

## Security Considerations

- **Least privilege** — the service account should only have the permissions it absolutely needs.
- **Network segmentation** — WinRM should only be open from your Windmill host to specific target machines, not broad access.
- **Secrets** — all credentials must be stored as Windmill Secrets, never as plain text in the flow definition.
- **Script integrity** — scripts on the remote host should be access-controlled so only authorised accounts can modify them.
- **Logging** — the return summary includes full stdout/stderr and exit code, giving you a complete audit trail for every execution.

---

## Licence

MIT — use freely, adapt as needed, credit appreciated but not required.
