# GreyNoise IP Reputation Playbook — outline

Looks up every source IP on a case in GreyNoise, formats the results as HTML, and writes them to the case as a note.

- **Trigger:** No Trigger (run manually from a case). Switch to **Case Created** to enrich every new case automatically.
- **Type:** Advanced (for loop + branch)

## Prerequisites checklist

- [ ] Service `GreyNoise` exists (Service Import + configuration parameters)
- [ ] `GreyNoise_Get_IP_Reputation` and `GreyNoise_Format_Report_HTML` are created under that service and **Deployed**
- [ ] A Service Instance named `GreyNoise` exists with `GN_API_KEY` filled in
- [ ] Service `Exabeam_Threat_Center` exists with the `Create_a_note_for_a_case` action deployed (see `Automation/Exabeam/Threat-Center` in the content hub)
- [ ] No Automation Agent needed — GreyNoise is a public SaaS API

## Playbook editor steps

```
Create Playbook
  Name: GreyNoise IP Reputation
  Description: Look up case source IPs in GreyNoise and add a reputation note to the case
  Trigger: No Trigger

  Add Step → For loop                                              (step a)
    Iterator expression = flow_input.src_ips
    Skip failures = on
    Add Step → Select Action → GreyNoise > GreyNoise_Get_IP_Reputation   (step b)
      ip_to_check = flow_input.iter.value

  Add Step → Select Action → GreyNoise > GreyNoise_Format_Report_HTML    (step c)
    report = results.a

  Add Step → Run one Branch                                        (step d)
    Edit Branch 1
      Predicate expression = results.c.status_code == 200
      Add Step → Select Action → Exabeam_Threat_Center > Create_a_note_for_a_case   (step e)
        CASE_UUID    = flow_input.case_id
        NOTE_CONTENT = results.c.html

  Deploy
```

Notes:
- To also check destination IPs, add a second For loop over `flow_input.dest_ips`, or put the VirusTotal `Extract_Public_IP_Addresses` action first and loop over its output — it merges both lists and drops private addresses.
- Free community keys: use `GreyNoise_Community_IP_Lookup` in step b instead. Its output has the same `status_code` / `data.verdict` shape, so steps c–e stay the same.
- To act only on bad IPs, put a branch inside the loop with predicate `results.b.data.verdict == 'malicious'`. If that branch blocks or isolates something, gate it behind an approval step if your Playbook editor has one (check the step's Advanced settings).
- GreyNoise rate-limits lookups. If a loop over many IPs returns 429s, turn off parallel execution or lower max-parallel, and add Retries in the step's Advanced settings if your editor has them.

## How the flow might look underneath (for reference only, not a confirmed import format)

```yaml
value:
  modules:
    - id: a
      value:
        type: forloopflow
        iterator: {expr: flow_input.src_ips, type: javascript}
        skip_failures: true
        modules:
          - id: b
            value:
              path: f/exabeam/GreyNoise/GreyNoise_Get_IP_Reputation
              type: script
              input_transforms:
                ip_to_check: {expr: flow_input.iter.value, type: javascript}
    - id: c
      value:
        path: f/exabeam/GreyNoise/GreyNoise_Format_Report_HTML
        type: script
        input_transforms:
          report: {expr: results.a, type: javascript}
    - id: d
      value:
        type: branchone
        default: []
        branches:
          - expr: "results.c.status_code == 200"
            modules:
              - id: e
                value:
                  path: f/exabeam/Exabeam_Threat_Center/Create_a_note_for_a_case
                  type: script
                  input_transforms:
                    CASE_UUID: {expr: flow_input.case_id, type: javascript}
                    NOTE_CONTENT: {expr: results.c.html, type: javascript}
```

The `forloopflow` module type name comes from Windmill and hasn't been checked against a real Exabeam export.
