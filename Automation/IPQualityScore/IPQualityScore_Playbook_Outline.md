# IPQualityScore IP Enrichment Playbook

Enriches every public source/destination IP on a case with IPQualityScore reputation data, then posts a single formatted HTML summary to the case as a note.

- **Type:** Advanced (for loop + branch)
- **Trigger:** No Trigger (run manually from Threat Center). Switch to **Case is created** to run it automatically on every new case.
- **Destructive actions:** None. This playbook only reads reputation data and writes a case note, so no approval step is needed. If you extend it to block or isolate based on `fraud_score`, put an approval step in front of that action (check the step's **Advanced** settings in your Playbook editor).

## Build steps

```
Create Playbook
  Name: IPQualityScore IP Enrichment
  Description: Enrich public case IPs with IPQualityScore and add a summary note
  Trigger: No Trigger

  Add Step (a) → Select Action → IPQualityScore > Extract_Public_IP_Addresses
    src_ips  = flow_input.src_ips
    dest_ips = flow_input.dest_ips

  Add Step (b) → For loop
    Iterator expression = results.a
    (Optional) Skip failures = on, so one bad lookup doesn't stop the loop

    Add Step (c) inside the loop → Select Action → IPQualityScore > IPQualityScore_Action_Get_IP_Reputation
      ip_to_check = flow_input.iter.value
      strictness  = 0                                  (static value)

  Add Step (d) → Select Action → IPQualityScore > IPQualityScore_Format_Report_HTML
    report = results.b                                 (array of step c results, one per IP)

  Add Step (e) → Run one Branch
    Edit Branch 1
      Predicate expression = results.d.status_code == 200
      Add Step (f) → Select Action → Exabeam_Threat_Center > Create_a_note_for_a_case
        CASE_UUID    = flow_input.case_id
        NOTE_CONTENT = results.d.html

  Deploy
```

### Optional: flag high-risk IPs

To act only on risky results, add a **Run one Branch** inside the loop after step (c), with a predicate such as:

```
results.c.status_code == 200 && results.c.data.fraud_score >= 85
```

Thresholds of 75 (suspicious) and 85-90 (high risk) are common starting points. Tune them to your environment.

## Prerequisites checklist

- [ ] Service `IPQualityScore` exists (Service Import + configuration parameters — see [readme.md](readme.md))
- [ ] `Extract_Public_IP_Addresses`, `IPQualityScore_Action_Get_IP_Reputation`, and `IPQualityScore_Format_Report_HTML` are created under that service and **Deployed** (draft actions can't be used in a playbook step)
- [ ] A Service Instance named `IPQualityScore` exists with a real `IPQS_API_KEY`
- [ ] Service `Exabeam_Threat_Center` with `Create_a_note_for_a_case` is set up (see [../Exabeam/Threat-Center/readme.md](../Exabeam/Threat-Center/readme.md)) if you use step (f)

## Notes / unconfirmed details

- `results.b` holding an array of each iteration's last-step result is how the underlying Windmill for loop behaves. Confirm it in your tenant by running the playbook once and inspecting step (b)'s output.
- Each IP lookup uses one IPQS credit. Large cases with many public IPs can consume credits quickly.

## Illustrative underlying representation (not a confirmed import format)

```yaml
value:
  modules:
    - id: a
      value:
        path: f/exabeam/IPQualityScore/Extract_Public_IP_Addresses
        type: script
        input_transforms:
          src_ips: {expr: flow_input.src_ips, type: javascript}
          dest_ips: {expr: flow_input.dest_ips, type: javascript}
    - id: b
      value:
        type: forloopflow
        iterator: {expr: results.a, type: javascript}
        skip_failures: true
        modules:
          - id: c
            value:
              path: f/exabeam/IPQualityScore/IPQualityScore_Action_Get_IP_Reputation
              type: script
              input_transforms:
                ip_to_check: {expr: flow_input.iter.value, type: javascript}
                strictness: {type: static, value: 0}
    - id: d
      value:
        path: f/exabeam/IPQualityScore/IPQualityScore_Format_Report_HTML
        type: script
        input_transforms:
          report: {expr: results.b, type: javascript}
    - id: e
      value:
        type: branchone
        default: []
        branches:
          - expr: "results.d.status_code == 200"
            modules:
              - id: f
                value:
                  path: f/exabeam/Exabeam_Threat_Center/Create_a_note_for_a_case
                  type: script
                  input_transforms:
                    CASE_UUID: {expr: flow_input.case_id, type: javascript}
                    NOTE_CONTENT: {expr: results.d.html, type: javascript}
```

The `forloopflow` module type name is Windmill's, and it has not been confirmed in an Exabeam export. Build this playbook through the UI steps above.
