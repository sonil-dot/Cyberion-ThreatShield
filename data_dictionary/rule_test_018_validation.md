

## Validation on public attack sample (Chainsaw v2.17.1)

- Sample: CA_keefarce_keepass_credump.evtx (EVTX-ATTACK-SAMPLES, copied to datasets/extra/)
- Command: chainsaw.exe --no-banner hunt datasets\extra\CA_keefarce_keepass_credump.evtx -s sigma_rules\rule_018_*.yml --mapping mappings\sigma-event-logs-all.yml --json
- Result: 1 detection(s)
- Event: 2019-04-27 18:47:00.062 UTC: remote thread into KeePass.exe (KeeFarce sample). Second KeePass attack tool, in addition to the 2 detections on the KeeThief sample
- Evidence: data_dictionary/evidence_rule018_extra.json
- Limitations: single public sample, no benign baseline, false-positive rate untested, not run in a live SIEM.
