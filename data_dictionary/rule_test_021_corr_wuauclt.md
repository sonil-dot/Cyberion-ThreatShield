# Rule Test 021 - Wuauclt Spawning Multiple cmd.exe (correlation)

- Rule: sigma_rules/rule_021_corr_wuauclt_multiple_cmd.yml (event_count, group by ParentProcessGuid, timespan 1m, gte 2), references rule 001
- ATT&CK: T1218
- Validation: sigma check loads the rule; it has 1 open tactic-tag issue (see report limitations)
- Dataset: evasion_execution_imageload_wuauclt_lolbas.evtx
- Method: Chainsaw does not run Sigma correlation rules, so the logic was replicated in PowerShell over the EVTX. Evidence: data_dictionary/evidence_rule021_manual_count.txt
- Result: 2 cmd.exe processes from one wuauclt.exe parent (PID 1716), span 0 seconds. This meets gte 2 within 1 minute.
- Status: manually validated, not tool-validated, not run in a SIEM
- Limitations: one public dataset, no benign baseline, false-positive rate untested

## Manual count output

ParentProcessGuid                      Count SpanSeconds
-----------------                      ----- -----------
{00247c92-09fe-5f86-0000-001051841401}     2           0

