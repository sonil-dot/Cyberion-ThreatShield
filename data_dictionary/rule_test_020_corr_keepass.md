# Rule Test 020 - Multiple Remote Threads Into KeePass (correlation)

- Rule: sigma_rules/rule_020_corr_keepass_multiple_threads.yml (event_count, group by SourceProcessGuid, timespan 1m, gte 2), references rule 018
- ATT&CK: T1555.005
- Validation: sigma check passes (correlation rule loads without errors)
- Dataset: CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx
- Method: Chainsaw does not run Sigma correlation rules, so the logic was replicated in PowerShell over the EVTX. Evidence: data_dictionary/evidence_rule020_manual_count.txt
- Result: 2 remote threads from one source process (powershell.exe PID 2856) into KeePass.exe, span 0.27 seconds. This meets gte 2 within 1 minute.
- Status: manually validated, not tool-validated, not run in a SIEM
- Limitations: one public dataset, no benign baseline, false-positive rate untested

## Manual count output

SourceProcessGuid                      Count SpanSeconds
-----------------                      ----- -----------
{365abb72-a512-5cc4-0000-0010c05e1b00}     2        0.27

