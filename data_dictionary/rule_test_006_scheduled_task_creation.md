# Rule 006 Test Report — Scheduled Task Creation

## Rule Details
- **Rule file:** `rule_006_scheduled_task_creation.yml`
- **Detection objective:** Identify `schtasks.exe` process-creation events whose command line contains `/create`.
- **MITRE ATT&CK:** T1053.005 — Scheduled Task/Job: Scheduled Task

## Sigma Validation
The rule passed Sigma CLI validation with:
- Errors: 0
- Condition errors: 0
- Issues: 0

This confirms that the rule passed the CLI checks; it does not establish detection effectiveness.

## Dataset Test
Three available EVTX datasets were examined for Sysmon Event ID 1 process-creation events.

| Dataset | Events checked | Matches |
|---|---:|---:|
| CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx | 0 | 0 |
| evasion_execution_imageload_wuauclt_lolbas.evtx | 2 | 0 |
| LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx | 1 | 0 |
| **Total** | **3** | **0** |

## Result
No events matched both detection conditions: the image ending in `\schtasks.exe` and a command line containing `/create`.

## Limitations
The available datasets did not contain a matching example. Therefore, detection effectiveness has not been confirmed. The dataset check was a Python-based field-condition test, not execution through a Sigma detection engine or a live Splunk search.

## Recommended Next Steps
Test the rule against suitable, authorized scheduled-task creation telemetry and validate the converted query in a supported SIEM environment. Review legitimate administrative task creation to assess potential false positives.

## Conclusion
Rule 006 passed Sigma CLI validation. No matching events were found in the three available datasets, so further testing is required to establish detection effectiveness.

## Validation on public attack sample (Chainsaw v2.17.1)

- Sample: rundll32_cmd_schtask.evtx (EVTX-ATTACK-SAMPLES, copied to datasets/extra/)
- Command: chainsaw.exe --no-banner hunt datasets\extra\rundll32_cmd_schtask.evtx -s sigma_rules\rule_006_*.yml --mapping mappings\sigma-event-logs-all.yml --json
- Result: 1 detection(s)
- Event: 2020-10-23 21:57:36.627 UTC: schtasks /Create /f /XML ...sduchxll.tmp /TN DataUsageHandlers, parent cmd.exe
- Evidence: data_dictionary/evidence_rule006_extra.json
- Limitations: single public sample, no benign baseline, false-positive rate untested, not run in a live SIEM.
