# Rule 007 Test Report — Windows Service Creation

## Rule Details
- **Rule file:** `rule_007_service_creation.yml`
- **Detection objective:** Detect process-creation events where `sc.exe` executes a command line containing `create`.
- **MITRE ATT&CK:** T1543.003 — Create or Modify System Process: Windows Service

## Sigma Validation
The rule passed Sigma CLI validation:
- Errors: 0
- Condition errors: 0
- Issues: 0

These results confirm that the rule passed the CLI checks, not that it detects real attacks.

## Dataset Test
Three available EVTX datasets were examined for Sysmon Event ID 1 process-creation events.

| Dataset | Events checked | Matches |
|---|---:|---:|
| CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx | 0 | 0 |
| evasion_execution_imageload_wuauclt_lolbas.evtx | 2 | 0 |
| LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx | 1 | 0 |
| **Total** | **3** | **0** |

## Result
No events matched both conditions: the image ending in `\sc.exe` and a command line containing `create`.

## Limitations
The available datasets did not contain a matching example. The test was a Python-based field-condition check, not execution through a Sigma detection engine or a live Splunk search. The absence of matches does not prove that the rule is ineffective.

## Potential False Positives
Legitimate software installations and authorized service administration may create Windows services and trigger this detection.

## Recommended Next Steps
Test against suitable, authorized service-creation telemetry and validate the converted query in a supported SIEM environment. Review false positives and confirm that the rule's command-line matching is sufficiently specific.

## Conclusion
Rule 007 passed Sigma CLI validation. No matching events were found in the available datasets, so further testing is required to assess detection effectiveness.


## Validation on public attack sample (Chainsaw v2.17.1)

- Sample: PanacheSysmon_vs_AtomicRedTeam01.evtx (EVTX-ATTACK-SAMPLES, copied to datasets/extra/)
- Command: chainsaw.exe --no-banner hunt datasets\extra\PanacheSysmon_vs_AtomicRedTeam01.evtx -s sigma_rules\rule_007_*.yml --mapping mappings\sigma-event-logs-all.yml --json
- Result: 1 detection(s)
- Event: 2019-07-19 14:44:08.181 UTC: sc.exe create AtomicTestService binPath= C:\AtomicRedTeam\atomics\T1050\bin\AtomicService.exe, parent cmd.exe
- Evidence: data_dictionary/evidence_rule007_extra.json
- Limitations: single public sample, no benign baseline, false-positive rate untested, not run in a live SIEM.
