# Rule 008 Test Report — Possible Local User Account Creation

## Rule Details
- **Rule file:** `rule_008_local_account_creation.yml`
- **Detection objective:** Detect process-creation events where `net.exe` or `net1.exe` has a command line containing both `user` and `/add`.
- **MITRE ATT&CK:** T1136.001 — Create Account: Local Account

## Sigma Validation
The rule passed Sigma CLI validation:
- Errors: 0
- Condition errors: 0
- Issues: 0

These results confirm that the rule passed the CLI checks; they do not establish detection effectiveness.

## Dataset Test
Three available EVTX datasets were examined for Sysmon Event ID 1 process-creation events.

| Dataset | Events checked | Matches |
|---|---:|---:|
| CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx | 0 | 0 |
| evasion_execution_imageload_wuauclt_lolbas.evtx | 2 | 0 |
| LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx | 1 | 0 |
| **Total** | **3** | **0** |

## Result
No events matched all the detection conditions: the image ending in `\net.exe` or `\net1.exe`, with `user` and `/add` both present in the command line.

## Limitations
No matching example was found in the available datasets. The test was a Python-based field-condition check, not execution through a Sigma detection engine or a live Splunk search. The rule's detection effectiveness remains unconfirmed.

## Potential False Positives
Authorized account provisioning by system administrators or IT support may trigger this detection.

## Recommended Next Steps
Test against suitable, authorized local-account creation telemetry and validate the converted query in a supported SIEM environment. Review false positives and ensure that the event fields match the intended log source.

## Conclusion
Rule 008 passed Sigma CLI validation. No matching events were found in the available datasets, so further testing is required to assess detection effectiveness.
