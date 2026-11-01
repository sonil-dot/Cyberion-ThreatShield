# Rule 011 Test Report — Possible Windows Event Log Clearing

## Rule Details
- **Rule file:** `rule_011_event_log_clearing.yml`
- **Detection objective:** Detect `wevtutil.exe` process-creation events whose command line contains ` cl ` or `clear-log`.
- **Security relevance:** Event-log clearing can be used to remove evidence of activity, although authorized maintenance may also perform this operation.

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
No events matched the tested conditions: an image ending in `\wevtutil.exe` and a command line containing ` cl ` or `clear-log`.

## Limitations
No matching example was found in the available datasets. The test was a Python-based field-condition check, not execution through a Sigma detection engine or a live Splunk search. Detection effectiveness remains unconfirmed.

## Potential False Positives
Authorized event-log maintenance or administrative testing may trigger this detection.

## Review Note
The Sigma rule contains the condition `' cl '` twice. This duplicate does not add a distinct detection condition and should be reviewed during rule refinement. The current test reflects the rule as written.

## Recommended Next Steps
Test against suitable, authorized event-log clearing telemetry. Validate the converted query in a supported SIEM environment and review command-line matching for accuracy and potential false positives.

## Conclusion
Rule 011 passed Sigma CLI validation. No matching events were found in the available datasets, so further testing is required to assess detection effectiveness.
