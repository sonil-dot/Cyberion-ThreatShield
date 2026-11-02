# Rule 012 Test Report — Possible BITS Job Abuse

## Rule Details
- **Rule file:** `rule_012_bitsadmin_activity.yml`
- **Detection objective:** Detect `bitsadmin.exe` process-creation events whose command line contains `/create` or `/addfile`.
- **Security relevance:** BITS can support legitimate background transfers but may also be abused for suspicious file-transfer activity.

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
No events matched the tested conditions: an image ending in `\bitsadmin.exe` and a command line containing `/create` or `/addfile`.

## Limitations
No matching example was found in the available datasets. The test was a Python-based field-condition check, not execution through a Sigma detection engine or a live Splunk search. Detection effectiveness remains unconfirmed.

## Potential False Positives
Legitimate background downloads and administrative software deployment may trigger the detection.

## Recommended Next Steps
Test against suitable, authorized BITS job-creation telemetry. Validate the converted query in a supported SIEM environment and assess whether the command-line conditions distinguish suspicious activity from routine transfers.

## Conclusion
Rule 012 passed Sigma CLI validation. No matching events were found in the available datasets, so further testing is required to assess detection effectiveness.


## Validation on public attack sample (Chainsaw v2.17.1)

- Sample: PanacheSysmon_vs_AtomicRedTeam01.evtx (EVTX-ATTACK-SAMPLES, copied to datasets/extra/)
- Command: chainsaw.exe --no-banner hunt datasets\extra\PanacheSysmon_vs_AtomicRedTeam01.evtx -s sigma_rules\rule_012_*.yml --mapping mappings\sigma-event-logs-all.yml --json
- Result: 2 detection(s)
- Event: 2019-07-19 14:48:30.655 and .796 UTC: bitsadmin.exe /create AtomicBITS, then /addfile AtomicBITS (URL to raw.githubusercontent.com) to C:\Windows\Temp\bitsadmin_flag.ps1, parent cmd.exe
- Evidence: data_dictionary/evidence_rule012_extra.json
- Limitations: single public sample, no benign baseline, false-positive rate untested, not run in a live SIEM.
