# Rule 016 Test Report — Suspicious Command Interpreter Launched by WinRM Host

## Rule Details
- **Rule file:** `rule_016_wsmprovhost_child_process.yml`
- **Detection objective:** Detect `cmd.exe`, `powershell.exe`, or `pwsh.exe` launched by `wsmprovhost.exe`.
- **Security relevance:** This parent-child process relationship may indicate remote command execution that requires investigation.

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
No matching events were found. None of the examined events had `wsmprovhost.exe` as the parent image and one of the specified command interpreters as the child image.

## Limitations
The test used a Python-based field-condition check, not execution through a Sigma detection engine or a live SIEM search. Only three process-creation events were available, so detection effectiveness remains unconfirmed.

## Potential False Positives
Legitimate remote administration and automation can launch command interpreters through WinRM. Alerts should be investigated using the user account, command line, process ancestry, and administrative context.

## Recommended Next Steps
Test the rule against suitable, authorized process-creation telemetry containing the specified parent-child relationship. Validate detection behavior in a supported Sigma engine or SIEM and review potential false positives.

## Conclusion
Rule 016 passed Sigma CLI validation. No matching events were found in the available datasets. Further testing is required to assess detection effectiveness.

## Chainsaw result
0 detections on 0 documents (Chainsaw v2.17.1). The dataset LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx contains one Sysmon EID 1 event (HOSTNAME.EXE, launched by the WinRM host). The rule targets cmd/powershell/pwsh children, so no match is expected. Status: written, not validated.
