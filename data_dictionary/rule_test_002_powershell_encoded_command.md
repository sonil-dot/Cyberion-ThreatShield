# Rule Test 002 — PowerShell Encoded Command Execution

## 1. Test Details
- Rule: `rule_002_powershell_encoded_command.yml`
- Test date: 2026-10-23
- Rule validation: Sigma CLI
- Target behaviour: PowerShell process creation using encoded-command flags

## 2. Syntax Validation
The Sigma CLI check completed with:
- Errors: 0
- Condition errors: 0
- Issues: 0

**Result:** Passed syntax and condition validation.

## 3. Dataset Suitability Review
Three available EVTX datasets were reviewed:

- `LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx`: Contains one Sysmon Event ID 1 recording `HOSTNAME.EXE` launched by `wsmprovhost.exe`.
- `CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx`: The current parser found no Sysmon Event ID 1 records.
- `evasion_execution_imageload_wuauclt_lolbas.evtx`: Contains two Sysmon Event ID 1 records for `cmd.exe`.

None of the observed process-creation events provides a matching PowerShell encoded-command example.

## 4. Test Result
**Status: Not tested against a matching event.**

The rule passed syntax validation, but its detection behaviour has not been confirmed against a suitable encoded-PowerShell event.

## 5. Limitations and Next Actions
- Obtain or generate a safe, controlled test event containing a PowerShell encoded-command flag.
- Evaluate the event's image and command-line fields against the rule conditions.
- Where possible, execute the converted rule using a compatible detection backend.
- Review potential false positives from legitimate administrative scripts.

Syntax validation alone does not establish detection effectiveness.

## Validation on public attack sample (Chainsaw v2.17.1)

- Sample: discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx (EVTX-ATTACK-SAMPLES, copied to datasets/extra/)
- Command: chainsaw.exe --no-banner hunt datasets\extra\discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx -s sigma_rules\rule_002_*.yml --mapping mappings\sigma-event-logs-all.yml --json
- Result: 1 detection(s)
- Event: 2019-05-27 01:28:42.700 UTC: powershell.exe -nop -noni -enc (base64 payload), parent w3wp.exe (IIS worker process)
- Evidence: data_dictionary/evidence_rule002_extra.json
- Limitations: single public sample, no benign baseline, false-positive rate untested, not run in a live SIEM.
