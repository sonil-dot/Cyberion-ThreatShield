# Rule 010 Test Report — Possible Windows Firewall Configuration Change

## Rule Details
- **Rule file:** `rule_010_firewall_changes.yml`
- **Detection objective:** Detect `netsh.exe` process-creation events whose command line references `firewall` or `advfirewall` and contains at least one of `set`, `add`, or `delete`.
- **MITRE ATT&CK:** T1562.004 — Impair Defenses: Disable or Modify System Firewall

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
No events matched all the tested conditions: the image ending in `\netsh.exe`, a command line referencing `firewall` or `advfirewall`, and at least one change-related word (`set`, `add`, or `delete`).

## Limitations
No matching example was found in the available

## Validation on public attack sample (Chainsaw v2.17.1)

- Sample: sysmon_13_rdp_settings_tampering.evtx (EVTX-ATTACK-SAMPLES, copied to datasets/extra/)
- Command: chainsaw.exe --no-banner hunt datasets\extra\sysmon_13_rdp_settings_tampering.evtx -s sigma_rules\rule_010_*.yml --mapping mappings\sigma-event-logs-all.yml --json
- Result: 1 detection(s)
- Event: 2019-03-17 20:18:09.272 UTC: netsh advfirewall firewall add rule name="Remote Desktop" dir=in protocol=tcp localport=3389 profile=any action=allow, parent RDPWInst.exe
- Evidence: data_dictionary/evidence_rule010_extra.json
- Limitations: single public sample, no benign baseline, false-positive rate untested, not run in a live SIEM.
