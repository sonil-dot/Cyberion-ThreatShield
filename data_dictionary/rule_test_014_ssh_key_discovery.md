# Rule 014 Test Report — Possible SSH Private Key Discovery

## Rule Details
- **Rule file:** `rule_014_ssh_key_discovery.yml`
- **Detection objective:** Identify process command lines referencing common SSH private-key paths.
- **Paths monitored:** `\.ssh\id_rsa`, `\.ssh\id_ed25519`, and `\.ssh\id_ecdsa`.
- **Severity:** Medium.

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
No matching events were found. None of the examined process command lines contained the SSH private-key path patterns specified in the rule.

## Limitations
The test used a Python-based field-condition check, not a Sigma detection engine or a live SIEM search. The available datasets contained only three process-creation events, so the absence of matches does not prove the rule is effective or ineffective.

## Potential False Positives
Legitimate SSH administration, key backup, and developer activity may reference private-key paths. Alerts should be investigated using the command, user, process ancestry, and surrounding activity.

## Recommended Next Steps
Test the rule against suitable, authorized process-creation telemetry containing the relevant path patterns. Validate detection behavior using a supported Sigma engine or SIEM and review possible false positives.

## Conclusion
Rule 014 passed Sigma CLI validation. No matching events were found in the available datasets. Further testing is required to assess detection effectiveness.
