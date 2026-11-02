# Cyberion ThreatShield - Final Report
Project CDL-DET-V2 | Detection Engineering & Threat Hunting Engagement
Author: `[FILL: your name]` | Repo: https://github.com/sonil-dot/Cyberion-ThreatShield

---

## 1. Executive Summary (non-technical)

**What we did.** We built a library of 18 detection rules that turn security logs into alerts, mapped them to the industry-standard MITRE ATT&CK framework, and tested them on real attack recordings.

**What we found.**
- Two attack behaviours were detected in real recordings and fully investigated:
  1. A trusted Windows update program was abused to run a hidden program (case INC-001).
  2. A tool injected itself into a password manager to steal the master key (case INC-002). If this were a real client, every stored password would need to be reset.
- Of 18 rules, **2 are proven against real data** so far. The other 16 are written and syntactically valid but have not yet been tested on matching recordings, so we do not claim they work.

**Biggest risks (coverage gaps).** Phishing delivery, command-and-control traffic, data theft, and remote desktop abuse have no detection (matrix rows marked Not covered).

**Recommendations.**
1. Test the remaining 16 rules on matching attack samples before relying on them.
2. Add detections for the uncovered areas above.
3. Adopt the incident playbooks so response quality does not depend on who is on shift.

## 2. Methodology
- **Data:** public EVTX samples (EVTX-ATTACK-SAMPLES / Mordor-style datasets), 3 files in `datasets/`: KeeThief KeePass sample, wuauclt LOLBAS sample, WSMProvHost PowerShell-remoting sample. No live client data was used. `[FILL: exact download URLs]`
- **Rule authoring:** Sigma format; syntax validated with sigma-cli 3.1.0 (`sigma check sigma_rules`: 0 errors, 0 issues).
- **Rule testing:** Chainsaw v2.17.1 with `mappings/sigma-event-logs-all.yml`. Command pattern:
  `chainsaw.exe --no-banner hunt <evtx> -s <rule.yml> --mapping .\mappings\sigma-event-logs-all.yml`
- **Event inspection:** PowerShell Get-WinEvent, reading EventData from each event's XML.
- **Timestamps:** all UTC. (Get-WinEvent displays local IST.)
- **Version control:** Git/GitHub, commits after each work item.
- **Splunk conversion:** SPL queries were generated with sigma-cli but **not executed** in a live Splunk.

## 3. Data Dictionary
### 3.1 Sysmon Event ID 1 - Process Creation
| Field | Meaning for detection |
|---|---|
| Image / CommandLine | What ran and with which arguments; core of most rules |
| ParentImage / ParentCommandLine | Who launched it; reveals LOLBin abuse (wuauclt parent) |
| User, LogonId, IntegrityLevel | Whose context; Medium vs High shows elevation |
| ProcessGuid / ParentProcessGuid | Stable IDs to link events into a timeline |
| Hashes | IOC lookups |
| OriginalFileName | Detects renamed binaries |

### 3.2 Sysmon Event ID 8 - CreateRemoteThread
| Field | Meaning for detection |
|---|---|
| SourceImage / SourceProcessId | The injector |
| TargetImage / TargetProcessId | The victim process |
| StartAddress | Where the thread begins |
| StartModule / StartFunction | Empty values suggest unbacked (injected) code |
| NewThreadId | Distinguishes multiple threads |

### 3.3 Third source
`[FILL: a third log source type from your datasets. Run this per dataset to list event IDs, then document one more (e.g. EID 7 image load or EID 10 process access):`
`Get-WinEvent -Path .\datasets\<file>.evtx | Group-Object Id | Sort Count -Desc | ft Name,Count]`

## 4. Detection Rule Library
18 rules in `sigma_rules/`, all pass `sigma check`. Results:

| Status | Rules |
|---|---|
| Validated on real data | 001 (2 detections), 018 (2 detections) |
| Written, not validated | 002-016 (no matches in available datasets, or not yet run) |
| Correlation rule, tool validation unconfirmed | 017 (Chainsaw may not support Sigma correlation) |

Per-rule detail: `data_dictionary/rule_test_*.md`. Severity and false-positive notes are in each rule file.

Correlation-style rules: 1 of the 3 required (017). `[FILL: add 2 more, e.g. encoded PowerShell followed by outbound connection; account creation followed by group add]`

## 5. ATT&CK Coverage
See `coverage_matrix/attack_coverage_matrix.csv`: 22 techniques across 8 tactics (Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Lateral Movement, C2/Exfiltration).
- Covered (tested): 2 | Written, not validated: 15 | Not covered: 5
- Technique IDs marked "verify" were assigned from memory and must be checked against attack.mitre.org before submission.

## 6. Tuning Pass
**Rule 018 (KeePass remote thread).**
- Observed: the two real events differ. Record 7070 starts at ntdll.dll!DbgUiRemoteBreakin; record 7071 starts at an unbacked address with no module or function.
- Candidate tuning: add `StartFunction|contains: 'DbgUiRemoteBreakin'`.
- Result: only record 7070 would match; 7071 would be missed. `[FILL: run the tuned rule in Chainsaw and paste the real count]`
- Trade-off: fewer alerts but a false negative on the injected-code variant. Decision: keep the broader rule.

`[FILL: two more tuning passes. Rule 001: restrict to ParentCommandLine containing UpdateDeploymentProvider and re-run. A third rule once more samples are tested.]`

## 7. Threat Hunts
`hunt_001_suspicious_wuauclt.md`, `hunt_002_keepass_credential_access.md`, `correlation_001_winrm.txt`. `[FILL: one-line outcome each: confirmed / inconclusive / ruled out. Confirm one hunt targets a technique with no existing rule.]`

## 8. Incident Case Reports
- INC-001: `incident_reports/incident_001_case_report_wuauclt.md` (True Positive)
- INC-002: `incident_reports/incident_002_case_report_keepass.md` (True Positive)

## 9. IR Playbooks
`playbooks/playbook_001..003`: process injection, remote execution, credential compromise.

## 10. IOC Research
`ioc_research/ioc_research_001_wuauclt.md`, `ioc_research_002_keepass.md`. Key IOCs from real evidence: `C:\ProgramData\Intel\helpa.dll` (path, wuauclt abuse); wuauclt command-line flag `/UpdateDeploymentProvider`; powershell.exe injecting threads into KeePass.exe. Operationalised via rules 001 and 018.

## 11. Limitations (disclosed honestly)
- Only 2 of 18 rules validated on real telemetry; the rest are untested.
- Three small public datasets, single host each; no benign baseline, so false-positive rates are unmeasured.
- Rule 017 correlation not confirmed by a tool.
- Splunk queries generated but never executed.
- Some ATT&CK IDs need manual verification.

## 12. Recommendations
1. Validate rules 002-016 against matching EVTX-ATTACK-SAMPLES files.
2. Cover phishing, C2, exfiltration and RDP.
3. Run a benign-baseline test before deploying any rule at scale.
4. Roll out the playbooks to all shifts.

## Appendix
Repo structure, commit history (`git log --oneline`), Chainsaw outputs in `data_dictionary/`.