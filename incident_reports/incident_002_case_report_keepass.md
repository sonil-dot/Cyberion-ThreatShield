# Incident Case Report 002 - PowerShell Remote Thread Injection into KeePass

| Field | Detail |
|---|---|
| Case ID | INC-002 |
| Source | Rule 018, hunts 002 and 003 |
| Dataset | CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx (public EVTX sample) |
| Host | IEWIN7 |
| Log source | Sysmon Event ID 8 (CreateRemoteThread) |
| ATT&CK | T1555.005 Credentials from Password Managers; T1055 Process Injection |
| Closure | True Positive (adversary-emulation sample) |

## 1. Detection
Rule 018 matched 2 events via Chainsaw v2.17.1 ("2 Detections found on 2 documents"). Tuned variant: 1 detection. Correlation rule 020: count 2 in 0.27 s (manually validated). Evidence: data_dictionary/evidence_rule018_chainsaw_output.txt, evidence_rule018_sysmon_eid8.txt, evidence_rule020_manual_count.txt, rule_test_018_keepass_remote_thread.md, tuning/tuning_report.md.

## 2. Timeline (UTC, from raw Sysmon EID 8)
| Time | Record ID | Source | Target | New thread | Start |
|---|---|---|---|---|---|
| 2019-04-27 18:55:04.710 | 7070 | powershell.exe PID 2856 | KeePass.exe PID 2364 | 3796 | ntdll.dll!DbgUiRemoteBreakin (0x76FAEC4B) |
| 2019-04-27 18:55:04.980 | 7071 | powershell.exe PID 2856 | KeePass.exe PID 2364 | 1384 | 0x06160000, no module, no function |

Source: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe. Target: C:\Program Files\KeePass Password Safe 2\KeePass.exe. Note: PowerShell cmdlet output shows local time (IST); the raw UtcTime is 18:55:04.

## 3. Root cause analysis
One PowerShell process created two threads inside KeePass 270 ms apart. The first starts at DbgUiRemoteBreakin, the routine used when a break-in is forced into a process. The second starts at an address with no backing module, consistent with injected code executing. The dataset name (KeeThief, Get-KeePassDatabaseKey) indicates the emulated tool, which targets the KeePass master key in memory. The events alone do not prove the key was extracted.

## 3a. Corroboration (second log source)
Not available. The dataset contains only 2 Sysmon EID 8 events, so corroboration is limited to a single log type. In a real investigation, pull EID 1 for PID 2856 (command line and parent), PowerShell script block logging (4104) and EID 10 on KeePass.

## 4. ATT&CK mapping
| Stage | Technique |
|---|---|
| Thread injected into KeePass | T1055 Process Injection |
| Master key targeted | T1555.005 Credentials from Password Managers |

## 5. Impact
If KeePass was unlocked, the master key and therefore every stored credential may be exposed. Treat all credentials in the database as compromised until shown otherwise.

## 6. Response
Follow playbooks/playbook_003_potential_credential_compromise.md: isolate the host, rotate all passwords in the vault, change the master password and key file, and review authentication logs for use of those credentials.

## 7. Closure and detection gap
- Classification: **True Positive.** A non-KeePass process creating threads inside KeePass has no ordinary explanation here.
- Gap 1: rule 018 is KeePass-specific, so injection into other processes is not covered (hunt 003 found no other pair in this data). Recommended: a generic EID 8 rule for script hosts and LOLBins, with an allow-list.
- Gap 2: the tuned rule 018 (requires DbgUiRemoteBreakin) misses record 7071, the thread most consistent with injected code. The broad rule stays in production.