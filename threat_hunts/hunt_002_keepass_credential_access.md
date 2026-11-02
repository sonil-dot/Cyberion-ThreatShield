# Threat Hunt 002 - PowerShell Remote Thread Injection into KeePass

## 1. Hypothesis
PowerShell creating remote threads inside KeePass.exe indicates process injection aimed at KeePass memory, consistent with credential-access tooling.

## 2. Data and method
- Dataset: CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx (Sysmon, host IEWIN7). The dataset contains only 2 events, both Sysmon Event ID 8.
- Method: (1) read EventData fields with Get-WinEvent XML parsing; (2) run Sigma rule 018 with Chainsaw v2.17.1.
- Evidence: data_dictionary/evidence_rule018_sysmon_eid8.txt, evidence_rule018_chainsaw_output.txt

## 3. Findings
| Record ID | UtcTime | Thread | Start address | Module / function |
|---|---|---|---|---|
| 7070 | 2019-04-27 18:55:04.710 | 3796 | 0x76FAEC4B | ntdll.dll / DbgUiRemoteBreakin |
| 7071 | 2019-04-27 18:55:04.980 | 1384 | 0x06160000 | none |

Both threads: source C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID 2856), target C:\Program Files\KeePass Password Safe 2\KeePass.exe (PID 2364).

- The first thread starts in ntdll at a break-in routine used when attaching to a process.
- The second thread starts at an address with no backing module, consistent with injected code.
- Two threads from one source within 0.27 seconds.

## 4. What the data cannot show (negative results)
- No process-creation events, so the PowerShell command line and parent are unknown.
- No Event ID 10 (process access), file or network events, so key extraction is not observable.
- No benign baseline, so false-positive rate is unmeasured.

## 5. Conclusion
**Confirmed as process injection into KeePass by PowerShell.** The hypothesis that this is credential-access tooling is supported by the pattern and the dataset name but is **not proven by the logs alone**.

## 6. Detection outcome
- Rule 018: 2 detections (records 7070, 7071).
- Tuned variant (tuning/rule_018_tuned.yml): 1 detection (record 7070); trade-off documented in tuning/tuning_report.md.
- Correlation rule 020: 2 threads from one source process in 0.27 s (manually validated).

## 7. Follow-up in a real environment
Pull Event ID 1 for PID 2856 (command line, parent), PowerShell script block logging (4104), Event ID 10 on KeePass, and file access to the .kdbx database; rotate vault credentials if KeePass was unlocked.