# Rule Test 019 - Process Launched by WinRM Host

* Rule file: sigma\_rules/rule\_019\_wsmprovhost\_any\_child\_process.yml
* ATT\&CK: T1021.006 Remote Services: Windows Remote Management (Lateral Movement)
* Validation: sigma check, 0 errors, 0 issues
* Dataset: LM\_PowershellRemoting\_sysmon\_1\_wsmprovhost.evtx (68.0 KiB)
* Tool: Chainsaw v2.17.1, mapping sigma-event-logs-all.yml

## Result

1 detection on 1 document, Sysmon Event ID 1

* UtcTime 2019-05-16 01:38:19.616, Image C:\\Windows\\System32\\HOSTNAME.EXE, PID 2936
* Parent: C:\\Windows\\system32\\wsmprovhost.exe -Embedding, PID 3332
* User insecurebank\\Administrator, IntegrityLevel High, LogonId 0x15daaf
* Sysmon RuleName: Lateral Movement - Windows Remote Management
* Record ID:18002

Relationship to rule 016

Rule 016 (cmd/powershell/pwsh children only) gave 0 detections on this dataset because the child was HOSTNAME.EXE. Rule 019 (any child) matches. Trade-off: 019 catches any remote command but is noisier where PowerShell remoting is used for administration. 016 is more precise but misses other tools.

## Limitations

Single public dataset with one event, no benign baseline, false-positive rate untested, not run in a live SIEM.

## False positives

Legitimate remote administration, automation and monitoring tools using PowerShell remoting.

