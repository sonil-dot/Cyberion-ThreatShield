# Incident Report 002 — PowerShell Remote Thread in KeePass

## 1. Case Summary
- Case ID: CT-IR-002
- Dataset: CA_keepass_KeeThief_Get-KeePassDatabaseKey
- Log source: Microsoft-Windows-Sysmon/Operational
- Event ID: 8 — CreateRemoteThread
- Event timestamp (UTC): 2019-04-27 18:55:04.980
- Affected host in sample: IEWIN7

## 2. Detection Context
The event records Windows PowerShell creating a remote thread inside KeePass.exe. This behavior can be relevant to process-injection investigations.

## 3. Key Evidence
- Source process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- Source process ID: 2856
- Target process: C:\Program Files\KeePass Password Safe 2\KeePass.exe
- Target process ID: 2364
- New thread ID: 1384
- Start address: 0x06160000
- Start module/function: Not provided

## 4. Analysis
Remote-thread creation may occur during process injection, but the event alone does not establish malicious intent or prove that credentials were accessed. The initiating script, process history, and surrounding telemetry would be needed to establish what occurred.

## 5. MITRE ATT&CK Mapping
Candidate behavior: Process Injection (T1055).

This is a hypothesis based