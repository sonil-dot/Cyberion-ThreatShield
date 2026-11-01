# Incident Report 001 — Suspicious Windows Update Utility Activity

## 1. Case Summary
- Case ID: CT-IR-001
- Dataset: evasion_execution_imageload_wuauclt_lolbas
- Log source: Microsoft-Windows-Sysmon/Operational
- Event ID: 1 — Process Creation
- Event timestamp (UTC): 2020-10-13 20:11:42.277
- Affected host in sample: LAPTOP-JU4M3I0E

## 2. Detection Context
The event records cmd.exe running with wuauclt.exe as its parent. The parent command line references a DLL under C:\ProgramData\Intel\helpa.dll.

## 3. Key Evidence
- Child image: C:\Windows\System32\cmd.exe
- Parent image: C:\Windows\System32\wuauclt.exe
- Parent command line: wuauclt.exe /UpdateDeploymentProvider C:\ProgramData\Intel\helpa.dll /RunHandlerComServer
- User: LAPTOP-JU4M3I0E\bouss
- SHA-256 of child process: FF79D3C4A0B7EB191783C323AB8363EBD1FD10BE58D8BCC96B07067743CA81D5

## 4. Analysis
The parent-child relationship and DLL-related command line warrant investigation. Legitimate Windows utilities can be abused, but unusual command-line arguments alone do not establish malicious activity.

## 5. MITRE ATT&CK Mapping
Candidate behavior: Windows Command Shell execution (T1059