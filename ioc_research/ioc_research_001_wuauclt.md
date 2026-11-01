# IOC Research 001 — Suspicious wuauclt Activity

## 1. Investigation Context
- Related case: CT-IR-001
- Dataset: evasion_execution_imageload_wuauclt_lolbas
- Host in sample: LAPTOP-JU4M3I0E
- Event ID: Sysmon 1 — Process Creation

## 2. Observed Indicators

### Process Relationship
- Parent process: C:\Windows\System32\wuauclt.exe
- Child process: C:\Windows\System32\cmd.exe

### Parent Command Line
wuauclt.exe /UpdateDeploymentProvider C:\ProgramData\Intel\helpa.dll /RunHandlerComServer

### Observed File Path
C:\ProgramData\Intel\helpa.dll

### Child Process SHA-256
FF79D3C4A0B7EB191783C323AB8363EBD1FD10BE58D8BCC96B07067743CA81D5

## 3. Indicator Assessment
The process relationship and DLL path are leads for investigation, not confirmed malicious IOCs. The SHA-256 value belongs to the observed cmd.exe process; it is not the hash of helpa.dll.

## 4. Recommended Research
1. Obtain the hash of helpa.dll from the original dataset or a preserved sample, if available.
2. Check available file metadata and trusted threat-intelligence sources.
3. Review surrounding Sysmon events for image loads, network activity, and related processes.
4. Compare findings with legitimate Windows Update behavior.
5. Record the source, date, and result of each reputation lookup.

## 5. Research Status
Pending. No external reputation lookup or malware classification has been confirmed in this record.

## 6. Handling Note
Do not block or quarantine a file based solely on its path or this preliminary assessment. Validate findings and follow approved incident-response procedures.
