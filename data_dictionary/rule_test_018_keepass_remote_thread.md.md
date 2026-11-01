**# Rule Test 018 - Remote Thread Created in KeePass Process**



**- Rule file: sigma\_rules/rule\_018\_keepass\_remote\_thread.yml**

**- ATT\&CK: T1555.005 (Credential Access)**

**- Validation: sigma check, 0 errors, 0 issues**

**- Dataset: CA\_keepass\_KeeThief\_Get-KeePassDatabaseKey.evtx (68.0 KiB)**

**- Tool: Chainsaw v2.17.1 with sigma-event-logs-all.yml mapping**

**- Command: .\\chainsaw.exe --no-banner hunt <evtx> -s <rule> --mapping .\\mappings\\sigma-event-logs-all.yml**



**## Result**

**2 detections on 2 documents (Sysmon Event ID 8)**

**- Record 7070, 2019-04-27 18:55:04.710 UTC, thread 3796, start ntdll.dll!DbgUiRemoteBreakin**

**- Record 7071, 2019-04-27 18:55:04.980 UTC, thread 1384, start 0x06160000 (no module)**

**Source: powershell.exe PID 2856 -> Target: KeePass.exe PID 2364, host IEWIN7**



**## Limitations**

**Single public dataset, single host, no benign baseline, so the false-positive rate is untested.**



**## False positives**

**Security or accessibility software injecting into KeePass; some KeePass plugins.**

