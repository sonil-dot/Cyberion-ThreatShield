# Threat Hunt 001 - wuauclt.exe Loading an Unsigned DLL and Spawning cmd.exe

## 1. Hypothesis
A Windows Update utility (wuauclt.exe) loading a DLL from a non-standard folder and then spawning a command shell indicates LOLBin proxy execution (T1218).

## 2. Data and method
- Dataset: evasion_execution_imageload_wuauclt_lolbas.evtx (3 events: 2 x Sysmon EID 1, 1 x EID 7)
- Method: read EventData fields via Get-WinEvent XML parsing for EID 1 and EID 7; run Sigma rule 001 with Chainsaw v2.17.1; compare ProcessGuid values across events.
- Evidence: data_dictionary/evidence_sysmon_eid7_wuauclt.txt, rule001_chainsaw.json

## 3. Findings
| UtcTime | Event | Detail |
|---|---|---|
| 2020-10-13 20:11:42.268 | EID 7 image load | wuauclt.exe (PID 1716) loaded C:\ProgramData\Intel\helpa.dll. Signed: false, SignatureStatus: Unavailable, file version metadata missing. SHA256 56C5AFF6AC04BDF86EDBC4F0D0F9581F250A4C97DD60FD1179F153AC20230920 |
| 2020-10-13 20:11:42.277 | EID 1 records 2196442, 2196443 | Two cmd.exe (PIDs 6372, 7648) spawned by wuauclt.exe PID 1716. Parent command line: wuauclt.exe /UpdateDeploymentProvider C:\ProgramData\Intel\helpa.dll /RunHandlerComServer |

The ProcessGuid in the image load equals the ParentProcessGuid of both cmd.exe events, so one wuauclt instance loaded the DLL and then spawned both shells, 9 ms apart.

## 4. What the data cannot show (negative results)
- No network (EID 3), file-creation (EID 11), registry or persistence events: the dataset has only 3 events.
- No event shows how helpa.dll arrived on disk.
- The DLL hash has not been looked up in a reputation service.
- No benign baseline, so the false-positive rate is unmeasured.

## 5. Conclusion
**Confirmed.** wuauclt.exe loaded an unsigned DLL from C:\ProgramData\Intel and spawned command shells from it, consistent with T1218 proxy execution.

## 6. Detection outcome
- Rule 001: 2 detections. Tuned variant: 2 detections. Correlation rule 021: count 2 (manually validated).
- Gap found: rules 001 and 021 depend on the cmd.exe child. Nothing detects the unsigned DLL load itself (EID 7). Recommended new rule: wuauclt.exe loading an unsigned DLL from outside System32.

## 7. Follow-up in a real environment
Look up the SHA256, collect helpa.dll, find how it was written (EID 11), check network connections from PID 1716, hunt for wuauclt.exe with /UpdateDeploymentProvider across the estate.