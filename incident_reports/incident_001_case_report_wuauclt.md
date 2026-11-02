# Incident Case Report 001 - wuauclt.exe Loading an Unsigned DLL and Spawning cmd.exe

| Field | Detail |
|---|---|
| Case ID | INC-001 |
| Source | Rule 001, hunt 001 |
| Dataset | evasion_execution_imageload_wuauclt_lolbas.evtx (public EVTX sample) |
| Host / User | LAPTOP-JU4M3I0E / bouss |
| Log sources | Sysmon Event ID 1 (process creation), Event ID 7 (image load) |
| ATT&CK | T1218 System Binary Proxy Execution; T1059.003 Windows Command Shell (secondary) |
| Closure | True Positive (adversary-emulation sample) |

## 1. Detection
Rule 001 matched 2 Sysmon EID 1 events via Chainsaw v2.17.1 ("2 Detections found on 2 documents"). Tuned variant: 2 detections. Correlation rule 021: count 2 (manually validated). Evidence: data_dictionary/rule001_chainsaw.json, rule_test_001_wuauclt.md, evidence_sysmon_eid7_wuauclt.txt, evidence_rule021_manual_count.txt.

## 2. Timeline (UTC, from raw Sysmon events)
| Time | Event | Evidence |
|---|---|---|
| 2020-10-13 20:11:42.268 | EID 7: wuauclt.exe (PID 1716) loads C:\ProgramData\Intel\helpa.dll | Signed: false, SignatureStatus Unavailable, version metadata missing. SHA256 56C5AFF6AC04BDF86EDBC4F0D0F9581F250A4C97DD60FD1179F153AC20230920 |
| 2020-10-13 20:11:42.277 | EID 1 record 2196442: wuauclt.exe PID 1716 spawns cmd.exe PID 6372 | ParentImage C:\Windows\System32\wuauclt.exe |
| 2020-10-13 20:11:42.277 | EID 1 record 2196443: same parent spawns cmd.exe PID 7648 | Same ParentProcessGuid |

Parent command line (both EID 1 events): `wuauclt.exe /UpdateDeploymentProvider C:\ProgramData\Intel\helpa.dll /RunHandlerComServer`

Context: IntegrityLevel Medium, LogonId 0x6f859, cmd.exe is the genuine Microsoft binary.

## 3. Root cause analysis
wuauclt.exe was started with /UpdateDeploymentProvider pointing at a DLL in C:\ProgramData\Intel\, a folder that does not normally hold Windows Update components. It loaded the unsigned DLL and, nine milliseconds later, spawned two command shells. This is the documented LOLBin technique for running attacker code through a signed Microsoft binary. How the DLL reached disk is not visible: the dataset has no file-creation events.

## 3a. Corroboration (second log source)
Sysmon EID 7 shows the same process instance, ProcessGuid {00247c92-09fe-5f86-0000-001051841401}, loading helpa.dll. That ProcessGuid equals the ParentProcessGuid of both cmd.exe events, which ties the DLL load to the shells.

## 4. ATT&CK mapping
| Stage | Technique |
|---|---|
| Unsigned DLL executed through wuauclt | T1218 System Binary Proxy Execution |
| cmd.exe spawned | T1059.003 Windows Command Shell (secondary) |

## 5. Impact
Attacker-chosen code ran as user "bouss" at Medium integrity. No privilege elevation is visible. The dataset holds only 3 events (2 x EID 1, 1 x EID 7), so no later activity can be assessed.

## 6. Response
Follow playbooks/playbook_001_suspicious_process_injection.md, adapted for LOLBin execution: isolate the host, collect and hash helpa.dll, look up the SHA256, block the path, review the parent chain, and hunt for wuauclt.exe with /UpdateDeploymentProvider across the estate.

## 7. Closure and detection gap
- Classification: **True Positive.** The command line, the unusual DLL path and the unsigned image load are unambiguous. The data comes from a public emulation sample, not a live client.
- Gap 1: rules 001 and 021 depend on the cmd.exe child. Nothing detects the unsigned DLL load itself (EID 7). Recommended new rule: wuauclt.exe loading an unsigned DLL from outside System32.
- Gap 2: a wuauclt run without the /UpdateDeploymentProvider flag, or without a child process, would be missed.