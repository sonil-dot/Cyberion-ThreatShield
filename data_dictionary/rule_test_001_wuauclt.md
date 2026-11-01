# Rule Test 001 — Suspicious Wuauclt Command Shell Launch

## 1. Test Details
- Rule: rule_001_suspicious_wuauclt.yml
- Dataset: evasion_execution_imageload_wuauclt_lolbas
- Event type: Sysmon Event ID 1 — Process Creation
- Test method: Manual comparison of rule conditions against recorded event fields

## 2. Expected Conditions

| Condition | Observed Value | Result |
|---|---|---|
| Child Image ends with `\cmd.exe` | `C:\Windows\System32\cmd.exe` | Match |
| ParentImage ends with `\wuauclt.exe` | `C:\Windows\System32\wuauclt.exe` | Match |
| ParentCommandLine contains `UpdateDeploymentProvider` | Present | Match |
| ParentCommandLine contains `helpa.dll` | Present | Match |

## 3. Preliminary Result

All four expected conditions are present in the recorded event. The event therefore appears to satisfy the rule's detection logic.

## 4. Limitations

This was a manual condition comparison. The Sigma rule has not yet been executed against the EVTX dataset, and no automated detection output has been produced. The result does not establish that the activity was malicious.

## 5. Next Actions

- Run the rule against parsed telemetry using a compatible Sigma backend or testing workflow.
- Review surrounding events and possible legitimate explanations.
- Record automated test results and false-positive findings when available.

## 6. Automated Condition Test

- **Dataset:** `evasion_execution_imageload_wuauclt_lolbas.evtx`
- **Method:** Python-based evaluation of Rule 001's four detection conditions against Sysmon Event ID 1 records.
- **Process-creation events checked:** 2
- **Events matching all four conditions:** 2

| Event Record ID | Conditions Matched | Result |
|---|---|---|
| 2196442 | 4 of 4 | Match |
| 2196443 | 4 of 4 | Match |

### Interpretation

Both process-creation events satisfied all four conditions implemented in the Python test. This confirms that the conditions match these two recorded events in the dataset.

### Limitations

This was an automated Python condition test, not execution of the Sigma rule through a Sigma detection engine or Splunk. The test covered only the two process-creation events in this dataset. It does not establish malicious intent, detection performance on other datasets, or a false-positive rate.

## Validation with Chainsaw (added)

- Tool: Chainsaw v2.17.1, mapping sigma-event-logs-all.yml
- Dataset: evasion_execution_imageload_wuauclt_lolbas.evtx (68.0 KiB)
- Command: .\chainsaw.exe --no-banner hunt <evtx> -s sigma_rules\rule_001_suspicious_wuauclt.yml --mapping .\mappings\sigma-event-logs-all.yml
- Result: 2 detections on 2 documents (Sysmon Event ID 1)

| Record ID | UtcTime | Image | PID | Parent | Parent PID |
|---|---|---|---|---|---|
| 2196442 | 2020-10-13 20:11:42.277 | cmd.exe | 6372 | wuauclt.exe | 1716 |
| 2196443 | 2020-10-13 20:11:42.277 | cmd.exe | 7648 | wuauclt.exe | 1716 |

- Host: LAPTOP-JU4M3I0E, User: bouss
- Parent command line: wuauclt.exe /UpdateDeploymentProvider C:\ProgramData\Intel\helpa.dll /RunHandlerComServer
- Interpretation: wuauclt was used to load a DLL from a non-standard folder, then spawned cmd.exe twice. This is consistent with LOLBin proxy execution (T1218).

## Limitations
Single public dataset, single host, no benign baseline, so the false-positive rate is untested. Not run in a live SIEM.
