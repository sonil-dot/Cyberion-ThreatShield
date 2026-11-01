# Threat Hunt 001 — Suspicious Windows Update Utility Activity

## 1. Hypothesis
A process launched by wuauclt.exe with a command line referencing an unexpected DLL may indicate abuse of a legitimate Windows utility.

## 2. Objective
Investigate whether the observed process relationship is isolated or accompanied by other suspicious activity.

## 3. Data Source
- Sysmon Event ID 1 — Process Creation
- Related process and image-load events, if available

## 4. Investigation Steps
1. Identify process-creation events where ParentImage is wuauclt.exe.
2. Review ParentCommandLine for unexpected DLL paths or unusual arguments.
3. Examine child processes and their command lines.
4. Search surrounding events for related image loads, network connections, persistence, or other suspicious activity.
5. Record relevant event timestamps, process IDs, hashes, and findings.

## 5. Initial Evidence
A Sysmon event from the evasion_execution_imageload_wuauclt_lolbas dataset records cmd.exe launched by wuauclt.exe. The parent command line references C:\ProgramData\Intel\helpa.dll.

## 6. Preliminary Assessment
The event is suspicious enough to investigate, but it does not independently confirm malicious activity.

## 7. Outcome
Status: In progress — only the initial event has been examined. Additional telemetry must be reviewed before concluding whether the hypothesis is supported or rejected.

## 8. Recommended Follow-up
Correlate the process-creation event with image-load and other available telemetry, then document false-positive considerations and any detection-rule tuning.
