# Threat Hunt 003 - Generic Process Injection via CreateRemoteThread (T1055)

## 1. Hypothesis
Remote-thread creation by any process into any other process (T1055 Process Injection) occurs in the available telemetry, regardless of target. Existing rule 018 only covers KeePass as a target, so injection into other processes would be missed.

## 2. Data and method
- Datasets: all three EVTX files in datasets/.
- Method: pull every Sysmon EID 8 event, group by file, SourceImage and TargetImage, without filtering on target. Evidence: data_dictionary/evidence_hunt003_eid8_pairs.txt
- Technique coverage: no generic rule exists for T1055; rule 018 is KeePass-specific.

## 3. Findings
- Only the KeePass dataset contains EID 8 events: 2 events, one source-target pair (powershell.exe PID 2856 into KeePass.exe PID 2364).
- The wuauclt dataset (EID 1 and 7) and the WSMProvHost dataset (EID 1) contain no EID 8 events.

## 4. Negative results
- No injection into any process other than KeePass was found.
- Three small datasets, so absence of other pairs says little about a real environment.

## 5. Conclusion
**Confirmed for the KeePass pair only; no other injection found.** The hunt shows that the one injection pattern in the data is already covered by rule 018, but a generic detection for T1055 does not exist.

## 6. Recommendation
Add a generic rule for EID 8 where the source is a script host or LOLBin (powershell.exe, wscript.exe, rundll32.exe and similar) and the target differs from the source, with an allow-list for known security tools. Expect higher noise than rule 018.