# Rule Test 005 — Rundll32 Comsvcs MiniDump Activity

## 1. Test Details
- Rule: `rule_005_comsvcs_minidump.yml`
- Test date: 2026-10-23
- Log source: Windows process creation (Sysmon Event ID 1)
- Target behaviour: `rundll32.exe` command lines referencing `comsvcs.dll` and `MiniDump`

## 2. Sigma Validation
The Sigma CLI validation completed with:
- Errors: 0
- Condition errors: 0
- Issues: 0

**Result:** Passed syntax and condition validation.

## 3. Dataset Review

| Dataset | Process-Creation Events | Rule 005 Matches |
|---|---:|---:|
| `CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx` | 0 | 0 |
| `evasion_execution_imageload_wuauclt_lolbas.evtx` | 2 | 0 |
| `LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx` | 1 | 0 |

The test checked for an image ending in `rundll32.exe` and a command line containing both `comsvcs.dll` and `MiniDump`.

## 4. Test Result
**Status: No matching event found.**

None of the reviewed process-creation events satisfied all Rule 005 conditions. Detection behaviour against a matching event remains unconfirmed.

## 5. Limitations and Next Actions
- Obtain suitable telemetry containing a controlled memory-dump test event.
- Compare the event's image and command-line fields with the Sigma rule.
- Investigate whether any matching activity is authorized debugging or incident response.
