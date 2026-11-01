# Rule Test 004 — Rundll32 from User-Writable Directory

## 1. Test Details
- Rule: `rule_004_suspicious_rundll32.yml`
- Test date: 2026-10-23
- Log source: Windows process creation (Sysmon Event ID 1)
- Target behaviour: `rundll32.exe` command lines referencing user-writable directories

## 2. Sigma Validation
The Sigma CLI validation completed with:
- Errors: 0
- Condition errors: 0
- Issues: 0

**Result:** Passed syntax and condition validation.

## 3. Dataset Review

| Dataset | Process-Creation Events | Rule 004 Matches |
|---|---:|---:|
| `CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx` | 0 | 0 |
| `evasion_execution_imageload_wuauclt_lolbas.evtx` | 2 | 0 |
| `LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx` | 1 | 0 |

The test searched for `rundll32.exe` commands referencing `AppData`, `Temp`, `Windows\Temp`, or `Users\Public`.

## 4. Test Result
**Status: No matching event found.**

The rule's conditions did not match any process-creation events in the reviewed datasets. Detection behaviour against a matching event remains unconfirmed.

## 5. Limitations and Next Actions
- Obtain suitable telemetry containing a controlled `rundll32.exe` test event referencing a user-writable directory.
- Evaluate the event fields against the Sigma conditions.
- Review legitimate software usage to assess potential false positives.
- Test using a compatible Sigma backend where possible.

A zero-match result in these datasets does not establish that the rule is ineffective.