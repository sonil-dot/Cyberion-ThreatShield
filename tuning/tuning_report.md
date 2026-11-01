# Tuning Report

## Tuning pass 1 - Rule 018 (KeePass remote thread, T1555.005)

- Original rule: sigma_rules/rule_018_keepass_remote_thread.yml
- Tuned rule: tuning/rule_018_tuned.yml (adds StartFunction contains DbgUiRemoteBreakin)
- Dataset: CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx
- Tool: Chainsaw v2.17.1

| Version | Detections | Records |
|---|---|---|
| Original | 2 | 7070, 7071 |
| Tuned | 1 | 7070 |

- Reason for tuning: remote threads from tools such as debuggers or security software could trigger the broad rule. Requiring DbgUiRemoteBreakin narrows it to one injection pattern.
- Trade-off accepted: record 7071 (thread at unbacked address 0x06160000, no module or function) is no longer detected. That is the thread most consistent with injected code. The tuned rule would miss attacks that do not use DbgUiRemoteBreakin.
- Decision: keep the original broad rule in production; keep the tuned rule only as a low-noise variant.
- Note: no false positive was observed in this dataset. The tuning is design-based and measured on match counts, not on benign traffic.
## Tuning pass 2 - Rules 016 and 019 (WinRM host child processes, T1021.006)

| Version | Logic | Detections on WSMProvHost sample |
|---|---|---|
| Rule 016 | wsmprovhost.exe parent AND cmd/powershell/pwsh child | 0 |
| Rule 019 | wsmprovhost.exe parent, any child | 1 (HOSTNAME.EXE, record from Chainsaw) |

- Observed gap: 016 missed a real remote command (HOSTNAME.EXE) because it only lists three interpreters.
- Change made: remove the child-image restriction (rule 019).
- Trade-off accepted: 019 alerts on every process started through PowerShell remoting, so it will be noisier where administrators or monitoring tools use remoting. Expect to add an allow-list for known automation accounts and hosts.

## Tuning pass 3 - Rule 001 (wuauclt spawning cmd.exe, T1218)

- Original rule: sigma_rules/rule_001_suspicious_wuauclt.yml
- Tuned rule: tuning/rule_001_tuned.yml (requires ParentCommandLine to contain UpdateDeploymentProvider)
- Dataset: evasion_execution_imageload_wuauclt_lolbas.evtx, Chainsaw v2.17.1

| Version | Detections | Records |
|---|---|---|
| Original | 2 | 2196442, 2196443 |
| Tuned | 2 | 2196442, 2196443 |

- Reason: a wuauclt.exe parent alone could match legitimate Windows Update activity. Requiring the DLL-loading flag targets the known abuse pattern.
- Result: no detections lost on this sample.
- Trade-off accepted: wuauclt abuse that does not use that flag, or that does not spawn cmd.exe, is missed. No false positive was observed in this dataset, so the precision gain is by design and not measured on benign traffic.

## Tuning pass 3 - Rule 001 (wuauclt spawning cmd.exe, T1218)

- Original rule: sigma_rules/rule_001_suspicious_wuauclt.yml
- Tuned rule: tuning/rule_001_tuned.yml (requires ParentCommandLine to contain UpdateDeploymentProvider)
- Dataset: evasion_execution_imageload_wuauclt_lolbas.evtx, Chainsaw v2.17.1

| Version | Detections | Records |
|---|---|---|
| Original | 2 | 2196442, 2196443 |
| Tuned | 2 | 2196442, 2196443 |

- Reason: a wuauclt.exe parent alone could match legitimate Windows Update activity. Requiring the DLL-loading flag targets the known abuse pattern.
- Result: no detections lost on this sample.
- Trade-off accepted: wuauclt abuse that does not use that flag, or that does not spawn cmd.exe, is missed. No false positive was observed in this dataset, so the precision gain is by design and not measured on benign traffic.

## Tuning pass 3 - Rule 001 (wuauclt spawning cmd.exe, T1218)

- Original rule: sigma_rules/rule_001_suspicious_wuauclt.yml
- Tuned rule: tuning/rule_001_tuned.yml (requires ParentCommandLine to contain UpdateDeploymentProvider)
- Dataset: evasion_execution_imageload_wuauclt_lolbas.evtx, Chainsaw v2.17.1

| Version | Detections | Records |
|---|---|---|
| Original | 2 | 2196442, 2196443 |
| Tuned | 2 | 2196442, 2196443 |

- Reason: a wuauclt.exe parent alone could match legitimate Windows Update activity. Requiring the DLL-loading flag targets the known abuse pattern.
- Result: no detections lost on this sample.
- Trade-off accepted: wuauclt abuse that does not use that flag, or that does not spawn cmd.exe, is missed. No false positive was observed in this dataset, so the precision gain is by design and not measured on benign traffic.
