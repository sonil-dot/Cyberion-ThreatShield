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