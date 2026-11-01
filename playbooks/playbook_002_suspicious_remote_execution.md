# Playbook 002 — Suspicious Remote Execution

## 1. Purpose
Guide investigation and response when a remote-management process launches unexpected commands or programs.

## 2. Trigger
A Sysmon Event ID 1 records a suspicious child process launched by wsmprovhost.exe, or unusual command-shell activity associated with a remote session.

## 3. Initial Severity
Medium — pending triage. Raise severity if evidence supports unauthorized access, lateral movement, or execution by a compromised account.

## 4. Triage
1. Record the event timestamp, hostname, user, image, parent image, command line, and process IDs.
2. Determine whether the remote session was expected and authorized.
3. Review related authentication and remote-session logs, if available.
4. Examine child processes, command-line arguments, executable hashes, and nearby events.
5. Identify whether the activity aligns with approved administrative tools or scripts.
6. Preserve relevant evidence before taking disruptive action.

## 5. Containment
If unauthorized remote execution is supported by evidence:
- Escalate to the incident-response lead.
- Restrict the affected remote session or account through approved procedures.
- Isolate the endpoint if the risk and operational impact justify it.
- Preserve relevant logs and endpoint evidence.

## 6. Eradication and Recovery
- Remove confirmed malicious scripts or tools.
- Review and remediate unauthorized persistence.
- Reset compromised credentials where appropriate.
- Restore affected systems and monitor for recurrence.

## 7. Escalation
Escalate if the activity involves privileged accounts, multiple endpoints, confirmed lateral movement, or suspected data theft