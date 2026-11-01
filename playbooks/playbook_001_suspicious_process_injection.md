# Playbook 001 — Suspicious Process Injection

## 1. Purpose
Provide a repeatable response process when telemetry indicates possible process injection or suspicious remote-thread creation.

## 2. Trigger
A Sysmon Event ID 8 records a process creating a remote thread inside a sensitive application, such as KeePass.exe.

## 3. Severity
Initial severity: Medium — pending triage.

Increase severity if corroborating evidence indicates credential theft, unauthorized access, or active compromise.

## 4. Triage
1. Record the event timestamp, computer, source process, target process, and process IDs.
2. Verify the source executable and review its command line and parent process.
3. Examine surrounding Sysmon events for related process creation, image loads, file activity, or network connections.
4. Determine whether the activity corresponds to an approved test or legitimate administrative operation.
5. Preserve relevant logs and hashes according to the organization's evidence-handling procedures.

## 5. Containment
If malicious activity is supported by evidence and an incident responder authorizes containment:
- Isolate the affected endpoint using approved security tooling.
- Stop or quarantine confirmed malicious processes using approved procedures.
- Protect potentially exposed credentials and follow the organization's credential-reset process.

Avoid terminating critical processes or isolating systems without considering operational impact and authorization.

## 6. Eradication and Recovery
- Remove confirmed malicious artifacts using approved procedures.
- Patch exploited weaknesses and review persistence mechanisms.
- Restore systems from trusted sources if required.
- Verify normal operation and continue monitoring.

## 7. Escalation
Escalate to the incident-response lead if evidence supports credential theft, lateral movement, or compromise of a privileged account.

## 8. Documentation
Record the evidence, timeline, actions taken, decisions, outcome, and lessons learned.

## 9. Current Project Status
This is a proposed playbook. No live containment or remediation has been performed as part of this documentation.
