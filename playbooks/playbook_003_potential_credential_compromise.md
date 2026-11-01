# Playbook 003 — Potential Credential Compromise

## 1. Purpose
Guide the investigation and response when telemetry suggests possible unauthorized access to credentials or sensitive authentication material.

## 2. Trigger
Suspicious process activity involving password managers, credential-related files, authentication logs, or unexpected access to sensitive application memory.

## 3. Initial Severity
Medium — pending triage. Increase severity if evidence supports credential theft, unauthorized account access, or privileged-account compromise.

## 4. Triage
1. Record the timestamp, affected host, user, process names, command lines, and available hashes.
2. Examine relevant Sysmon events, including process creation and remote-thread creation.
3. Review authentication logs for unusual logins, repeated failures, new sessions, or unexpected privilege use.
4. Determine whether the activity corresponds to an approved test or legitimate administrative action.
5. Identify potentially affected accounts and systems without assuming that credentials were successfully stolen.
6. Preserve relevant evidence and maintain an incident timeline.

## 5. Containment
If credential compromise is supported by evidence:
- Escalate to the incident-response lead.
- Revoke affected sessions and tokens using approved identity-management procedures.
- Reset confirmed compromised credentials and rotate exposed secrets where necessary.
- Restrict affected endpoints or accounts when justified by the risk.
- Preserve evidence before destructive remediation where feasible.

## 6. Eradication