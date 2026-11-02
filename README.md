Cyberion ThreatShield
Detection Engineering & Threat Hunting engagement (CDL-DET-V2)
Prepared by: Sneha Philip | Internmo internship, 5 August 2026 to 5 November 2026

Summary
- 21 Sigma rules, tagged to MITRE ATT&CK, all passing sigma check
- 12 rules tested with Chainsaw on public Sysmon samples
- 2 correlation rules (020, 021) checked by replaying the logic in PowerShell
- 7 rules written but not yet tested (003, 008, 009, 011, 014, 016, 017)
- 22 techniques in the coverage matrix
- 3 threat hunts, 2 incident case reports, 3 IR playbooks, 3 tuning passes

Folders
- sigma_rules/ - Sigma detection rules 001 to 021
- datasets/ - EVTX telemetry used for testing (datasets/extra/ holds the extra public samples used to test more rules)
- data_dictionary/ - log field notes, rule test reports, evidence records
- coverage_matrix/ - MITRE ATT&CK coverage matrix (CSV)
- threat_hunts/ - hunt reports 001 to 003
- incident_reports/ - incident case reports INC-001 and INC-002
- playbooks/ - IR playbooks
- ioc_research/ - IOC notes
- tuning/ - tuned rule variants and the tuning report
- screenshots/ - evidence screenshots
- final_report/ - final report (includes the executive summary and methodology)

Reproduce a result

chainsaw.exe --no-banner hunt EVTX_FILE -s RULE_FILE --mapping mappings\sigma-event-logs-all.yml

Example: rule 018 on datasets/CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx gives 2 detections.

Limitations
- Small public datasets and no benign baseline, so false-positive rates are not measured
- Splunk queries were generated but not run
- Chainsaw cannot run Sigma correlation rules, so rules 020 and 021 were checked manually
