# ALLSAFE Security Analysis Report: Multi-Stage Attack

- **Analysis ID:** sim-60e687b14a44
- **Report ID:** RPT-75FDCCE3A1
- **Generated:** 2026-10-31T04:31:54.509906+00:00
- **Log file:** Not a file: synthetic simulation run
- **Log type:** Synthetic simulation run
- **Analysis started:** 2026-10-31T04:31:08.993151+00:00
- **Analysis completed:** 2026-10-31T04:31:12.492810+00:00

## Overall security assessment

**THREATS DETECTED**

8 detection(s) have strong supporting evidence and need investigation.

## Executive summary

Multi-Stage Attack: 44 of 44 records were processed, producing 11 alert(s) and 1 incident(s). The highest priority is INC-000003, Multi-Stage Attack on web-01: 7 tactics, 11 detections, at 98/100 (CRITICAL). 10 recommended action(s) are waiting for an analyst. No action has changed a real system. All of this data is synthetic.

## Threat overview

- **Attack categories:** Collection, Credential Access, Exfiltration, Initial Access, Lateral Movement, Persistence, Privilege Escalation
- **Rules fired:** IOA-001, IOA-002, IOA-003, IOA-004, IOA-007, IOA-009, IOA-010, IOA-016, IOC-IP, UEBA-001, UEBA-002

## Processing summary

- **Status:** COMPLETED
- **Total uploaded records:** 44
- **Successfully processed records:** 44
- **Rejected records:** 0
- **Duplicate records:** 0

## Data quality

- **Malformed records:** 0
- **Invalid timestamps:** 0
- **Missing timestamps:** 0
- **Flows with no timestamp, kept:** 0
- **Missing optional values:** none
- **Fields with no equivalent in the common schema:** none

## Detection engines

### Executed

- **IOC enrichment:** evaluated 39 of 44 event(s), 1 finding(s)
- **IOA behavior rules:** evaluated 44 of 44 event(s), 8 finding(s)
- **UEBA baselines:** evaluated 23 of 44 event(s), 3 finding(s)
- **Anomaly model:** evaluated 44 of 44 event(s), 2 finding(s)

### Skipped or failed

- **Supervised ML (saved network model) (SKIPPED):** This data has no records with all 78 CIC-IDS2017 flow features the model needs. Logs of other kinds are never fed to it.

## Finding classification

- **Confirmed detections:** 8 alert(s) over 24 event(s), 1 incident(s)
- **Suspicious activity:** 3 alert(s) over 1 event(s), 2 anomaly window(s), 0 flow(s) classified as attacks
- **Benign activity (normal events):** 19 event(s). These events triggered no applicable detection condition. That is not proof they are safe.
- **Data quality issues:** 0 bad record(s), 0 duplicate(s)
- **Detection limitations:** 1
  - Supervised ML (saved network model): This data has no records with all 78 CIC-IDS2017 flow features the model needs. Logs of other kinds are never fed to it.

## Detection results

- **Alerts:** 11
- **Incidents:** 1

### IOC matches (1)

- 39 event(s) were checked against the threat intelligence database.
- **IOC-IP Threat Intelligence Match: IP** (Confirmed detection)
  - Severity MEDIUM, confidence 70%, risk 36/100 (LOW), 3 event(s), last seen 2026-10-31T04:31:08.976695+00:00
  - Why it fired: dst_ip matched ip indicator 198.51.100.77 from feed 'allsafe-synthetic-demo-feed'. Synthetic: staging server for data theft in the demo scenarios. This is evidence to investigate, not proof of compromise.
  - Triggering conditions: {"type": "ioc", "window_seconds": 3600}
  - Matched indicator: 198.51.100.77 (ip) in dst_ip, from feed allsafe-synthetic-demo-feed. Context: Synthetic: staging server for data theft in the demo scenarios.
  - MITRE ATT&CK: not mapped
  - Supporting event IDs: sim-60e687b14a44-00041, sim-60e687b14a44-00042, sim-60e687b14a44-00043
  - Evidence: 10.10.1.10 -> 198.51.100.77:443 HTTPS, 31,457,280 bytes
  - Evidence: 10.10.1.10 -> 198.51.100.77:443 HTTPS, 31,457,280 bytes
  - Evidence: 10.10.1.10 -> 198.51.100.77:443 HTTPS, 31,457,280 bytes

### IOA rule matches (8)

- **IOA-002 Successful Login After Repeated Failures** (Confirmed detection)
  - Severity HIGH, confidence 92%, risk 60/100 (MEDIUM), 13 event(s), last seen 2026-10-31T04:19:08.976695+00:00
  - Description: A login succeeded from a source that had just failed repeatedly, which suggests the password was guessed.
  - Why it fired: 203.0.113.50 logged in successfully after 12 failed attempts within 600s.
  - Triggering conditions: {"type": "sequence", "group_by": ["src_ip"], "threshold": 5, "window_seconds": 600, "first": {"field": "event_type", "equals": "authentication_failure"}, "then": {"field": "event_type", "equals": "authentication_success"}}
  - MITRE ATT&CK: T1110 Brute Force, T1078 Valid Accounts
  - Supporting event IDs: sim-60e687b14a44-00019, sim-60e687b14a44-00020, sim-60e687b14a44-00021, sim-60e687b14a44-00022, sim-60e687b14a44-00023, sim-60e687b14a44-00024, sim-60e687b14a44-00025, sim-60e687b14a44-00026, sim-60e687b14a44-00027, sim-60e687b14a44-00028
  - Evidence: Failed login for svc_admin from 203.0.113.50 to web-01
  - Evidence: Failed login for svc_admin from 203.0.113.50 to web-01
  - Evidence: Failed login for svc_admin from 203.0.113.50 to web-01
- **IOA-001 Brute Force Login Attempts** (Confirmed detection)
  - Severity MEDIUM, confidence 77%, risk 46/100 (MEDIUM), 12 event(s), last seen 2026-10-31T04:18:41.976695+00:00
  - Description: Many failed logins from one source address in a short time.
  - Why it fired: 12 failed logins from 203.0.113.50 within 300s (threshold 5).
  - Triggering conditions: {"type": "threshold", "group_by": ["src_ip"], "threshold": 5, "window_seconds": 300, "match": {"field": "event_type", "equals": "authentication_failure"}}
  - MITRE ATT&CK: T1110 Brute Force
  - Supporting event IDs: sim-60e687b14a44-00019, sim-60e687b14a44-00020, sim-60e687b14a44-00021, sim-60e687b14a44-00022, sim-60e687b14a44-00023, sim-60e687b14a44-00024, sim-60e687b14a44-00025, sim-60e687b14a44-00026, sim-60e687b14a44-00027, sim-60e687b14a44-00028
  - Evidence: Failed login for svc_admin from 203.0.113.50 to web-01
  - Evidence: Failed login for svc_admin from 203.0.113.50 to web-01
  - Evidence: Failed login for svc_admin from 203.0.113.50 to web-01
- **IOA-003 Suspicious Privilege Escalation** (Confirmed detection)
  - Severity HIGH, confidence 80%, risk 50/100 (MEDIUM), 2 event(s), last seen 2026-10-31T04:22:18.976695+00:00
  - Description: An escalation event, or a command that grants or obtains administrative rights.
  - Why it fired: Privilege-related activity by svc_admin on web-01: net.exe: net localgroup administrators backup_svc /add.
  - Triggering conditions: {"type": "threshold", "group_by": ["hostname", "user"], "threshold": 1, "window_seconds": 900, "match": {"any": [{"field": "event_type", "in": ["privilege_escalation", "privilege_granted"]}, {"field": "command_line", "regex": "\\bsudo\\b.*(\\bsu\\b|/bash\\b|/sh\\b|\\s-i\\b|\\s-s\\b)|usermod\\s+.*-a?G\\s+\\S*(sudo|wheel|admin)|net\\s+localgroup\\s+administrators\\s+\\S+\\s+/add|Add-LocalGroupMember
  - MITRE ATT&CK: T1548 Abuse Elevation Control Mechanism, T1098 Account Manipulation
  - Supporting event IDs: sim-60e687b14a44-00032, sim-60e687b14a44-00034
  - Evidence: sudo: sudo su -
  - Evidence: net.exe: net localgroup administrators backup_svc /add
- **IOA-004 Unexpected Account Creation** (Confirmed detection)
  - Severity CRITICAL, confidence 85%, risk 58/100 (MEDIUM), 1 event(s), last seen 2026-10-31T04:22:08.976695+00:00
  - Description: A new local account was created.
  - Why it fired: Account creation by svc_admin on web-01: net.exe: net user backup_svc Xy12 /add.
  - Triggering conditions: {"type": "threshold", "group_by": ["hostname", "user"], "threshold": 1, "window_seconds": 900, "match": {"any": [{"field": "event_type", "equals": "account_created"}, {"field": "command_line", "regex": "net\\s+user\\s+\\S+.*\\s/add\\b|\\buseradd\\s|\\badduser\\s+\\S+\\s*$|New-LocalUser\\b"}]}}
  - MITRE ATT&CK: T1136 Create Account
  - Supporting event IDs: sim-60e687b14a44-00033
  - Evidence: net.exe: net user backup_svc Xy12 /add
- **IOA-009 Internal Lateral Movement Pattern** (Confirmed detection)
  - Severity HIGH, confidence 76%, risk 52/100 (MEDIUM), 4 event(s), last seen 2026-10-31T04:25:38.976695+00:00
  - Description: An internal host connected to several other internal hosts on remote administration ports.
  - Why it fired: 10.10.1.10 reached 4 internal hosts on remote administration ports within 300s (threshold 3).
  - Triggering conditions: {"type": "threshold", "group_by": ["src_ip"], "threshold": 3, "distinct": "dst_ip", "window_seconds": 300, "match": {"all": [{"field": "source", "equals": "network"}, {"field": "src_ip", "ip_scope": "internal"}, {"field": "dst_ip", "ip_scope": "internal"}, {"field": "dst_port", "in": [22, 135, 445, 3389, 5985, 5986]}]}}
  - MITRE ATT&CK: T1021 Remote Services
  - Supporting event IDs: sim-60e687b14a44-00035, sim-60e687b14a44-00036, sim-60e687b14a44-00037, sim-60e687b14a44-00038
  - Evidence: 10.10.1.10 -> 10.10.1.20:445 TCP
  - Evidence: 10.10.1.10 -> 10.10.1.21:3389 TCP
  - Evidence: 10.10.1.10 -> 10.10.1.22:445 TCP
- **IOA-010 Remote Execution Tool** (Confirmed detection)
  - Severity HIGH, confidence 80%, risk 52/100 (MEDIUM), 1 event(s), last seen 2026-10-31T04:25:58.976695+00:00
  - Description: A tool commonly used to run commands on other hosts was started.
  - Why it fired: Remote execution tool psexec.exe started on web-01: psexec.exe: psexec.exe \\10.10.1.20 cmd.exe.
  - Triggering conditions: {"type": "threshold", "group_by": ["hostname", "process_name"], "threshold": 1, "window_seconds": 900, "match": {"all": [{"field": "event_type", "equals": "process_start"}, {"any": [{"field": "process_name", "regex": "^(psexec|psexec64|psexesvc|winrs)(\\.exe)?$"}, {"field": "command_line", "regex": "wmic(\\.exe)?\\s.*/node:|Enter-PSSession\\b|Invoke-Command\\s.*-ComputerName"}]}]}}
  - MITRE ATT&CK: T1569.002 System Services: Service Execution
  - Supporting event IDs: sim-60e687b14a44-00039
  - Evidence: psexec.exe: psexec.exe \\10.10.1.20 cmd.exe
- **IOA-016 Archive Staging** (Suspicious activity)
  - Severity LOW, confidence 40%, risk 30/100 (LOW), 1 event(s), last seen 2026-10-31T04:28:08.976695+00:00
  - Description: An archive file was accessed or created. This is weak alone and only adds context to related activity.
  - Why it fired: Archive activity by svc_admin on web-01: 7z.exe: 7z.exe a C:\Temp\export.7z C:\Finance.
  - Triggering conditions: {"type": "threshold", "group_by": ["hostname", "user"], "threshold": 1, "window_seconds": 900, "match": {"any": [{"all": [{"field": "event_type", "in": ["file_access", "file_create"]}, {"field": "file_path", "regex": "\\.(zip|rar|7z|tar|tgz|gz)$"}]}, {"field": "command_line", "regex": "\\b(7z|rar|zip)(\\.exe)?\\s+a\\b|\\btar\\s+-?c"}]}}
  - MITRE ATT&CK: T1560 Archive Collected Data
  - Supporting event IDs: sim-60e687b14a44-00040
  - Evidence: 7z.exe: 7z.exe a C:\Temp\export.7z C:\Finance
- **IOA-007 Possible Data Exfiltration** (Confirmed detection)
  - Severity HIGH, confidence 79%, risk 53/100 (MEDIUM), 3 event(s), last seen 2026-10-31T04:31:08.976695+00:00
  - Description: An internal host sent a large volume of data to external addresses.
  - Why it fired: 10.10.1.10 sent 90.0 MB to external destinations within 600s (threshold 50 MB).
  - Triggering conditions: {"type": "sum", "group_by": ["src_ip"], "threshold": 52428800, "field": "bytes_out", "window_seconds": 600, "match": {"all": [{"field": "source", "equals": "network"}, {"field": "src_ip", "ip_scope": "internal"}, {"field": "dst_ip", "ip_scope": "external"}, {"not": {"field": "dst_ip", "in": ["198.51.100.10"]}}]}}
  - MITRE ATT&CK: T1041 Exfiltration Over C2 Channel
  - Supporting event IDs: sim-60e687b14a44-00041, sim-60e687b14a44-00042, sim-60e687b14a44-00043
  - Evidence: 10.10.1.10 -> 198.51.100.77:443 HTTPS, 31,457,280 bytes
  - Evidence: 10.10.1.10 -> 198.51.100.77:443 HTTPS, 31,457,280 bytes
  - Evidence: 10.10.1.10 -> 198.51.100.77:443 HTTPS, 31,457,280 bytes

### UEBA findings (2)

- **UEBA-001 Login From a New Source for an Established User** (Suspicious activity)
  - Severity MEDIUM, confidence 60%, risk 40/100 (MEDIUM), 1 event(s), last seen 2026-10-31T04:19:08.976695+00:00
  - Description: An account with an established login history signed in from an address it has never used.
  - Why it fired: svc_admin logged in from 203.0.113.50, a source not seen in 7 earlier logins from 1 known source(s).
  - Triggering conditions: {"type": "baseline", "group_by": ["user", "src_ip"], "window_seconds": 3600}
  - MITRE ATT&CK: T1078 Valid Accounts
  - Supporting event IDs: sim-60e687b14a44-00031
  - Evidence: Successful login for svc_admin from 203.0.113.50 to web-01
- **UEBA-002 Outbound Volume Far Above This Host's Baseline** (Suspicious activity)
  - Severity MEDIUM, confidence 65%, risk 42/100 (MEDIUM), 2 event(s), last seen 2026-10-31T04:30:38.976695+00:00
  - Description: A single transfer was far larger than this address normally sends.
  - Why it fired: 10.10.1.10 sent 30.0 MB in one transfer, 3 deviations above its average of 2.34 MB over 13 earlier transfers.
  - Triggering conditions: {"type": "baseline", "group_by": ["src_ip"], "window_seconds": 3600}
  - MITRE ATT&CK: T1048 Exfiltration Over Alternative Protocol
  - Supporting event IDs: sim-60e687b14a44-00041, sim-60e687b14a44-00042
  - Evidence: 10.10.1.10 -> 198.51.100.77:443 HTTPS, 31,457,280 bytes

## ML classification results

- The saved network model classified nothing in this data. See the detection engines above for why.

## Anomaly detection results

- **Unusual activity windows:** 2. Statistically unusual activity, not confirmed attacks.
- **203.0.113.50** (strength 71 of 100, 13 event(s)): Unusual compared with the model's synthetic baseline of normal activity: 12 failed logins (typically about 0.0), 13 events (typically about 1.6), 1 distinct destinations (typically about 0.3). A statistical anomaly, not a confirmed attack.
- **10.10.1.10** (strength 66 of 100, 4 event(s)): Unusual compared with the model's synthetic baseline of normal activity: 4 connections to admin ports (typically about 0.0), 4 distinct destinations (typically about 0.3), 3 distinct destination ports (typically about 0.3). A statistical anomaly, not a confirmed attack.

## Incident investigation

### INC-000003: Multi-Stage Attack on web-01: 7 tactics, 11 detections

- **Status:** ACTIVE, priority P1
- **Severity:** CRITICAL
- **Confidence:** 99%
- **Risk:** 98/100 CRITICAL
- **Affected hosts:** web-01
- **Affected users:** svc_admin
- **Related alerts:** IOA-002, IOA-001, UEBA-001, IOA-003, IOA-004, IOA-009, IOA-010, IOA-016, IOA-007, IOC-IP, UEBA-002
- **Possible ATT&CK stages:** T1021 Remote Services (Lateral Movement); T1041 Exfiltration Over C2 Channel (Exfiltration); T1048 Exfiltration Over Alternative Protocol (Exfiltration); T1078 Valid Accounts (Initial Access); T1098 Account Manipulation (Privilege Escalation); T1110 Brute Force (Credential Access); T1136 Create Account (Persistence); T1548 Abuse Elevation Control Mechanism (Privilege Escalation); T1560 Archive Collected Data (Collection); T1569.002 System Services: Service Execution (Lateral Movement)
- **Automation:** Needs SOC approval now: every response action waits for an analyst decision. Evidence is collected and an immediate notification is sent.

**Why this score:**

- severity (25.0 points): Incident severity is CRITICAL.
- evidence confidence (24.8 points): Combined evidence confidence is 99%.
- ioc ioa signals (18.8 points): 8 distinct behavior rule(s), 1 threat intelligence match(es), best confidence 70%.
- behavioral anomalies (10.6 points): 2 behavioral anomaly(ies) against the entity's own baseline, best confidence 65%; 2 statistically unusual activity window(s), strength 71 of 100. The strongest one counts.
- attack progression (15.0 points): 7 MITRE tactic(s) across 11 distinct detection(s): Credential Access, Initial Access, Privilege Escalation, Persistence, Lateral Movement, Collection, Exfiltration.
- asset importance (4 points): web-01 has criticality level 2 in the asset list.

**Timeline:**

- 2026-10-31T04:18:08.976695+00:00: Failed login for svc_admin from 203.0.113.50 to web-01 (x12) [IOA-001, IOA-002]
- 2026-10-31T04:19:08.976695+00:00: Successful login for svc_admin from 203.0.113.50 to web-01 [IOA-002, UEBA-001]
- 2026-10-31T04:21:08.976695+00:00: sudo: sudo su - [IOA-003]
- 2026-10-31T04:22:08.976695+00:00: net.exe: net user backup_svc Xy12 /add [IOA-004]
- 2026-10-31T04:22:18.976695+00:00: net.exe: net localgroup administrators backup_svc /add [IOA-003]
- 2026-10-31T04:25:08.976695+00:00: 10.10.1.10 -> 10.10.1.20:445 TCP [IOA-009]
- 2026-10-31T04:25:18.976695+00:00: 10.10.1.10 -> 10.10.1.21:3389 TCP [IOA-009]
- 2026-10-31T04:25:28.976695+00:00: 10.10.1.10 -> 10.10.1.22:445 TCP [IOA-009]
- 2026-10-31T04:25:38.976695+00:00: 10.10.1.10 -> 10.10.1.23:22 TCP [IOA-009]
- 2026-10-31T04:25:58.976695+00:00: psexec.exe: psexec.exe \\10.10.1.20 cmd.exe [IOA-010]
- 2026-10-31T04:28:08.976695+00:00: 7z.exe: 7z.exe a C:\Temp\export.7z C:\Finance [IOA-016]
- 2026-10-31T04:30:08.976695+00:00: 10.10.1.10 -> 198.51.100.77:443 HTTPS, 31,457,280 bytes (x2) [IOA-007, IOC-IP, UEBA-002]
- 2026-10-31T04:31:08.976695+00:00: 10.10.1.10 -> 198.51.100.77:443 HTTPS, 31,457,280 bytes [IOA-007, IOC-IP]

## Affected users and hosts

- **Users:** svc_admin
- **Hosts:** web-01

## Risk analysis

- **Severity distribution (alerts):** HIGH 5, MEDIUM 4, CRITICAL 1, LOW 1
- **Incident risk distribution:** CRITICAL 1, HIGH 0, MEDIUM 0, LOW 0
- **Alert risk distribution:** CRITICAL 0, HIGH 0, MEDIUM 9, LOW 2
- Risk is an investigation priority, not the probability that an attack is real. Each incident above lists the factors behind its score.

## MITRE ATT&CK mappings

- T1021 Remote Services (Lateral Movement)
- T1041 Exfiltration Over C2 Channel (Exfiltration)
- T1048 Exfiltration Over Alternative Protocol (Exfiltration)
- T1078 Valid Accounts (Initial Access)
- T1098 Account Manipulation (Privilege Escalation)
- T1110 Brute Force (Credential Access)
- T1136 Create Account (Persistence)
- T1548 Abuse Elevation Control Mechanism (Privilege Escalation)
- T1560 Archive Collected Data (Collection)
- T1569.002 System Services: Service Execution (Lateral Movement)

## Recommended remediation

Historical analysis is read-only. Nothing below has been done, and any disruptive step needs an analyst to approve it.

- **IOA-001 Brute Force Login Attempts:** Review the targeted accounts and whether this source address is expected. Consider rate limiting or blocking the source address after review.
- **IOA-002 Successful Login After Repeated Failures:** Confirm with the account owner whether this login was theirs. If not, reset the account's password and revoke its active sessions. Review what the account did after this login.
- **IOA-003 Suspicious Privilege Escalation:** Check whether a change ticket or admin task explains this. Review the group membership of the affected account.
- **IOA-004 Unexpected Account Creation:** Verify the account against approved change records. If it is unauthorized, disable the account after analyst review. Check for unauthorized remote access to this host.
- **IOA-007 Possible Data Exfiltration:** Identify the destination and the process that sent the data. Check whether the user recently accessed sensitive file shares. Consider isolating the host after analyst review.
- **IOA-009 Internal Lateral Movement Pattern:** Check the destination hosts for new sessions, processes and accounts. Determine whether this host normally administers those systems.
- **IOA-010 Remote Execution Tool:** Scan the source workstation for unauthorized admin tools. Identify the target hosts and review their activity.
- **IOA-016 Archive Staging:** Check what the archive contains and whether it left this host.
- **IOC-IP Threat Intelligence Match: IP:** Verify the indicator is still current. Threat intelligence can be stale or wrong. Look for other activity that confirms or rules out compromise.
- **UEBA-001 Login From a New Source for an Established User:** Confirm with the account owner that this login was expected.
- **UEBA-002 Outbound Volume Far Above This Host's Baseline:** Review what this host sent, and to where.

## Recommended actions (simulation only)

- INC-000003, **PENDING:** Investigate source IP on `203.0.113.50`
- INC-000003, **PENDING:** Review affected account on `svc_admin`
- INC-000003, **EXECUTED:** Block test IP on `203.0.113.50` (disruptive, needs approval)
- INC-000003, **PENDING:** Disable test account on `svc_admin` (disruptive, needs approval)
- INC-000003, **PENDING:** Collect additional logs on `web-01`
- INC-000003, **PENDING:** Investigate source IP on `10.10.1.10`
- INC-000003, **PENDING:** Inspect suspicious process on `psexec.exe`
- INC-000003, **PENDING:** Terminate test process on `psexec.exe` (disruptive, needs approval)
- INC-000003, **PENDING:** Investigate source IP on `198.51.100.77`
- INC-000003, **PENDING:** Block test IP on `198.51.100.77` (disruptive, needs approval)
- INC-000003, **PENDING:** Collect additional logs on `10.10.1.10`

## Analyst decisions

- INC-000003, EXECUTED: Block test IP on `203.0.113.50` by Demo Analyst at 2026-10-31T04:31:13.955901+00:00. Reason: Confirmed in the timeline

## Model performance

- Event level: TP 25, FP 0, FN 0, TN 19, precision 1.0, recall 1.0, F1 1.0, false-positive rate 0.0
- Alert level: TP 11, FP 0, FN 0, precision 1.0, recall 1.0, F1 1.0
- Incident level: TP 1, FP 0, FN 0, precision 1.0, recall 1.0, F1 1.0
- Anomaly model, event level: TP 17, FP 0, FN 8, TN 19, precision 1.0, recall 0.68, F1 0.8095, false-positive rate 0.0
- Detection latency: 0.27 seconds
- Expected rules that did not fire: none
- Rules that fired unexpectedly: none
- These numbers come from labelled data, and risk scores play no part in them.

## Known limitations

- Detection combines behavior rules, threat intelligence matches, statistical baselines and two models. None of them proves an attack happened, and none proves that one did not.
- The saved network model runs only on flow data with its 78 CIC-IDS2017 features. It has not been validated here, no preprocessing pipeline was saved with it, and its output is uncalibrated, so no accuracy or prediction confidence is claimed.
- The anomaly model was trained on synthetic normal activity, and does not run on live telemetry. Its findings are statistical anomalies, not confirmed attacks.
- Threat intelligence only covers known indicators, and the bundled feed is synthetic. No match does not mean an event is safe.
- Performance metrics compare results with labels on synthetic or supplied data. They do not predict performance on real attacks.
- The synthetic scenarios and the detection rules were written by the same team, so scenario results show the pipeline works as designed.
- Behavioral checks need history. An entity with too little history is not judged.
- Window-based rules cite every matching event in their window, so a normal event inside an attack window counts as an event-level false positive.
- Risk is an investigation priority, not the probability that an attack is real.
- Historical analysis is read-only. Every response action is a recommendation that needs an analyst, and runs only in simulation. No firewall, account, host or process is changed.
- Analyst names are self-reported: there are no user accounts.
