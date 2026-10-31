# ALLSAFE Security Analysis Report: Mixed benign and malicious (seed 42)

- **Analysis ID:** ds-832d440f3cd2
- **Report ID:** RPT-47DEBC8BBD
- **Generated:** 2026-10-31T04:31:53.746153+00:00
- **Log file:** Mixed benign and malicious (seed 42)
- **Log type:** Mixed: Application security events, Endpoint and process events, Linux authentication events, Network flow events, Other logs
- **Analysis started:** 2026-10-31T04:31:46.139706+00:00
- **Analysis completed:** 2026-10-31T04:31:53.383708+00:00

## Overall security assessment

**THREATS DETECTED**

7 detection(s) have strong supporting evidence and need investigation.

## Executive summary

Mixed benign and malicious (seed 42): 2000 of 2000 records were processed, producing 9 alert(s) and 4 incident(s). The highest priority is INC-000023, Possible Data Exfiltration (fin-02), at 78/100 (HIGH). 8 recommended action(s) are waiting for an analyst. No action has changed a real system. All of this data is synthetic.

## Threat overview

- **Attack categories:** Collection, Credential Access, Exfiltration, Initial Access, Lateral Movement, Privilege Escalation
- **Rules fired:** IOA-001, IOA-002, IOA-003, IOA-007, IOA-009, IOA-010, IOA-016, IOC-IP, UEBA-002

## Processing summary

- **Status:** COMPLETED
- **Total uploaded records:** 2000
- **Successfully processed records:** 2000
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

- **IOC enrichment:** evaluated 1570 of 2000 event(s), 1 finding(s)
- **IOA behavior rules:** evaluated 2000 of 2000 event(s), 7 finding(s)
- **UEBA baselines:** evaluated 931 of 2000 event(s), 2 finding(s)
- **Anomaly model:** evaluated 2000 of 2000 event(s), 3 finding(s)

### Skipped or failed

- **Supervised ML (saved network model) (SKIPPED):** This data has no records with all 78 CIC-IDS2017 flow features the model needs. Logs of other kinds are never fed to it.

## Finding classification

- **Confirmed detections:** 7 alert(s) over 20 event(s), 4 incident(s)
- **Suspicious activity:** 2 alert(s) over 5 event(s), 3 anomaly window(s), 0 flow(s) classified as attacks
- **Benign activity (normal events):** 1975 event(s). These events triggered no applicable detection condition. That is not proof they are safe.
- **Data quality issues:** 0 bad record(s), 0 duplicate(s)
- **Detection limitations:** 1
  - Supervised ML (saved network model): This data has no records with all 78 CIC-IDS2017 flow features the model needs. Logs of other kinds are never fed to it.

## Detection results

- **Alerts:** 9
- **Incidents:** 4

### IOC matches (1)

- 1570 event(s) were checked against the threat intelligence database.
- **IOC-IP Threat Intelligence Match: IP** (Confirmed detection)
  - Severity MEDIUM, confidence 70%, risk 32/100 (LOW), 2 event(s), last seen 2026-10-31T03:00:06.253849+00:00
  - Why it fired: dst_ip matched ip indicator 198.51.100.77 from feed 'allsafe-synthetic-demo-feed'. Synthetic: staging server for data theft in the demo scenarios. This is evidence to investigate, not proof of compromise.
  - Triggering conditions: {"type": "ioc", "window_seconds": 3600}
  - Matched indicator: 198.51.100.77 (ip) in dst_ip, from feed allsafe-synthetic-demo-feed. Context: Synthetic: staging server for data theft in the demo scenarios.
  - MITRE ATT&CK: not mapped
  - Supporting event IDs: ds-832d440f3cd2-000452, ds-832d440f3cd2-000472
  - Evidence: 10.40.0.2 -> 198.51.100.77:443 HTTPS, 41,943,040 bytes
  - Evidence: 10.40.0.2 -> 198.51.100.77:443 HTTPS, 41,943,040 bytes

### IOA rule matches (7)

- **IOA-003 Suspicious Privilege Escalation** (Confirmed detection)
  - Severity HIGH, confidence 80%, risk 50/100 (MEDIUM), 2 event(s), last seen 2026-10-31T02:35:15.248938+00:00
  - Description: An escalation event, or a command that grants or obtains administrative rights.
  - Why it fired: Privilege-related activity by deploy on app-02: usermod: usermod -aG sudo deploy.
  - Triggering conditions: {"type": "threshold", "group_by": ["hostname", "user"], "threshold": 1, "window_seconds": 900, "match": {"any": [{"field": "event_type", "in": ["privilege_escalation", "privilege_granted"]}, {"field": "command_line", "regex": "\\bsudo\\b.*(\\bsu\\b|/bash\\b|/sh\\b|\\s-i\\b|\\s-s\\b)|usermod\\s+.*-a?G\\s+\\S*(sudo|wheel|admin)|net\\s+localgroup\\s+administrators\\s+\\S+\\s+/add|Add-LocalGroupMember
  - MITRE ATT&CK: T1548 Abuse Elevation Control Mechanism, T1098 Account Manipulation
  - Supporting event IDs: ds-832d440f3cd2-000053, ds-832d440f3cd2-000061
  - Evidence: sudo: sudo su -
  - Evidence: usermod: usermod -aG sudo deploy
- **IOA-016 Archive Staging** (Suspicious activity)
  - Severity LOW, confidence 40%, risk 23/100 (LOW), 1 event(s), last seen 2026-10-31T02:58:06.253849+00:00
  - Description: An archive file was accessed or created. This is weak alone and only adds context to related activity.
  - Why it fired: Archive activity by analyst1 on fin-02: Archive file accessed.
  - Triggering conditions: {"type": "threshold", "group_by": ["hostname", "user"], "threshold": 1, "window_seconds": 900, "match": {"any": [{"all": [{"field": "event_type", "in": ["file_access", "file_create"]}, {"field": "file_path", "regex": "\\.(zip|rar|7z|tar|tgz|gz)$"}]}, {"field": "command_line", "regex": "\\b(7z|rar|zip)(\\.exe)?\\s+a\\b|\\btar\\s+-?c"}]}}
  - MITRE ATT&CK: T1560 Archive Collected Data
  - Supporting event IDs: ds-832d440f3cd2-000438
  - Evidence: Archive file accessed
- **IOA-007 Possible Data Exfiltration** (Confirmed detection)
  - Severity HIGH, confidence 78%, risk 49/100 (MEDIUM), 2 event(s), last seen 2026-10-31T03:00:06.253849+00:00
  - Description: An internal host sent a large volume of data to external addresses.
  - Why it fired: 10.40.0.2 sent 80.0 MB to external destinations within 600s (threshold 50 MB).
  - Triggering conditions: {"type": "sum", "group_by": ["src_ip"], "threshold": 52428800, "field": "bytes_out", "window_seconds": 600, "match": {"all": [{"field": "source", "equals": "network"}, {"field": "src_ip", "ip_scope": "internal"}, {"field": "dst_ip", "ip_scope": "external"}, {"not": {"field": "dst_ip", "in": ["198.51.100.10"]}}]}}
  - MITRE ATT&CK: T1041 Exfiltration Over C2 Channel
  - Supporting event IDs: ds-832d440f3cd2-000452, ds-832d440f3cd2-000472
  - Evidence: 10.40.0.2 -> 198.51.100.77:443 HTTPS, 41,943,040 bytes
  - Evidence: 10.40.0.2 -> 198.51.100.77:443 HTTPS, 41,943,040 bytes
- **IOA-009 Internal Lateral Movement Pattern** (Confirmed detection)
  - Severity HIGH, confidence 76%, risk 48/100 (MEDIUM), 4 event(s), last seen 2026-10-31T03:04:52.882036+00:00
  - Description: An internal host connected to several other internal hosts on remote administration ports.
  - Why it fired: 10.30.0.7 reached 4 internal hosts on remote administration ports within 300s (threshold 3).
  - Triggering conditions: {"type": "threshold", "group_by": ["src_ip"], "threshold": 3, "distinct": "dst_ip", "window_seconds": 300, "match": {"all": [{"field": "source", "equals": "network"}, {"field": "src_ip", "ip_scope": "internal"}, {"field": "dst_ip", "ip_scope": "internal"}, {"field": "dst_port", "in": [22, 135, 445, 3389, 5985, 5986]}]}}
  - MITRE ATT&CK: T1021 Remote Services
  - Supporting event IDs: ds-832d440f3cd2-000546, ds-832d440f3cd2-000548, ds-832d440f3cd2-000550, ds-832d440f3cd2-000553
  - Evidence: 10.30.0.7 -> 10.30.0.20:445 TCP
  - Evidence: 10.30.0.7 -> 10.30.0.21:3389 TCP
  - Evidence: 10.30.0.7 -> 10.30.0.22:445 TCP
- **IOA-010 Remote Execution Tool** (Confirmed detection)
  - Severity HIGH, confidence 80%, risk 42/100 (MEDIUM), 1 event(s), last seen 2026-10-31T03:05:07.882036+00:00
  - Description: A tool commonly used to run commands on other hosts was started.
  - Why it fired: Remote execution tool psexec.exe started on wks-07: psexec.exe: psexec.exe \\10.30.0.20 cmd.exe.
  - Triggering conditions: {"type": "threshold", "group_by": ["hostname", "process_name"], "threshold": 1, "window_seconds": 900, "match": {"all": [{"field": "event_type", "equals": "process_start"}, {"any": [{"field": "process_name", "regex": "^(psexec|psexec64|psexesvc|winrs)(\\.exe)?$"}, {"field": "command_line", "regex": "wmic(\\.exe)?\\s.*/node:|Enter-PSSession\\b|Invoke-Command\\s.*-ComputerName"}]}]}}
  - MITRE ATT&CK: T1569.002 System Services: Service Execution
  - Supporting event IDs: ds-832d440f3cd2-000558
  - Evidence: psexec.exe: psexec.exe \\10.30.0.20 cmd.exe
- **IOA-002 Successful Login After Repeated Failures** (Confirmed detection)
  - Severity HIGH, confidence 90%, risk 56/100 (MEDIUM), 11 event(s), last seen 2026-10-31T03:48:38.809102+00:00
  - Description: A login succeeded from a source that had just failed repeatedly, which suggests the password was guessed.
  - Why it fired: 203.0.113.10 logged in successfully after 10 failed attempts within 600s.
  - Triggering conditions: {"type": "sequence", "group_by": ["src_ip"], "threshold": 5, "window_seconds": 600, "first": {"field": "event_type", "equals": "authentication_failure"}, "then": {"field": "event_type", "equals": "authentication_success"}}
  - MITRE ATT&CK: T1110 Brute Force, T1078 Valid Accounts
  - Supporting event IDs: ds-832d440f3cd2-001268, ds-832d440f3cd2-001269, ds-832d440f3cd2-001271, ds-832d440f3cd2-001272, ds-832d440f3cd2-001273, ds-832d440f3cd2-001274, ds-832d440f3cd2-001275, ds-832d440f3cd2-001277, ds-832d440f3cd2-001278, ds-832d440f3cd2-001279
  - Evidence: Failed login for admin from 203.0.113.10 to app-01
  - Evidence: Failed login for admin from 203.0.113.10 to app-01
  - Evidence: Failed login for admin from 203.0.113.10 to app-01
- **IOA-001 Brute Force Login Attempts** (Confirmed detection)
  - Severity MEDIUM, confidence 75%, risk 41/100 (MEDIUM), 10 event(s), last seen 2026-10-31T03:48:31.809102+00:00
  - Description: Many failed logins from one source address in a short time.
  - Why it fired: 10 failed logins from 203.0.113.10 within 300s (threshold 5).
  - Triggering conditions: {"type": "threshold", "group_by": ["src_ip"], "threshold": 5, "window_seconds": 300, "match": {"field": "event_type", "equals": "authentication_failure"}}
  - MITRE ATT&CK: T1110 Brute Force
  - Supporting event IDs: ds-832d440f3cd2-001268, ds-832d440f3cd2-001269, ds-832d440f3cd2-001271, ds-832d440f3cd2-001272, ds-832d440f3cd2-001273, ds-832d440f3cd2-001274, ds-832d440f3cd2-001275, ds-832d440f3cd2-001277, ds-832d440f3cd2-001278, ds-832d440f3cd2-001279
  - Evidence: Failed login for admin from 203.0.113.10 to app-01
  - Evidence: Failed login for admin from 203.0.113.10 to app-01
  - Evidence: Failed login for admin from 203.0.113.10 to app-01

### UEBA findings (1)

- **UEBA-002 Outbound Volume Far Above This Host's Baseline** (Suspicious activity)
  - Severity MEDIUM, confidence 65%, risk 38/100 (LOW), 2 event(s), last seen 2026-10-31T03:00:06.253849+00:00
  - Description: A single transfer was far larger than this address normally sends.
  - Why it fired: 10.40.0.2 sent 40.0 MB in one transfer, 3 deviations above its average of 3.36 MB over 12 earlier transfers.
  - Triggering conditions: {"type": "baseline", "group_by": ["src_ip"], "window_seconds": 3600}
  - MITRE ATT&CK: T1048 Exfiltration Over Alternative Protocol
  - Supporting event IDs: ds-832d440f3cd2-000452, ds-832d440f3cd2-000472
  - Evidence: 10.40.0.2 -> 198.51.100.77:443 HTTPS, 41,943,040 bytes

## ML classification results

- The saved network model classified nothing in this data. See the detection engines above for why.

## Anomaly detection results

- **Unusual activity windows:** 3. Statistically unusual activity, not confirmed attacks.
- **203.0.113.10** (strength 73 of 100, 11 event(s)): Unusual compared with the model's synthetic baseline of normal activity: 10 failed logins (typically about 0.0), 11 events (typically about 1.6), 1 successful logins (typically about 0.3). A statistical anomaly, not a confirmed attack.
- **10.30.0.7** (strength 66 of 100, 4 event(s)): Unusual compared with the model's synthetic baseline of normal activity: 4 connections to admin ports (typically about 0.0), 4 distinct destinations (typically about 0.3), 3 distinct destination ports (typically about 0.3). A statistical anomaly, not a confirmed attack.
- **10.90.0.45** (strength 63 of 100, 4 event(s)): Unusual compared with the model's synthetic baseline of normal activity: 4 distinct destinations (typically about 0.3), 4 events (typically about 1.6), 594,934 bytes transferred (typically about 49.6). A statistical anomaly, not a confirmed attack.

## Incident investigation

### INC-000022: Suspicious Privilege Escalation (app-02)

- **Status:** ACTIVE, priority P3
- **Severity:** HIGH
- **Confidence:** 80%
- **Risk:** 50/100 MEDIUM
- **Affected hosts:** app-02
- **Affected users:** deploy
- **Related alerts:** IOA-003
- **Possible ATT&CK stages:** T1098 Account Manipulation (Privilege Escalation); T1548 Abuse Elevation Control Mechanism (Privilege Escalation)
- **Automation:** Handled automatically: evidence gathered and safe response steps ran in simulation. Disruptive actions are held, and go to the SOC if risk rises.

**Why this score:**

- severity (18.8 points): Incident severity is HIGH.
- evidence confidence (20.0 points): Combined evidence confidence is 80%.
- ioc ioa signals (10.7 points): 1 distinct behavior rule(s), 0 threat intelligence match(es).

**Timeline:**

- 2026-10-31T02:34:45.248938+00:00: sudo: sudo su - [IOA-003]
- 2026-10-31T02:35:15.248938+00:00: usermod: usermod -aG sudo deploy [IOA-003]

### INC-000023: Possible Data Exfiltration (fin-02)

- **Status:** ACTIVE, priority P2
- **Severity:** HIGH
- **Confidence:** 98%
- **Risk:** 78/100 HIGH
- **Affected hosts:** fin-02
- **Affected users:** analyst1
- **Related alerts:** IOA-016, IOA-007, IOC-IP, UEBA-002
- **Possible ATT&CK stages:** T1041 Exfiltration Over C2 Channel (Exfiltration); T1048 Exfiltration Over Alternative Protocol (Exfiltration); T1560 Archive Collected Data (Collection)
- **Automation:** Needs SOC approval: every response action waits for an analyst decision. Evidence is collected and an urgent notification is sent.

**Why this score:**

- severity (18.8 points): Incident severity is HIGH.
- evidence confidence (24.5 points): Combined evidence confidence is 98%.
- ioc ioa signals (18.8 points): 2 distinct behavior rule(s), 1 threat intelligence match(es), best confidence 70%.
- behavioral anomalies (9.8 points): 1 behavioral anomaly(ies) against the entity's own baseline, best confidence 65%. The strongest one counts.
- attack progression (6.2 points): 2 MITRE tactic(s) across 4 distinct detection(s): Collection, Exfiltration.

**Timeline:**

- 2026-10-31T02:58:06.253849+00:00: Archive file accessed [IOA-016]
- 2026-10-31T02:59:06.253849+00:00: 10.40.0.2 -> 198.51.100.77:443 HTTPS, 41,943,040 bytes (x2) [IOA-007, IOC-IP, UEBA-002]

### INC-000024: Remote Execution Tool (wks-07)

- **Status:** ACTIVE, priority P3
- **Severity:** HIGH
- **Confidence:** 88%
- **Risk:** 68/100 MEDIUM
- **Affected hosts:** wks-07
- **Affected users:** it_admin
- **Related alerts:** IOA-009, IOA-010
- **Possible ATT&CK stages:** T1021 Remote Services (Lateral Movement); T1569.002 System Services: Service Execution (Lateral Movement)
- **Automation:** Handled automatically: evidence gathered and safe response steps ran in simulation. Disruptive actions are held, and go to the SOC if risk rises.

**Why this score:**

- severity (18.8 points): Incident severity is HIGH.
- evidence confidence (22.0 points): Combined evidence confidence is 88%.
- ioc ioa signals (16.0 points): 2 distinct behavior rule(s), 0 threat intelligence match(es).
- behavioral anomalies (9.9 points): 1 statistically unusual activity window(s), strength 66 of 100. The strongest one counts.
- attack progression (0.9 points): 1 MITRE tactic(s) across 2 distinct detection(s): Lateral Movement.

**Timeline:**

- 2026-10-31T03:04:37.882036+00:00: 10.30.0.7 -> 10.30.0.20:445 TCP [IOA-009]
- 2026-10-31T03:04:42.882036+00:00: 10.30.0.7 -> 10.30.0.21:3389 TCP [IOA-009]
- 2026-10-31T03:04:47.882036+00:00: 10.30.0.7 -> 10.30.0.22:445 TCP [IOA-009]
- 2026-10-31T03:04:52.882036+00:00: 10.30.0.7 -> 10.30.0.23:22 TCP [IOA-009]
- 2026-10-31T03:05:07.882036+00:00: psexec.exe: psexec.exe \\10.30.0.20 cmd.exe [IOA-010]

### INC-000025: Successful Login After Repeated Failures (app-01)

- **Status:** ACTIVE, priority P2
- **Severity:** HIGH
- **Confidence:** 97%
- **Risk:** 74/100 HIGH
- **Affected hosts:** app-01
- **Affected users:** admin
- **Related alerts:** IOA-002, IOA-001
- **Possible ATT&CK stages:** T1078 Valid Accounts (Initial Access); T1110 Brute Force (Credential Access)
- **Automation:** Needs SOC approval: every response action waits for an analyst decision. Evidence is collected and an urgent notification is sent.

**Why this score:**

- severity (18.8 points): Incident severity is HIGH.
- evidence confidence (24.2 points): Combined evidence confidence is 97%.
- ioc ioa signals (16.0 points): 2 distinct behavior rule(s), 0 threat intelligence match(es).
- behavioral anomalies (10.9 points): 1 statistically unusual activity window(s), strength 73 of 100. The strongest one counts.
- attack progression (4.4 points): 2 MITRE tactic(s) across 2 distinct detection(s): Credential Access, Initial Access.

**Timeline:**

- 2026-10-31T03:48:13.809102+00:00: Failed login for admin from 203.0.113.10 to app-01 (x10) [IOA-001, IOA-002]
- 2026-10-31T03:48:38.809102+00:00: Successful login for admin from 203.0.113.10 to app-01 [IOA-002]

## Affected users and hosts

- **Users:** admin, analyst1, deploy, it_admin
- **Hosts:** app-01, app-02, fin-02, wks-07

## Risk analysis

- **Severity distribution (alerts):** HIGH 5, LOW 1, MEDIUM 3
- **Incident risk distribution:** CRITICAL 0, HIGH 2, MEDIUM 2, LOW 0
- **Alert risk distribution:** CRITICAL 0, HIGH 0, MEDIUM 6, LOW 3
- Risk is an investigation priority, not the probability that an attack is real. Each incident above lists the factors behind its score.

## MITRE ATT&CK mappings

- T1021 Remote Services (Lateral Movement)
- T1041 Exfiltration Over C2 Channel (Exfiltration)
- T1048 Exfiltration Over Alternative Protocol (Exfiltration)
- T1078 Valid Accounts (Initial Access)
- T1098 Account Manipulation (Privilege Escalation)
- T1110 Brute Force (Credential Access)
- T1548 Abuse Elevation Control Mechanism (Privilege Escalation)
- T1560 Archive Collected Data (Collection)
- T1569.002 System Services: Service Execution (Lateral Movement)

## Recommended remediation

Historical analysis is read-only. Nothing below has been done, and any disruptive step needs an analyst to approve it.

- **IOA-001 Brute Force Login Attempts:** Review the targeted accounts and whether this source address is expected. Consider rate limiting or blocking the source address after review.
- **IOA-002 Successful Login After Repeated Failures:** Confirm with the account owner whether this login was theirs. If not, reset the account's password and revoke its active sessions. Review what the account did after this login.
- **IOA-003 Suspicious Privilege Escalation:** Check whether a change ticket or admin task explains this. Review the group membership of the affected account.
- **IOA-007 Possible Data Exfiltration:** Identify the destination and the process that sent the data. Check whether the user recently accessed sensitive file shares. Consider isolating the host after analyst review.
- **IOA-009 Internal Lateral Movement Pattern:** Check the destination hosts for new sessions, processes and accounts. Determine whether this host normally administers those systems.
- **IOA-010 Remote Execution Tool:** Scan the source workstation for unauthorized admin tools. Identify the target hosts and review their activity.
- **IOA-016 Archive Staging:** Check what the archive contains and whether it left this host.
- **IOC-IP Threat Intelligence Match: IP:** Verify the indicator is still current. Threat intelligence can be stale or wrong. Look for other activity that confirms or rules out compromise.
- **UEBA-002 Outbound Volume Far Above This Host's Baseline:** Review what this host sent, and to where.

## Recommended actions (simulation only)

- INC-000022, **EXECUTED:** Review affected account on `deploy`
- INC-000022, **EXECUTED:** Collect additional logs on `app-02`
- INC-000023, **PENDING:** Collect additional logs on `fin-02`
- INC-000023, **PENDING:** Investigate source IP on `198.51.100.77`
- INC-000023, **PENDING:** Block test IP on `198.51.100.77` (disruptive, needs approval)
- INC-000023, **PENDING:** Collect additional logs on `10.40.0.2`
- INC-000024, **EXECUTED:** Investigate source IP on `10.30.0.7`
- INC-000024, **EXECUTED:** Collect additional logs on `wks-07`
- INC-000024, **EXECUTED:** Inspect suspicious process on `psexec.exe`
- INC-000024, **HELD:** Terminate test process on `psexec.exe` (disruptive, needs approval)
- INC-000025, **PENDING:** Investigate source IP on `203.0.113.10`
- INC-000025, **PENDING:** Review affected account on `admin`
- INC-000025, **PENDING:** Block test IP on `203.0.113.10` (disruptive, needs approval)
- INC-000025, **PENDING:** Disable test account on `admin` (disruptive, needs approval)

## Analyst decisions

- INC-000022, EXECUTED: Review affected account on `deploy` by automation at 2026-10-31T04:31:51.490747+00:00. Reason: MEDIUM risk: safe steps are handled automatically
- INC-000022, EXECUTED: Collect additional logs on `app-02` by automation at 2026-10-31T04:31:51.677153+00:00. Reason: MEDIUM risk: safe steps are handled automatically
- INC-000024, EXECUTED: Investigate source IP on `10.30.0.7` by automation at 2026-10-31T04:31:49.630451+00:00. Reason: MEDIUM risk: safe steps are handled automatically
- INC-000024, EXECUTED: Collect additional logs on `wks-07` by automation at 2026-10-31T04:31:50.113967+00:00. Reason: MEDIUM risk: safe steps are handled automatically
- INC-000024, EXECUTED: Inspect suspicious process on `psexec.exe` by automation at 2026-10-31T04:31:50.275161+00:00. Reason: MEDIUM risk: safe steps are handled automatically

## Model performance

- Event level: TP 21, FP 0, FN 0, TN 1979, precision 1.0, recall 1.0, F1 1.0, false-positive rate 0.0
- Alert level: TP 9, FP 0, FN 0, precision 1.0, recall 1.0, F1 1.0
- Incident level: TP 4, FP 0, FN 0, precision 1.0, recall 1.0, F1 1.0
- Anomaly model, event level: TP 15, FP 4, FN 6, TN 1975, precision 0.7895, recall 0.7143, F1 0.75, false-positive rate 0.002
- Detection latency: 1.902 seconds
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
