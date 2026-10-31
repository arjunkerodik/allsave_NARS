# ALLSAFE Security Analysis Report: brute_force_windows.csv

- **Analysis ID:** ds-6e8498492f01
- **Report ID:** RPT-7B3CE04101
- **Generated:** 2026-10-31T04:31:17.891817+00:00
- **Log file:** brute_force_windows.csv
- **Log type:** Windows authentication events
- **Analysis started:** 2026-10-31T04:31:16.678600+00:00
- **Analysis completed:** 2026-10-31T04:31:17.754089+00:00

## Overall security assessment

**THREATS DETECTED**

2 detection(s) have strong supporting evidence and need investigation.

## Executive summary

brute_force_windows.csv: 15 of 15 records were processed, producing 2 alert(s) and 1 incident(s). The highest priority is INC-000005, Successful Login After Repeated Failures (dc-01.corp.example), at 74/100 (HIGH). 4 recommended action(s) are waiting for an analyst. No action has changed a real system.

## Threat overview

- **Attack categories:** Credential Access, Initial Access
- **Rules fired:** IOA-001, IOA-002

## Processing summary

- **Status:** COMPLETED
- **Total uploaded records:** 15
- **Successfully processed records:** 15
- **Rejected records:** 0
- **Duplicate records:** 0

## Data quality

- **Malformed records:** 0
- **Invalid timestamps:** 0
- **Missing timestamps:** 0
- **Flows with no timestamp, kept:** 0
- **Missing optional values:** dst_ip 15
- **Fields with no equivalent in the common schema:** TimeCreated, EventID, TargetUserName, LogonType, Channel
- **Warning:** 5 field(s) have no equivalent in the common schema. They are preserved with each event, but no detection reads them.

## Detection engines

### Executed

- **IOC enrichment:** evaluated 15 of 15 event(s), 0 finding(s)
- **IOA behavior rules:** evaluated 15 of 15 event(s), 2 finding(s)
- **UEBA baselines:** evaluated 6 of 15 event(s), 0 finding(s)
- **Anomaly model:** evaluated 15 of 15 event(s), 1 finding(s)

### Skipped or failed

- **Supervised ML (saved network model) (SKIPPED):** This data has no records with all 78 CIC-IDS2017 flow features the model needs. Logs of other kinds are never fed to it.

## Finding classification

- **Confirmed detections:** 2 alert(s) over 10 event(s), 1 incident(s)
- **Suspicious activity:** 0 alert(s) over 0 event(s), 1 anomaly window(s), 0 flow(s) classified as attacks
- **Benign activity (normal events):** 5 event(s). These events triggered no applicable detection condition. That is not proof they are safe.
- **Data quality issues:** 0 bad record(s), 0 duplicate(s)
- **Detection limitations:** 1
  - Supervised ML (saved network model): This data has no records with all 78 CIC-IDS2017 flow features the model needs. Logs of other kinds are never fed to it.

## Detection results

- **Alerts:** 2
- **Incidents:** 1

### IOC matches (0)

- 15 event(s) were checked against the threat intelligence database.
- No known indicator was matched. This does not mean these events are safe: the feed only holds known indicators.

### IOA rule matches (2)

- **IOA-002 Successful Login After Repeated Failures** (Confirmed detection)
  - Severity HIGH, confidence 89%, risk 55/100 (MEDIUM), 10 event(s), last seen 2026-01-15T09:01:30+00:00
  - Description: A login succeeded from a source that had just failed repeatedly, which suggests the password was guessed.
  - Why it fired: 203.0.113.44 logged in successfully after 9 failed attempts within 600s.
  - Triggering conditions: {"type": "sequence", "group_by": ["src_ip"], "threshold": 5, "window_seconds": 600, "first": {"field": "event_type", "equals": "authentication_failure"}, "then": {"field": "event_type", "equals": "authentication_success"}}
  - MITRE ATT&CK: T1110 Brute Force, T1078 Valid Accounts
  - Supporting event IDs: ds-6e8498492f01-d1fd1da35204e42f, ds-6e8498492f01-810fe33728e23854, ds-6e8498492f01-2efcab1eb1c79387, ds-6e8498492f01-1015ae535cf876d9, ds-6e8498492f01-5ca72c1fe136f8e1, ds-6e8498492f01-85331f5ad1684eae, ds-6e8498492f01-f5bc3c613ab89a60, ds-6e8498492f01-316bb973e12fc286, ds-6e8498492f01-af1a7d29c4b2160d, ds-6e8498492f01-0303cb6d4831d065
  - Evidence: Failed login for svc_backup from 203.0.113.44 to dc-01.corp.example
  - Evidence: Failed login for svc_backup from 203.0.113.44 to dc-01.corp.example
  - Evidence: Failed login for svc_backup from 203.0.113.44 to dc-01.corp.example
- **IOA-001 Brute Force Login Attempts** (Confirmed detection)
  - Severity MEDIUM, confidence 74%, risk 41/100 (MEDIUM), 9 event(s), last seen 2026-01-15T09:01:04+00:00
  - Description: Many failed logins from one source address in a short time.
  - Why it fired: 9 failed logins from 203.0.113.44 within 300s (threshold 5).
  - Triggering conditions: {"type": "threshold", "group_by": ["src_ip"], "threshold": 5, "window_seconds": 300, "match": {"field": "event_type", "equals": "authentication_failure"}}
  - MITRE ATT&CK: T1110 Brute Force
  - Supporting event IDs: ds-6e8498492f01-d1fd1da35204e42f, ds-6e8498492f01-810fe33728e23854, ds-6e8498492f01-2efcab1eb1c79387, ds-6e8498492f01-1015ae535cf876d9, ds-6e8498492f01-5ca72c1fe136f8e1, ds-6e8498492f01-85331f5ad1684eae, ds-6e8498492f01-f5bc3c613ab89a60, ds-6e8498492f01-316bb973e12fc286, ds-6e8498492f01-af1a7d29c4b2160d
  - Evidence: Failed login for svc_backup from 203.0.113.44 to dc-01.corp.example
  - Evidence: Failed login for svc_backup from 203.0.113.44 to dc-01.corp.example
  - Evidence: Failed login for svc_backup from 203.0.113.44 to dc-01.corp.example

### UEBA findings (0)

- None.

## ML classification results

- The saved network model classified nothing in this data. See the detection engines above for why.

## Anomaly detection results

- **Unusual activity windows:** 1. Statistically unusual activity, not confirmed attacks.
- **203.0.113.44** (strength 73 of 100, 10 event(s)): Unusual compared with the model's synthetic baseline of normal activity: 9 failed logins (typically about 0.0), 10 events (typically about 1.6), 1 successful logins (typically about 0.3). A statistical anomaly, not a confirmed attack.

## Incident investigation

### INC-000005: Successful Login After Repeated Failures (dc-01.corp.example)

- **Status:** ACTIVE, priority P2
- **Severity:** HIGH
- **Confidence:** 97%
- **Risk:** 74/100 HIGH
- **Affected hosts:** dc-01.corp.example
- **Affected users:** svc_backup
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

- 2026-01-15T09:00:00+00:00: Failed login for svc_backup from 203.0.113.44 to dc-01.corp.example (x9) [IOA-001, IOA-002]
- 2026-01-15T09:01:30+00:00: Successful login for svc_backup from 203.0.113.44 to dc-01.corp.example [IOA-002]

## Affected users and hosts

- **Users:** svc_backup
- **Hosts:** dc-01.corp.example

## Risk analysis

- **Severity distribution (alerts):** HIGH 1, MEDIUM 1
- **Incident risk distribution:** CRITICAL 0, HIGH 1, MEDIUM 0, LOW 0
- **Alert risk distribution:** CRITICAL 0, HIGH 0, MEDIUM 2, LOW 0
- Risk is an investigation priority, not the probability that an attack is real. Each incident above lists the factors behind its score.

## MITRE ATT&CK mappings

- T1078 Valid Accounts (Initial Access)
- T1110 Brute Force (Credential Access)

## Recommended remediation

Historical analysis is read-only. Nothing below has been done, and any disruptive step needs an analyst to approve it.

- **IOA-001 Brute Force Login Attempts:** Review the targeted accounts and whether this source address is expected. Consider rate limiting or blocking the source address after review.
- **IOA-002 Successful Login After Repeated Failures:** Confirm with the account owner whether this login was theirs. If not, reset the account's password and revoke its active sessions. Review what the account did after this login.

## Recommended actions (simulation only)

- INC-000005, **PENDING:** Investigate source IP on `203.0.113.44`
- INC-000005, **PENDING:** Review affected account on `svc_backup`
- INC-000005, **PENDING:** Block test IP on `203.0.113.44` (disruptive, needs approval)
- INC-000005, **PENDING:** Disable test account on `svc_backup` (disruptive, needs approval)

## Analyst decisions

- None yet.

## Model performance

- This data has no ground truth labels, so these are descriptive counts, not performance metrics.

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
