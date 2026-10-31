# ALLSAFE Security Analysis Report: Data Exfiltration

- **Analysis ID:** sim-dcebbea238f6
- **Report ID:** RPT-3EEE5A1619
- **Generated:** 2026-10-31T04:31:08.904247+00:00
- **Log file:** Not a file: synthetic simulation run
- **Log type:** Synthetic simulation run
- **Analysis started:** 2026-10-31T04:31:06.885645+00:00
- **Analysis completed:** 2026-10-31T04:31:08.677154+00:00

## Overall security assessment

**THREATS DETECTED**

2 detection(s) have strong supporting evidence and need investigation.

## Executive summary

Data Exfiltration: 14 of 14 records were processed, producing 4 alert(s) and 1 incident(s). The highest priority is INC-000002, Possible Data Exfiltration (fin-02), at 78/100 (HIGH). 4 recommended action(s) are waiting for an analyst. No action has changed a real system. All of this data is synthetic.

## Threat overview

- **Attack categories:** Collection, Exfiltration
- **Rules fired:** IOA-007, IOA-016, IOC-IP, UEBA-002

## Processing summary

- **Status:** COMPLETED
- **Total uploaded records:** 14
- **Successfully processed records:** 14
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

- **IOC enrichment:** evaluated 13 of 14 event(s), 1 finding(s)
- **IOA behavior rules:** evaluated 14 of 14 event(s), 2 finding(s)
- **UEBA baselines:** evaluated 13 of 14 event(s), 2 finding(s)
- **Anomaly model:** evaluated 14 of 14 event(s), 0 finding(s)

### Skipped or failed

- **Supervised ML (saved network model) (SKIPPED):** This data has no records with all 78 CIC-IDS2017 flow features the model needs. Logs of other kinds are never fed to it.

## Finding classification

- **Confirmed detections:** 2 alert(s) over 2 event(s), 1 incident(s)
- **Suspicious activity:** 2 alert(s) over 1 event(s), 0 anomaly window(s), 0 flow(s) classified as attacks
- **Benign activity (normal events):** 11 event(s). These events triggered no applicable detection condition. That is not proof they are safe.
- **Data quality issues:** 0 bad record(s), 0 duplicate(s)
- **Detection limitations:** 1
  - Supervised ML (saved network model): This data has no records with all 78 CIC-IDS2017 flow features the model needs. Logs of other kinds are never fed to it.

## Detection results

- **Alerts:** 4
- **Incidents:** 1

### IOC matches (1)

- 13 event(s) were checked against the threat intelligence database.
- **IOC-IP Threat Intelligence Match: IP** (Confirmed detection)
  - Severity MEDIUM, confidence 70%, risk 32/100 (LOW), 2 event(s), last seen 2026-10-31T04:31:06.870354+00:00
  - Why it fired: dst_ip matched ip indicator 198.51.100.77 from feed 'allsafe-synthetic-demo-feed'. Synthetic: staging server for data theft in the demo scenarios. This is evidence to investigate, not proof of compromise.
  - Triggering conditions: {"type": "ioc", "window_seconds": 3600}
  - Matched indicator: 198.51.100.77 (ip) in dst_ip, from feed allsafe-synthetic-demo-feed. Context: Synthetic: staging server for data theft in the demo scenarios.
  - MITRE ATT&CK: not mapped
  - Supporting event IDs: sim-dcebbea238f6-00012, sim-dcebbea238f6-00013
  - Evidence: 10.40.0.2 -> 198.51.100.77:443 HTTPS, 41,943,040 bytes
  - Evidence: 10.40.0.2 -> 198.51.100.77:443 HTTPS, 41,943,040 bytes

### IOA rule matches (2)

- **IOA-016 Archive Staging** (Suspicious activity)
  - Severity LOW, confidence 40%, risk 23/100 (LOW), 1 event(s), last seen 2026-10-31T04:29:06.870354+00:00
  - Description: An archive file was accessed or created. This is weak alone and only adds context to related activity.
  - Why it fired: Archive activity by analyst1 on fin-02: Archive file accessed.
  - Triggering conditions: {"type": "threshold", "group_by": ["hostname", "user"], "threshold": 1, "window_seconds": 900, "match": {"any": [{"all": [{"field": "event_type", "in": ["file_access", "file_create"]}, {"field": "file_path", "regex": "\\.(zip|rar|7z|tar|tgz|gz)$"}]}, {"field": "command_line", "regex": "\\b(7z|rar|zip)(\\.exe)?\\s+a\\b|\\btar\\s+-?c"}]}}
  - MITRE ATT&CK: T1560 Archive Collected Data
  - Supporting event IDs: sim-dcebbea238f6-00011
  - Evidence: Archive file accessed
- **IOA-007 Possible Data Exfiltration** (Confirmed detection)
  - Severity HIGH, confidence 78%, risk 49/100 (MEDIUM), 2 event(s), last seen 2026-10-31T04:31:06.870354+00:00
  - Description: An internal host sent a large volume of data to external addresses.
  - Why it fired: 10.40.0.2 sent 80.0 MB to external destinations within 600s (threshold 50 MB).
  - Triggering conditions: {"type": "sum", "group_by": ["src_ip"], "threshold": 52428800, "field": "bytes_out", "window_seconds": 600, "match": {"all": [{"field": "source", "equals": "network"}, {"field": "src_ip", "ip_scope": "internal"}, {"field": "dst_ip", "ip_scope": "external"}, {"not": {"field": "dst_ip", "in": ["198.51.100.10"]}}]}}
  - MITRE ATT&CK: T1041 Exfiltration Over C2 Channel
  - Supporting event IDs: sim-dcebbea238f6-00012, sim-dcebbea238f6-00013
  - Evidence: 10.40.0.2 -> 198.51.100.77:443 HTTPS, 41,943,040 bytes
  - Evidence: 10.40.0.2 -> 198.51.100.77:443 HTTPS, 41,943,040 bytes

### UEBA findings (1)

- **UEBA-002 Outbound Volume Far Above This Host's Baseline** (Suspicious activity)
  - Severity MEDIUM, confidence 65%, risk 38/100 (LOW), 2 event(s), last seen 2026-10-31T04:31:06.870354+00:00
  - Description: A single transfer was far larger than this address normally sends.
  - Why it fired: 10.40.0.2 sent 40.0 MB in one transfer, 3 deviations above its average of 3.36 MB over 12 earlier transfers.
  - Triggering conditions: {"type": "baseline", "group_by": ["src_ip"], "window_seconds": 3600}
  - MITRE ATT&CK: T1048 Exfiltration Over Alternative Protocol
  - Supporting event IDs: sim-dcebbea238f6-00012, sim-dcebbea238f6-00013
  - Evidence: 10.40.0.2 -> 198.51.100.77:443 HTTPS, 41,943,040 bytes

## ML classification results

- The saved network model classified nothing in this data. See the detection engines above for why.

## Anomaly detection results

- **Unusual activity windows:** 0. Statistically unusual activity, not confirmed attacks.

## Incident investigation

### INC-000002: Possible Data Exfiltration (fin-02)

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

- 2026-10-31T04:29:06.870354+00:00: Archive file accessed [IOA-016]
- 2026-10-31T04:30:06.870354+00:00: 10.40.0.2 -> 198.51.100.77:443 HTTPS, 41,943,040 bytes (x2) [IOA-007, IOC-IP, UEBA-002]

## Affected users and hosts

- **Users:** analyst1
- **Hosts:** fin-02

## Risk analysis

- **Severity distribution (alerts):** LOW 1, HIGH 1, MEDIUM 2
- **Incident risk distribution:** CRITICAL 0, HIGH 1, MEDIUM 0, LOW 0
- **Alert risk distribution:** CRITICAL 0, HIGH 0, MEDIUM 1, LOW 3
- Risk is an investigation priority, not the probability that an attack is real. Each incident above lists the factors behind its score.

## MITRE ATT&CK mappings

- T1041 Exfiltration Over C2 Channel (Exfiltration)
- T1048 Exfiltration Over Alternative Protocol (Exfiltration)
- T1560 Archive Collected Data (Collection)

## Recommended remediation

Historical analysis is read-only. Nothing below has been done, and any disruptive step needs an analyst to approve it.

- **IOA-007 Possible Data Exfiltration:** Identify the destination and the process that sent the data. Check whether the user recently accessed sensitive file shares. Consider isolating the host after analyst review.
- **IOA-016 Archive Staging:** Check what the archive contains and whether it left this host.
- **IOC-IP Threat Intelligence Match: IP:** Verify the indicator is still current. Threat intelligence can be stale or wrong. Look for other activity that confirms or rules out compromise.
- **UEBA-002 Outbound Volume Far Above This Host's Baseline:** Review what this host sent, and to where.

## Recommended actions (simulation only)

- INC-000002, **PENDING:** Collect additional logs on `fin-02`
- INC-000002, **PENDING:** Investigate source IP on `198.51.100.77`
- INC-000002, **PENDING:** Block test IP on `198.51.100.77` (disruptive, needs approval)
- INC-000002, **PENDING:** Collect additional logs on `10.40.0.2`

## Analyst decisions

- None yet.

## Model performance

- Event level: TP 3, FP 0, FN 0, TN 11, precision 1.0, recall 1.0, F1 1.0, false-positive rate 0.0
- Alert level: TP 4, FP 0, FN 0, precision 1.0, recall 1.0, F1 1.0
- Incident level: TP 1, FP 0, FN 0, precision 1.0, recall 1.0, F1 1.0
- Detection latency: 0.212 seconds
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
