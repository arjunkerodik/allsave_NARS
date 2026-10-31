# ALLSAFE Security Analysis Report: malformed_records.csv

- **Analysis ID:** ds-885e4a4ec49b
- **Report ID:** RPT-47BD5E6D4B
- **Generated:** 2026-10-31T04:31:31.642009+00:00
- **Log file:** malformed_records.csv
- **Log type:** Application security events
- **Analysis started:** 2026-10-31T04:31:31.207362+00:00
- **Analysis completed:** 2026-10-31T04:31:31.523603+00:00

## Overall security assessment

**NO THREATS DETECTED**

No suspicious activity was detected by the enabled detection engines during this analysis. This does not guarantee that the environment is completely free of threats.

## Executive summary

malformed_records.csv: 6 of 11 records were processed, producing 0 alert(s) and 0 incident(s). No incident was created. 0 recommended action(s) are waiting for an analyst. No action has changed a real system.

## Threat overview

- **Attack categories:** none
- **Rules fired:** none

## Processing summary

- **Status:** COMPLETED
- **Total uploaded records:** 11
- **Successfully processed records:** 6
- **Rejected records:** 5
- **Duplicate records:** 0

## Data quality

- **Malformed records:** 2
- **Invalid timestamps:** 1
- **Missing timestamps:** 0
- **Flows with no timestamp, kept:** 0
- **Missing optional values:** dst_ip 6, hostname 6
- **Fields with no equivalent in the common schema:** none

## Detection engines

### Executed

- **IOC enrichment:** evaluated 6 of 6 event(s), 0 finding(s)
- **IOA behavior rules:** evaluated 6 of 6 event(s), 0 finding(s)
- **UEBA baselines:** evaluated 6 of 6 event(s), 0 finding(s)
- **Anomaly model:** evaluated 6 of 6 event(s), 0 finding(s)

### Skipped or failed

- **Supervised ML (saved network model) (SKIPPED):** This data has no records with all 78 CIC-IDS2017 flow features the model needs. Logs of other kinds are never fed to it.

## Finding classification

- **Confirmed detections:** 0 alert(s) over 0 event(s), 0 incident(s)
- **Suspicious activity:** 0 alert(s) over 0 event(s), 0 anomaly window(s), 0 flow(s) classified as attacks
- **Benign activity (normal events):** 6 event(s). These events triggered no applicable detection condition. That is not proof they are safe.
- **Data quality issues:** 3 bad record(s), 0 duplicate(s)
- **Detection limitations:** 1
  - Supervised ML (saved network model): This data has no records with all 78 CIC-IDS2017 flow features the model needs. Logs of other kinds are never fed to it.

## Detection results

- **Alerts:** 0
- **Incidents:** 0

### IOC matches (0)

- 6 event(s) were checked against the threat intelligence database.
- No known indicator was matched. This does not mean these events are safe: the feed only holds known indicators.

### IOA rule matches (0)

- None.

### UEBA findings (0)

- None.

## ML classification results

- The saved network model classified nothing in this data. See the detection engines above for why.

## Anomaly detection results

- **Unusual activity windows:** 0. Statistically unusual activity, not confirmed attacks.

## Incident investigation

No incident was created.

## Affected users and hosts

- **Users:** none named
- **Hosts:** none named

## Risk analysis

- **Severity distribution (alerts):** none
- **Incident risk distribution:** CRITICAL 0, HIGH 0, MEDIUM 0, LOW 0
- **Alert risk distribution:** CRITICAL 0, HIGH 0, MEDIUM 0, LOW 0
- Risk is an investigation priority, not the probability that an attack is real. Each incident above lists the factors behind its score.

## MITRE ATT&CK mappings

- None.

## Recommended remediation

Historical analysis is read-only. Nothing below has been done, and any disruptive step needs an analyst to approve it.

- None required by these findings.

## Recommended actions (simulation only)

- None.

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
