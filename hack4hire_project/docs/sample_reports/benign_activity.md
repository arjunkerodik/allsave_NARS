# ALLSAFE Security Analysis Report: Benign Activity

- **Analysis ID:** sim-52cd8c96c571
- **Report ID:** RPT-31013255CD
- **Generated:** 2026-10-31T04:31:13.871087+00:00
- **Log file:** Not a file: synthetic simulation run
- **Log type:** Synthetic simulation run
- **Analysis started:** 2026-10-31T04:31:13.530962+00:00
- **Analysis completed:** 2026-10-31T04:31:13.784323+00:00

## Overall security assessment

**SUSPICIOUS ACTIVITY FOUND**

Nothing here has strong enough evidence to count as a confirmed detection, but some of it needs an analyst to look at it.

## Executive summary

Benign Activity: 13 of 13 records were processed, producing 0 alert(s) and 0 incident(s). No incident was created. 0 recommended action(s) are waiting for an analyst. No action has changed a real system. All of this data is synthetic.

## Threat overview

- **Attack categories:** none
- **Rules fired:** none

## Processing summary

- **Status:** COMPLETED
- **Total uploaded records:** 13
- **Successfully processed records:** 13
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

- **IOC enrichment:** evaluated 9 of 13 event(s), 0 finding(s)
- **IOA behavior rules:** evaluated 13 of 13 event(s), 0 finding(s)
- **UEBA baselines:** evaluated 5 of 13 event(s), 0 finding(s)
- **Anomaly model:** evaluated 13 of 13 event(s), 1 finding(s)

### Skipped or failed

- **Supervised ML (saved network model) (SKIPPED):** This data has no records with all 78 CIC-IDS2017 flow features the model needs. Logs of other kinds are never fed to it.

## Finding classification

- **Confirmed detections:** 0 alert(s) over 0 event(s), 0 incident(s)
- **Suspicious activity:** 0 alert(s) over 4 event(s), 1 anomaly window(s), 0 flow(s) classified as attacks
- **Benign activity (normal events):** 9 event(s). These events triggered no applicable detection condition. That is not proof they are safe.
- **Data quality issues:** 0 bad record(s), 0 duplicate(s)
- **Detection limitations:** 1
  - Supervised ML (saved network model): This data has no records with all 78 CIC-IDS2017 flow features the model needs. Logs of other kinds are never fed to it.

## Detection results

- **Alerts:** 0
- **Incidents:** 0

### IOC matches (0)

- 9 event(s) were checked against the threat intelligence database.
- No known indicator was matched. This does not mean these events are safe: the feed only holds known indicators.

### IOA rule matches (0)

- None.

### UEBA findings (0)

- None.

## ML classification results

- The saved network model classified nothing in this data. See the detection engines above for why.

## Anomaly detection results

- **Unusual activity windows:** 1. Statistically unusual activity, not confirmed attacks.
- **10.60.0.20** (strength 53 of 100, 4 event(s)): Unusual compared with the model's synthetic baseline of normal activity: 1 connections to admin ports (typically about 0.0), 2 distinct destination ports (typically about 0.3), 2 distinct destinations (typically about 0.3). A statistical anomaly, not a confirmed attack.

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

- Event level: TP 0, FP 0, FN 0, TN 13, precision not measurable, recall not measurable, F1 not measurable, false-positive rate 0.0
- Alert level: TP 0, FP 0, FN 0, precision not measurable, recall not measurable, F1 not measurable
- Incident level: TP 0, FP 0, FN 0, precision not measurable, recall not measurable, F1 not measurable
- Anomaly model, event level: TP 0, FP 4, FN 0, TN 9, precision 0.0, recall not measurable, F1 0.0, false-positive rate 0.3077
- Detection latency: not measurable, because no attack was detected
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
