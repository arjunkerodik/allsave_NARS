# ALLSAFE Security Analysis Report: network_flows_cicids.csv

- **Analysis ID:** ds-5b9975b6eb9e
- **Report ID:** RPT-85381B7E95
- **Generated:** 2026-10-31T04:31:35.932043+00:00
- **Log file:** network_flows_cicids.csv
- **Log type:** Network flow events
- **Analysis started:** 2026-10-31T04:31:33.309043+00:00
- **Analysis completed:** 2026-10-31T04:31:35.846842+00:00

## Overall security assessment

**SUSPICIOUS ACTIVITY FOUND**

Nothing here has strong enough evidence to count as a confirmed detection, but some of it needs an analyst to look at it.

## Executive summary

network_flows_cicids.csv: 200 of 200 records were processed, producing 0 alert(s) and 0 incident(s). No incident was created. 0 recommended action(s) are waiting for an analyst. No action has changed a real system.

## Threat overview

- **Attack categories:** none
- **Rules fired:** none

## Processing summary

- **Status:** COMPLETED
- **Total uploaded records:** 200
- **Successfully processed records:** 200
- **Rejected records:** 0
- **Duplicate records:** 0

## Data quality

- **Malformed records:** 0
- **Invalid timestamps:** 0
- **Missing timestamps:** 0
- **Flows with no timestamp, kept:** 200
- **Missing optional values:** timestamp 200, event_type 200, src_ip 200, dst_ip 200, user 200, hostname 200
- **Fields with no equivalent in the common schema:** Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets, Total Length of Bwd Packets, Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std, Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std, Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min, Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Length, Bwd Header Length, Fwd Packets/s, Bwd Packets/s, Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance, FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count, CWE Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size, Fwd Header Length.1, Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate, Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes, Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward, Active Mean, Active Std, Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min
- **Warning:** 200 of 200 record(s) hold only a time and a message, with no address, user, host or process. Most rules measure those fields, so they had little to work with here.
- **Warning:** 200 flow record(s) have no timestamp. They were kept, but time-based detection cannot evaluate them.
- **Warning:** 76 field(s) have no equivalent in the common schema. They are preserved with each event, but no detection reads them.

## Detection engines

### Executed

- **Supervised ML (saved network model):** evaluated 200 of 200 event(s), 0 finding(s)

### Skipped or failed

- **IOC enrichment (SKIPPED):** No event had both a timestamp and an IP address, domain, URL or file hash to check.
- **IOA behavior rules (SKIPPED):** No event had a usable timestamp, and every behavior rule works over a time window.
- **UEBA baselines (SKIPPED):** No event was a successful login or an outbound transfer with a timestamp, which is what the baselines compare.
- **Anomaly model (SKIPPED):** No event had a timestamp and a source or host to group by.

## Finding classification

- **Confirmed detections:** 0 alert(s) over 0 event(s), 0 incident(s)
- **Suspicious activity:** 0 alert(s) over 5 event(s), 0 anomaly window(s), 5 flow(s) classified as attacks
- **Benign activity (normal events):** 195 event(s). These events triggered no applicable detection condition. That is not proof they are safe.
- **Data quality issues:** 0 bad record(s), 0 duplicate(s)
- **Detection limitations:** 4
  - IOC enrichment: No event had both a timestamp and an IP address, domain, URL or file hash to check.
  - IOA behavior rules: No event had a usable timestamp, and every behavior rule works over a time window.
  - UEBA baselines: No event was a successful login or an outbound transfer with a timestamp, which is what the baselines compare.
  - Anomaly model: No event had a timestamp and a source or host to group by.

## Detection results

- **Alerts:** 0
- **Incidents:** 0

### IOC matches (0)

- 0 event(s) were checked against the threat intelligence database.
- No known indicator was matched. This does not mean these events are safe: the feed only holds known indicators.

### IOA rule matches (0)

- None.

### UEBA findings (0)

- None.

## ML classification results

- **Flows classified:** 200, by model version 33d735ec14d8
- **Distribution:** BENIGN 195, DoS Slowhttptest 1, SSH-Patator 4
- **Prediction confidence:** not reported, because the model is not calibrated. Predictions from one uncalibrated model, not validated here. They are suspicious until something else supports them.

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

- Event level: TP 2, FP 3, FN 41, TN 154, precision 0.4, recall 0.0465, F1 0.0833, false-positive rate 0.0191
- Alert level: TP 0, FP 0, FN 0, precision not measurable, recall not measurable, F1 not measurable
- Incident level: TP 0, FP 0, FN 1, precision not measurable, recall 0.0, F1 0.0
- Network model, flow level: TP 2, FP 3, FN 41, TN 154, precision 0.4, recall 0.0465, F1 0.0833, false-positive rate 0.0191
- Detection latency: not measurable, because no attack was detected
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
