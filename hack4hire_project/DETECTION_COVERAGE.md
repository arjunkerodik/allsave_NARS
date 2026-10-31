# Detection Coverage

This describes what ALLSAFE detects today, what it assumes and where it falls short. Every scenario listed is run by the automated tests and compared against its recorded ground truth. These are synthetic scenarios written alongside the rules, so passing them shows the pipeline works as designed. It does not measure real-world detection rates.

## What defines a log as a threat

One log is rarely a threat by itself. Each rule sets five parameters: which logs count, how they are grouped, what is measured, the limit, and the time window. For example, IOA-001 fires on at least 5 logs where the event type is `authentication_failure`, from the same source IP, within 300 seconds. Four failures are suspicious. The fifth is a detection.

| Class | Meaning |
| :--- | :--- |
| Normal | Matches no rule's pattern and supports no detection. This does not prove it is harmless. |
| Suspicious | Has a rule's pattern below its limit, or supports a weak detection, or only a behavioral or model signal. |
| Threat | Supports an IOA rule or IOC match with confidence of at least 70%, and severity of MEDIUM or higher. |

Every rule's parameters are on the **Threat Parameters** page and at `GET /api/threat-parameters`. `GET /api/logs/<id>/verdict` measures them for one log, and `GET /api/simulations/<id>/impact` compares how far normal and attack logs reached against each limit.

## Required threat types

| Threat | Detected by | Scenario or sample that exercises it |
| :--- | :--- | :--- |
| Brute-force attempts | IOA-001, IOA-002, IOA-015 | `brute_force`, `credential_abuse`, `brute_force_windows.csv`, `linux_auth.log` |
| Privilege misuse | IOA-003, IOA-004, IOA-011 | `privilege_escalation`, `account_creation`, `cred_dump`, `privilege_escalation.jsonl` |
| Lateral movement | IOA-009, IOA-010 | `lateral`, `multi_stage` |
| Data exfiltration | IOA-007, IOA-016, UEBA-002, IOC match | `exfil`, `multi_stage`, `exfiltration.csv` |

## Rules

Definitions, thresholds and windows are in `config/detection_rules.json`.

| Rule | Detects | Logic (default) | Severity | MITRE |
| :--- | :--- | :--- | :--- | :--- |
| IOA-001 | Brute force | 5 or more failed logins from one IP in 5 min | MEDIUM | T1110 |
| IOA-002 | Success after failures | 5 or more failures, then a success, from one IP in 10 min | HIGH | T1110, T1078 |
| IOA-003 | Privilege escalation | Escalation event, or a matching command | HIGH | T1548, T1098 |
| IOA-004 | Account creation | Account event, or a matching command | CRITICAL | T1136 |
| IOA-005 | Port scan | SYN attempts to 15 or more ports from one IP in 60 s | MEDIUM | T1046 |
| IOA-006 | Unusual outbound port | Internal to external on a listed port | MEDIUM | T1571 |
| IOA-007 | Data exfiltration | 50 MB or more outbound from one host in 10 min | HIGH | T1041 |
| IOA-008 | Suspicious process | Listed tools or command patterns | HIGH | T1059 |
| IOA-009 | Lateral movement | One host to 3 or more internal hosts on admin ports in 5 min | HIGH | T1021 |
| IOA-010 | Remote execution tool | PsExec, WinRS, WMIC `/node`, PS remoting | HIGH | T1569.002 |
| IOA-011 | Credential dumping | LSASS memory access or dump commands | HIGH | T1003.001 |
| IOA-012 | Web shell upload | Server-side script uploaded | HIGH | T1505.003 |
| IOA-013 | Web server spawned shell | Shell whose parent is a web server | CRITICAL | T1505.003 |
| IOA-014 | Beaconing | 5 or more connections to one external IP at regular intervals | MEDIUM | T1071 |
| IOA-015 | Password spraying | Failures for 5 or more accounts from one IP in 10 min | HIGH | T1110.003 |
| IOA-016 | Archive staging | Archive access or creation. Adds context only, and opens no incident by itself. | LOW | T1560 |
| IOA-017 | Suspicious application access | 3 or more requests to sensitive paths from one IP in 5 min | MEDIUM | T1190 |
| IOA-018 | Alert reported by another security tool | One alert from an IDS, a firewall or a labelled log column. It stays suspicious until a rule of ours supports it. | MEDIUM | None |
| IOC-* | Threat intelligence | Exact match on IP, domain (including subdomains), URL or file hash | Set by feed, never CRITICAL | None |

## Behavioral baselines

Definitions are in `config/ueba_rules.json`. Each entity is compared only with its own history. An entity with too little history is not judged, so a new deployment starts quiet instead of flagging everything as new.

| Rule | Detects | Needs | Severity |
| :--- | :--- | :--- | :--- |
| UEBA-001 | Login from a source this user has never used | 5 earlier logins | MEDIUM |
| UEBA-002 | One transfer far above this address's normal volume | 10 earlier transfers, 10 MB or more, 3 or more deviations above average | MEDIUM |
| UEBA-003 | Login well outside this user's usual hours | 10 earlier logins within a span of 10 hours or fewer, then one at least 3 hours outside it | LOW |

## Machine learning

**Anomaly model.** An Isolation Forest over what each source or host did in each 5-minute window: events, failed and successful logins, distinct users, destinations and ports, admin port connections, bytes, and process starts. No rule result or label is an input. It is trained at startup, with a fixed seed, on synthetic normal activity, and measured on seeded data it did not train on:

| Measure | Result |
| :--- | :--- |
| False alarms on held-out normal windows | 3 of 2,460 (0.12%) |
| Attack windows flagged, across all scenarios | 6 of 22 (recall 0.27) |

These numbers come from `GET /api/ml`, and are shown on the Threat Parameters page. Low recall is expected, because a single command is not statistically unusual, and the rules cover those. A finding never opens an incident and never counts as confirmed: it shows as suspicious activity, and can add to the behavioral part of an incident's risk. The model does not run on live telemetry, because a synthetic baseline says nothing about what is normal on a given machine.

**Saved network model.** `nids_model.pkl` is a soft vote of LightGBM, XGBoost and CatBoost that takes the 78 named CIC-IDS2017 flow features and predicts 12 classes: BENIGN, Bot, DDoS, DoS GoldenEye, DoS Hulk, DoS Slowhttptest, DoS slowloris, FTP-Patator, PortScan, SSH-Patator, Web Attack Brute Force and Web Attack XSS.

- It runs only on records carrying all 78 features. Windows, Linux and application logs are never fed to it, and the reason appears in the analysis.
- No preprocessing pipeline was saved with it. Its tree models take the features as they are, and non-finite values such as `Infinity` are passed as missing.
- It has **not been validated here**, so no accuracy is claimed. Only synthetic flows in the CIC-IDS2017 layout have been run through it, and their random values say nothing about accuracy. A labelled CIC-IDS2017 file would be measured automatically at flow level.
- Its output is not calibrated, so **no prediction confidence is reported**. Its alerts carry a fixed, low evidence weight.
- A prediction counts as suspicious unless a rule or indicator supports it, and it cannot reach HIGH or CRITICAL risk alone.

An earlier version padded 5 per-packet values with 73 zeros and fed that to this model during live capture. That gave meaningless output, so it has been removed.

## Scenarios

| Scenario | Expected detections | Risk reached (`scripts/reproduce_demo.py`) |
| :--- | :--- | :--- |
| `brute_force` | IOA-001, IOA-002 | HIGH |
| `credential_abuse` | IOA-001, IOA-002, IOA-015 | HIGH |
| `port_scan` | IOA-005 | MEDIUM |
| `privilege_escalation` | IOA-003 | MEDIUM |
| `account_creation` | IOA-004 | MEDIUM |
| `lateral` | IOA-009, IOA-010 | MEDIUM |
| `suspicious_process` | IOA-008 | MEDIUM |
| `cred_dump` | IOA-011 | MEDIUM |
| `exfil` | IOA-007, IOA-016, IOC-IP, UEBA-002 | HIGH |
| `beacon` | IOA-014 | LOW |
| `webshell` | IOA-012, IOA-013 | MEDIUM |
| `multi_stage` | IOA-001, 002, 003, 004, 007, 009, 010, 016, IOC-IP, UEBA-001, UEBA-002, all in one incident | CRITICAL |
| `low_signal` | IOA-016. Opens no incident. | LOW (alert only) |
| `benign` | None | None |

## Log sources

| Source | Collected or accepted | Not available |
| :--- | :--- | :--- |
| Network | Flow records, including the CIC-IDS2017 layout; firewall logs (kernel and UFW lines, or structured with an action); packet metadata when capture is available; flow summaries from PCAP | Encrypted payload contents. Live capture needs administrator rights and Npcap on Windows. |
| Windows | Security and Sysmon events from .evtx files, Event Viewer XML, or exports to CSV or JSON, including UTF-16 and Winlogbeat: 4624, 4625, 4634, 4647, 4648, 4672, 4720, 4728, 4732, 4740, 4756, 4688, 4689, 4771, 4776, Sysmon 1, 3, 5, 10, 11, 22. Other event IDs are kept and named, and no rule reads them. | Event 4672 alone is not treated as escalation, because it occurs at every administrator logon. |
| Linux | sshd, sudo, useradd and PAM lines from auth logs | Other daemons' messages are reported as unrecognized lines |
| Endpoint | Process start and stop, parent process, command line where permitted, high resource use, new files in Downloads, Desktop and `temp`, connections to remote-access ports; uploaded process records | Kernel-level events, registry monitoring, file reads, LSASS access on the live collector. Polling every few seconds can miss short-lived processes. |
| Application | Requests to this application; uploaded web and authentication logs | This dashboard has no login, so authentication events come only from uploads, the API and simulations. |

**Real collectors and these rules:** many rules (such as IOA-011 and IOA-012) need event types the local collectors cannot observe. They work on uploaded logs, API events and simulations, but will not fire from live collection on this machine.

## How findings are classified

| Class | Meaning |
| :--- | :--- |
| Confirmed detection | A rule or indicator alert with confidence of at least 70 (configurable) that is not LOW severity. Strong evidence, not proof. |
| Suspicious activity | Weaker alerts, behavioral findings, anomaly windows and model predictions. Needs a person to look. |
| Benign activity | Events that triggered no applicable condition. That is not proof they are safe. |
| Data quality issue | Rejected, malformed or duplicate records, and bad or missing timestamps. |
| Detection limitation | An engine that could not evaluate this data, or events no engine could evaluate. |

A dataset is never described as safe. If nothing is found, the result is **NO THREATS DETECTED**, with the statement that this does not guarantee the environment is free of threats. If an engine failed, or none could evaluate the records, the result is **ANALYSIS INCOMPLETE**.

## How incidents are scored

- **Severity (potential impact):** the highest severity among the incident's alerts.
- **Confidence (strength of evidence):** `1 - product(1 - alert confidence x link score)`, using the best alert per rule. Base confidence values are judgment-based settings in the rule file, not measured probabilities.
- **Risk (investigation priority):** a weighted sum of severity (25), evidence confidence (25), IOC and IOA signals (20), behavioral anomalies (15) and attack progression (15), plus up to 5 for asset importance, capped at 100. UEBA findings, model predictions and anomaly windows are alternatives within the behavioral factor, so one piece of unusual activity is not counted three times. Levels start at CRITICAL 90, HIGH 70, MEDIUM 40.

The dashboard and reports show each component and its reason. Weights are judgment-based, and have not been tuned against real data.

Alerts link to an incident only through shared entities, weighted by type: session, source IP, user, hostname, or a pivot where an earlier destination becomes a source. Occurring at the same time never links alerts, and a shared external destination alone is too weak to link them.

## Response

Each detection can recommend actions, listed in `config/response_playbook.json`. Nothing disruptive runs without an analyst's decision, and by default every action runs in simulation only: it writes to a `simulated_enforcement` table, and verification reads that record back. There is no code path that reaches a real firewall, account or process. Verification therefore confirms the record was written, not a real-world effect. Historical dataset analysis is read-only. Each action also shows the real commands for an analyst to run by hand. Optional real mode adds one real change: a Windows Firewall block on this machine, after a person approves it, with undo.

The risk tier decides which safe steps run by themselves: enrichment, grouping duplicates, updating the monitoring record, collecting evidence, creating an investigation task, and notifying the analyst. These only read stored data and write SOC records.

Addresses and accounts in `protected_targets` cannot be acted on, and an attempt is recorded as FAILED with the reason. Decisions, results and refused attempts all go to an append-only audit log, which the database itself protects from change.

## Assumptions

- Internal addresses are the private, loopback and link-local ranges. All others are external.
- `198.51.100.10` is the demo's approved backup destination, set in IOA-007. Change this for any real use.
- Log timestamps without a timezone are treated as server local time. Syslog has no year, so the most recent matching date is assumed. CIC-IDS2017 timestamps are read as day first. Other dates such as `01/02/2026` are ambiguous, and are read month first unless only day first can be valid.
- A flow file with no timestamps is kept with no event time, because a time is never made up. Its timestamp column then holds the ingestion time, with a note on the event, and time-based engines report that they could not evaluate it.
- The asset list in `config/risk_scoring.json` describes the synthetic demo hosts. So does `host_addresses`, which tells correlation that a hostname and an address are the same machine. Without an entry there, host logs and flow data for one machine will not link.

## Known limitations

- **Thresholds are fixed.** Slow attacks that stay under a threshold or window are missed, and legitimate bursts can trigger alerts. A shared address (such as NAT) can combine unrelated users.
- **Command patterns are bypassable.** Renamed tools and obfuscated commands can evade IOA-003, 004, 008 and 010, and these rules can also flag legitimate administrators.
- **Behavioral baselines are simple.** They have no sense of day of week, seasonality or role, and a new user has no baseline at all.
- **The anomaly model's baseline is synthetic.** Findings on real uploaded data show difference from that baseline, not necessarily anything wrong.
- **IOC matching is only as good as its feed.** The bundled feed is synthetic. An uploaded feed is trusted at the confidence it states, and a wrong entry produces a false alert. Indicators do not expire, and updating a feed means uploading it again.
- **Feed analysis reports what the feed says.** Its themes match words in the feed's own text, and nothing verifies an indicator. **Test this feed** plants indicators in synthetic logs, so it shows that matching works, not that the feed is accurate or that an organization was contacted.
- **A retro-hunt only reports.** It lists stored events containing a new feed's indicators and creates no alerts, so past matches do not open incidents. New events that match do.
- **Simulation impact is inferred.** Asset states come from which detections fired, using `config/impact_model.json`, the team's judgement of what each detection implies. Nothing measures whether a real asset would have been harmed, and an attack no rule detects shows no impact.
- **A verdict for one log uses its context as stored now,** so it can change as later logs arrive. Logs below every limit are classed as normal in the live flow, which counts only stored detections.
- **NARS reports what is stored.** It adds no detection. Local mode recognises question patterns rather than understanding language, and says so when it has no answer. AI mode can misread evidence, so its answers should be checked against the sources it lists.
- **Correlation limits:** two unrelated attacks on the same host in the window will merge. An alert that bridges two existing incidents joins the stronger one and does not merge them.
- **Each simulation run and log file is isolated by design.** Each is evaluated and correlated separately, so activity spanning two uploads is not connected.
- **Window-based rules cite every matching event in their window,** so a normal event inside an attack's window counts as an event-level false positive.
- **Beacon detection** looks for regular timing only, so random jitter above 15% evades it, and legitimate pollers can trigger it.
- **Payload signatures** in the network collector mark packet details only. They do not produce alerts.
- **Large files are held in memory** while validated, and at most `ALLSAFE_MAX_DATASET_RECORDS` records are analyzed from one file, with a warning for any left out. Very large logs need sampling, or higher limits and enough memory.
- **Any log can be stored, but detection needs fields.** A log with no time cannot trigger time-window rules, so it is reported as ANALYSIS INCOMPLETE. A log with no addresses, users or hosts gives rules little to work with, and the result says so.
- **No user accounts.** Anyone who can reach the port can read everything, ingest logs and run scenarios, so the default bind is localhost. Analyst decisions are refused from other machines, but analyst names are self-reported, so the audit log records who claimed to act. The blocklist records an intent and enforces nothing.
- **No learning from analyst feedback.** Decisions are recorded, but nothing retrains on them.
- **Closed incidents stay closed.** New activity after an incident is resolved opens a new incident, and the two are not linked to each other.
- **Not validated at scale or against real attacks.** There are no benchmarks of throughput, detection rate or false-positive rate on real traffic.
