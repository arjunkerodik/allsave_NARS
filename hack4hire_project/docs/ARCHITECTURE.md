# Architecture and Setup

ALLSAFE is one Python process with a browser dashboard. Every event, whatever its origin, takes the same path through the same code. There is no separate detection path for uploads or simulations.

## Setup

Requires Python 3.12. The dashboard's libraries are bundled, so it needs no internet access.

```bash
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`. To keep a demonstration apart from any existing data, give it its own database:

```powershell
$env:ALLSAFE_DB_PATH = "demo.db"; python app.py     # PowerShell
```
```bash
ALLSAFE_DB_PATH=demo.db python app.py               # bash
```

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `ALLSAFE_HOST` | `127.0.0.1` | Bind address. The server has no TLS and is a development server, so exposing it is unsafe even with accounts on. |
| `ALLSAFE_PORT` | `5000` | Port |
| `ALLSAFE_DB_PATH` | `security_monitoring.db` | Database file |
| `ALLSAFE_MAX_UPLOAD_MB` | `100` | Log file size limit. Parsing holds the file in memory. |
| `ALLSAFE_MAX_DATASET_RECORDS` | `100000` | Records analyzed from one file. Any left out are reported as a warning. |
| `ALLSAFE_LOAD_ML` | `1` | `0` switches off the saved network model. Flow data then reports that it could not be classified. |
| `ALLSAFE_PUBLIC_DEMO` | `0` | `1` is for a copy reachable from the internet: it reads no `.env`, runs no live collectors, keeps real mode and mail off, closes sign-up, and will not start without an account. Use a new database for it. |
| `ALLSAFE_REAL_RESPONSE` | `0` | `1` turns on real mode: an analyst who approves Block test IP adds a real Windows Firewall rule on this machine. It needs an Administrator terminal. |
| `ALLSAFE_SECRET_KEY` | random per run | Flask secret key. Set it so that logins survive a restart. |
| `ALLSAFE_HTTPS` | `0` | `1` marks the session cookie as HTTPS only. Use it behind a TLS proxy. |
| `GROQ_API_KEY` | unset | Turns on NARS AI mode with Groq. The stored data NARS reads is then sent to Groq. |
| `ANTHROPIC_API_KEY` | unset | Turns on NARS AI mode with Claude, when no Groq key is set. The stored data NARS reads is then sent to the Anthropic API. |
| `NARS_MODEL` | `openai/gpt-oss-120b` on Groq, `claude-opus-5-5` on Claude | The model for NARS |
| `ALLSAFE_SMTP_HOST`, `ALLSAFE_SMTP_PORT`, `ALLSAFE_SMTP_USER`, `ALLSAFE_SMTP_PASSWORD`, `ALLSAFE_SMTP_SECURITY` | port `587`, `starttls` | The mail server for alert emails. Security can be `starttls`, `ssl` or `none`. |
| `ALLSAFE_ALERT_EMAIL_TO`, `ALLSAFE_ALERT_EMAIL_FROM` | unset | Who gets alert emails (comma separated), and who they come from. No recipient means no email. |
| `ALLSAFE_ALERT_EMAIL_MIN_RISK`, `ALLSAFE_ALERT_EMAIL_MAX_PER_HOUR` | `HIGH`, `20` | Which incidents are emailed, and the hourly limit |
| `ALLSAFE_PUBLIC_URL` | this machine | The base of links in alert emails |
| `ALLSAFE_NO_ENV_FILE` | `0` | `1` ignores `.env`. The test suites use it, so that they never call an AI service or send email. |

`app.py` reads these from a `.env` file beside it when started directly. Real environment variables win. See `.env.example`.
| `NARS_MODE` | unset | `local` keeps NARS in local mode even with a key |
| `ALLSAFE_DEBUG` | `0` | Flask debug mode. Never enable this on a shared network. |
| `ALLSAFE_SIMULATED_TELEMETRY` | `0` | Random packets when capture is unavailable, labelled `simulated_telemetry`. |

Live packet capture needs administrator rights and Npcap on Windows. Without them the dashboard says capture is unavailable, and network data comes from uploads and simulations.

## Data flow

```text
 Live collectors     Dataset upload            Simulation Lab
 (this machine)      (validate, identify,      (synthetic events,
      |               parse, map fields)        ground truth kept apart)
      |                     |                        |
      +----------+----------+------------------------+
                 |
        utils/normalizer.py      one schema; the original record is kept untouched
                 |
           logs table            every event is stored first
                 |
   utils/correlation_engine.py   reads new events through a saved cursor, and records for
                 |               each dataset what each engine really did (engine_runs)
                 |
   +---------+---+-----+-----------+-------------+
   |         |         |           |             |
  IOC       IOA       UEBA    Saved network    Anomaly
 feed      rules    baselines     model         model
   |         |         |           |             |
   +----+----+---------+-----+-----+             |
        |                    |                   |
      alerts        predictions stored    unusual windows stored
        |                                        |
   link by shared entities into incidents        |
        |                                        |
   utils/risk_engine.py  <-----------------------+
   severity, confidence and risk, kept separate, each with reasons
        |
   utils/automation.py        safe steps by risk tier. Never touches a system.
   utils/response_engine.py   recommended actions wait for an analyst, and run only in simulation
        |
   utils/dataset_analysis.py  finding classes and the verdict, from what was recorded
   utils/report_engine.py     reports from stored results: PDF, JSON, Markdown, CSV
        |
   REST API + Socket.IO + dashboard
```

## Modules

| Path | Responsibility |
| :--- | :--- |
| `app.py` | Flask application and REST API |
| `models.py` | Database schema, additive migrations and queries |
| `collectors/` | Live network, endpoint and application collectors |
| `utils/normalizer.py` | The common event schema |
| `utils/log_ingest.py` | Exact text log parsers (web access, sshd, sudo, useradd, PAM, kernel firewall), PCAP flows and storing records |
| `utils/log_formats.py` | Reads other log types by shape: CEF, LEEF, syslog, nginx, Snort, Zeek, IIS, XML, EVTX, nested JSON, and .gz or .zip |
| `utils/source_parsers.py` | Identifies what kind of log a record is, and maps it: CIC-IDS2017 flows, Windows events, firewall, Linux, endpoint, application |
| `utils/dataset_engine.py` | Validates a file: content against name, encoding, structure, columns, bad and duplicate records |
| `utils/dataset_generator.py` | Seeded synthetic datasets, with labels kept apart from events |
| `utils/job_runner.py` | Background simulations and dataset jobs. One of each at a time. |
| `utils/detection_engine.py` | IOA rules, using event time |
| `utils/ioc_engine.py` | Threat intelligence matching |
| `utils/ioc_feed.py` | Recognises uploaded threat intelligence feeds, imports them, and searches stored events for their indicators |
| `utils/nars.py` | The NARS assistant: read-only lookups, local answers, and the Claude tool loop |
| `utils/attack_views.py` | The attack graph for an incident, rule coverage on ATT&CK, and the live flow's counts |
| `utils/threat_parameters.py` | States each rule's parameters in words, measures them on any logs, and explains one log's verdict |
| `utils/impact.py`, `config/impact_model.json` | What a threat did to a simulated environment: assets before and after, and limits crossed |
| `utils/email_alerts.py` | Alert emails over SMTP on their own thread, with an hourly limit and a record of each attempt |
| `static/flow.js`, `static/landing.js` | The animated flow, and the landing page |
| `utils/auth.py`, `scripts/manage_users.py` | Optional accounts: password hashing, login throttling, roles |
| `utils/ueba_engine.py` | Each entity against its own history |
| `utils/anomaly_engine.py` | Isolation Forest over 5-minute activity windows, trained on synthetic normal activity |
| `utils/nids_engine.py` | The saved network model. Only ever sees records with all 78 of its features. |
| `utils/correlation_engine.py` | Runs the engines, records that they ran, links alerts into incidents |
| `utils/risk_engine.py` | Severity, confidence and risk, each with reasons |
| `utils/automation.py` | Safe automatic steps for each risk tier |
| `utils/response_engine.py` | The response policy, the approval workflow and simulated execution |
| `utils/real_response.py` | Real mode's Windows Firewall calls and their safety checks, and the real commands shown for each action |
| `utils/evaluation.py` | Metrics against ground truth, at event, alert, incident and model level |
| `utils/dataset_analysis.py` | Finding classes and the overall verdict |
| `utils/report_engine.py` | Report content and its PDF, JSON, Markdown and CSV forms |
| `config/` | Detection rules, behavioral rules, model rules, risk weights, response policy |
| `data/samples/` | Synthetic sample datasets. Rebuild with `scripts/make_sample_datasets.py`. |
| `scripts/reproduce_demo.py` | The whole pipeline from the command line, with checks |
| `docs/sample_reports/` | Reports from that script, and its output in `RUN_SUMMARY.txt` |

## How a verdict is reached

A verdict comes from what the engines recorded for that dataset, not from an assumption that they ran.

| Verdict | When |
| :--- | :--- |
| `VALIDATION_FAILED` | The file could not be read at all, or holds no usable record. |
| `ANALYSIS_INCOMPLETE` | The job died or was interrupted, an engine failed, a finding could not be stored, or no engine could evaluate the records. Never shown as clean. |
| `THREATS_DETECTED` | At least one rule or indicator alert meets the confirmation threshold (`classification.confirmed_min_confidence` in `config/risk_scoring.json`, default 70) and is not LOW severity. |
| `SUSPICIOUS_ACTIVITY` | Only weaker signals: lower-confidence alerts, behavioral findings, anomaly windows or model predictions. |
| `NO_THREATS_DETECTED` | Engines ran and nothing was found. The result always says this is not a guarantee. |

An engine that had nothing to evaluate is reported as `SKIPPED` with its reason. For example, the network model is skipped on Windows logs, and that is not a failure.

## How risk is scored

Risk is an investigation priority from 0 to 100. It is not the probability that an attack is real. Severity and confidence are separate values, and each has its own reasons.

| Factor | Weight | What gives it points |
| :--- | :--- | :--- |
| Severity | 25 | The highest alert severity |
| Evidence confidence | 25 | Independent rules reinforcing each other, weighted by how strongly they link |
| IOC and IOA signals | 20 | Distinct behavior rules, and the best threat intelligence match |
| Behavioral anomalies | 15 | The strongest of: UEBA finding, network model prediction, anomaly window. Only one counts, so the same activity is not counted three times. |
| Attack progression | 15 | Distinct MITRE tactics and detections |
| Asset importance | up to +5 | The most critical affected asset in the asset list |

Levels start at CRITICAL 90, HIGH 70, MEDIUM 40, LOW 0. The weights and levels are starting values rather than a security standard. They can be changed on the Risk Management page, which scores open incidents again and writes to the audit log. A single indicator cannot reach CRITICAL.

## Automation policy

High and critical risk wait for the SOC. Small risks are handled automatically, but what an action could affect still decides: a disruptive action never runs on its own.

| Risk | Done automatically | Analyst |
| :--- | :--- | :--- |
| LOW | Enrich, group duplicates, update the monitoring record. Safe response actions run in simulation. | Not needed. Disruptive actions are held. |
| MEDIUM | Those, plus collect evidence and create an investigation task | Not needed. Disruptive actions are held. If the risk rises, held actions join the SOC queue. |
| HIGH | Those, plus an urgent notification | Every open response action waits for SOC approval |
| CRITICAL | Those, plus a critical notification | Every open response action waits for SOC approval |

An attack often starts small and grows. A safe step can run automatically while its incident is still at medium risk. When the risk rises, that step stays on record, held actions join the SOC queue, and everything still open waits for approval.

Automatic steps only read stored data and write SOC records. Blocking an address, disabling an account and terminating a process always need an analyst, and even then they only write to a `simulated_enforcement` table. There is no code path to a real firewall, account or process. The exception is optional real mode. With it on, Block test IP adds a real Windows Firewall rule after a person approves it and clicks run, and that person can undo it. Automation never makes a real change, an uploaded log never does, and internal addresses, protected targets, DNS servers and this machine's own addresses are refused. Stopping processes and changing accounts stay as commands for an analyst to run.

## Data storage

SQLite in WAL mode. In the server each thread keeps its database connection, because opening and closing one per query was most of the time spent on an uploaded log. Migrations are additive, so an existing database upgrades in place when the application starts. `audit_log` is append-only: database triggers refuse changes and deletions.

| Tables | Hold |
| :--- | :--- |
| `logs` | Events, with the original record in `raw_event` |
| `alerts`, `alert_events`, `incidents` | Detections, the events supporting them, and correlated incidents |
| `iocs` | Threat intelligence |
| `users` | Optional accounts, with hashed passwords and roles |
| `email_log` | Each alert email attempt and its result |
| `ground_truth` | Labels, kept apart from `logs`, which is all that detection reads |
| `simulation_runs`, `datasets` | Runs and dataset jobs, with their status, validation summary and verdict |
| `engine_runs` | What each engine did for each dataset or run |
| `ml_predictions`, `anomaly_findings` | Model output for each flow, and unusual activity windows |
| `response_actions`, `simulated_enforcement` | Recommendations, decisions and simulated results |
| `automation_log`, `notifications` | Automatic steps and analyst notifications |
| `reports`, `audit_log` | Generated reports and the record of who did what |

## Tests

```bash
python -m unittest discover -s tests -t .   # unit and API tests
python tests/e2e_pipeline.py                # the whole pipeline against a real server
node tests/e2e_browser.mjs                  # the dashboard in headless Edge or Chrome
python scripts/reproduce_demo.py            # the demonstration, with checks
```

All of them use temporary databases and never touch your data. The pipeline test starts one harmless real PowerShell process on Windows, to check the live endpoint collector.

## What production would still need

This is a hackathon prototype. Accounts and roles exist, but they are optional and have no single sign-on or multi-factor login. Before real use it would need TLS, a production WSGI server in place of the development server, a server database in place of SQLite, a detection worker separate from the web process, scheduled threat intelligence updates with expiry, validation of the network model on real traffic, and tuning of every threshold on real data.
