# ALLSAFE // AI-Driven SIEM Command Center

ALLSAFE is a security monitoring prototype built for **Hack4Hire 2026**, for the problem statement *AI-Powered Cybersecurity and Threat Detection*. It ingests common log formats, normalizes them into one schema, detects suspicious activity with rules, threat intelligence, behavioral baselines and machine learning, correlates related alerts into investigation timelines, assigns severity, confidence and risk, explains why each thing was flagged, and recommends proportionate responses for an analyst to approve.

**NARS**, the built-in assistant, answers an analyst's questions from the stored data, shows what it read, and can never change anything. ALLSAFE uses only public or synthetic data. It is a hackathon prototype, not a production product. See [what production would still need](docs/ARCHITECTURE.md#what-production-would-still-need).

| Deliverable | Where |
| :--- | :--- |
| Source code | This repository |
| Architecture and setup notes | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Reproducible demonstration | [docs/DEMO.md](docs/DEMO.md) and `python scripts/reproduce_demo.py` |
| Sample investigation reports | [docs/sample_reports/](docs/sample_reports/) |
| Coverage statement: threat types, assumptions, known limitations | [DETECTION_COVERAGE.md](DETECTION_COVERAGE.md) |

## Quick start

Requires Python 3.12. The saved model needs NumPy 2.

```bash
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` for the landing page, then **Open the console**. Optional keys and mail settings go in `.env`: copy `.env.example`. Git ignores `.env`, so never zip it with the code. In the console:

1. Enter your name in the **Analyst** box. It goes in the audit log.
2. Open **Simulation Lab** and click **Run** on **Multi-Stage Attack**. Then click **Investigate**.
3. Open **Log Analysis** and add any log file: one from `data/samples/` or `data/samples/formats/`, or your own public or synthetic log.

Or see the whole pipeline work from the command line, with checks, on a throwaway database:

```bash
python scripts/reproduce_demo.py
```

To keep a demonstration apart from existing data, set `ALLSAFE_DB_PATH` to a new file. The full procedure is in [docs/DEMO.md](docs/DEMO.md).

## The console

The menu follows the workflow. **Monitor:** Overview and Live Stream. **Analyze:** Log Analysis, Threat Detection, Threat Parameters and the Simulation Lab. **Respond:** Investigations, Response and Reports. Supporting pages are under **More**: Threat Intelligence, Risk Settings, ATT&CK Coverage and the Audit Log.

## Current status

| Capability | Status |
| :--- | :--- |
| Ingestion: live collectors, log file upload, JSON API | Working |
| Log types: any text log, plus CSV, JSON, JSONL, XML, Windows EVTX and PCAP, also inside a single-file .gz or .zip. Read by name or shape: syslog (RFC 3164 and 5424), SSH and Linux auth, Apache, nginx, IIS, Zeek, Suricata, Snort, CEF, LEEF, CloudTrail, Okta, Winlogbeat and Elastic exports, firewall logs, Windows Event Viewer exports | Working. Each has a synthetic sample in `data/samples/formats` that the tests run. Also run on 5 public Loghub logs and 2 public EVTX files. A log with no time in it is analyzed but reported as ANALYSIS INCOMPLETE, because time-window rules cannot apply. |
| Content and encoding checks, column profile, per-record rejection with reasons | Working |
| Source identification: flows, Windows, Linux, endpoint, application, firewall | Working |
| IOA rule engine: 18 configurable rules, mapped to MITRE ATT&CK. One treats another tool's alert as a lead, and it stays suspicious until a rule of ours supports it. | Working |
| IOC matching against a local threat intelligence database | Working. The bundled feed is synthetic. |
| Threat intelligence feed upload, in CSV or JSON, with a read-only retro-hunt of stored events | Working. Tested with a public feed of 1,003 indicators. |
| NARS assistant, local mode: answers built directly from stored data, with no language model | Working |
| NARS assistant, AI mode with Groq: the model chooses read-only lookups and writes the answer | Working, and tested live. A free key allows 8,000 tokens a minute, so rapid questions can fall back to local answers, which NARS says when it happens. |
| NARS assistant, AI mode with Claude | Built, and tested with the real SDK against a local stand-in API. **Not run against the live API, because no key was available.** |
| Threat parameters: what makes logs a threat, measured for any single log | Working |
| Simulation impact: assets before and after, normal against attack logs, limits crossed | Working. Asset states are inferred from detections, not measured. |
| Live data flow: log type, verdict and outcome, with one moving dot per real log | Working |
| Landing page, from live data | Working |
| Alert emails over SMTP for high-risk incidents | Working, and sent through Gmail with a real account. The subject says when an incident comes from a simulation or a log file. |
| Attack graph for each incident, from its evidence events | Working |
| ATT&CK coverage page: techniques, alerts, scenario tests and gaps | Working |
| Optional user accounts with analyst and viewer roles | Working. Off until an account is created. |
| UEBA: new login source, unusual outbound volume, unusual login time | Working. Needs history for each entity. |
| Anomaly model: Isolation Forest over activity windows | Working, and measured on held-out synthetic data. Signals only. |
| Supervised network model on CIC-IDS2017 flow data | Runs, on compatible data only. **Not validated: no accuracy is claimed.** |
| Correlation into incidents, without merging unrelated activity | Working |
| Separate severity, confidence and risk, each with its reasons | Working |
| Risk-based response: high and critical risk wait for SOC approval. At medium and low risk, safe steps run on their own, and disruptive actions are held and go to the SOC if the risk rises. | Working. All execution is simulated. |
| Analyst approval, with simulated execution and verification | Working |
| Verdicts, including NO THREATS DETECTED and ANALYSIS INCOMPLETE | Working |
| Engine execution recorded for each analyzed log | Working |
| Reports in PDF, JSON, Markdown and CSV | Working |
| Append-only audit log | Working |
| Simulation Lab with start, pause, resume and stop | Working |
| Seeded dataset generator, with ground truth kept apart | Working |
| Metrics against ground truth at event, alert, incident and model level | Working |
| Testing on real CIC-IDS2017 files | **Not done.** Only synthetic flows in that layout have been run. |
| SHAP explanations | **Removed.** They explained a misuse of the model. Findings explain themselves from their evidence. |
| Learning from analyst true or false positive feedback | **Not implemented** |
| Solution Portal in the Simulation Lab: every threat, how it is detected, its fix steps, response actions, who decides and real commands, read from the rules and playbook in force | Working |
| Real commands for every response action, filled in from the incident, with undo commands where one exists | Working. An analyst reads and runs them. A value from a log that is not safe in a command gets no command. |
| Real response: a Windows Firewall block on this machine, after an analyst approves it, with undo | Built, and **off by default**. It needs `ALLSAFE_REAL_RESPONSE=1` and administrator rights, and never applies to uploaded logs. Tested against a stand-in for the firewall command. `scripts/check_real_block.py` runs it against the real firewall. |
| Stopping processes or changing accounts from ALLSAFE | **Not implemented, by design.** They are shown as commands instead. |
| TLS and a production web server | **Not implemented.** Keep it bound to localhost, even with accounts on. |

## NARS

Select **Ask NARS** on any page, on an incident, or on a dataset result. Selecting a node in an attack graph asks about that host, user or address.

- **Local mode** is the default. It matches the question to a read-only lookup and builds the answer directly from the result. There is no language model, and nothing leaves the machine.
- **AI mode** turns on when `GROQ_API_KEY` is set in `.env`, or `ANTHROPIC_API_KEY` with `pip install -r requirements-claude.txt`. The model chooses the same read-only lookups and writes the answer, and **the stored data it reads is sent to that service**, so check its answers against the sources it lists. If a call fails, NARS answers in local mode and says so. `NARS_MODE=local` keeps it local even with a key.

NARS has no tool that changes anything, so text in a log that tries to instruct it has nothing to act with. Answers are shown as text only, list what was read, and link only to items that lookups returned. Every question goes in the audit log.

## What makes a log a threat

One log is rarely a threat by itself. Logs become a threat when they meet a rule's parameters: which logs count, how they are grouped, what is measured, the limit and the time window. The **Threat Parameters** page lists them all, and selecting any log in the **Live Stream** measures them for that log.

| Class | Meaning |
| :--- | :--- |
| Normal | Matches no rule's pattern and supports no detection. This does not prove it is harmless. |
| Suspicious | Has a rule's pattern below its limit, or supports a weak detection, or only a behavioral or model signal. |
| Threat | Supports an IOA rule or IOC match with confidence of at least 70%, and severity of MEDIUM or higher. |

After a **Simulation Lab** run, **What the threat did to this simulated environment** shows each asset before and after, how far normal and attack logs reached against each limit, how the logs changed, and how long detection took. Asset states come from `config/impact_model.json`, which records the team's judgement of what each detection implies.

## Alert emails

Set the `ALLSAFE_SMTP_*` and `ALLSAFE_ALERT_EMAIL_*` settings in `.env` (see `.env.example`) and restart. Incidents at the minimum risk or above are then emailed once per risk level, up to the hourly limit. Simulated incidents say so in the subject. For Gmail, use an app password. **More > Risk Settings** shows the status and recent results, and can send a test email.

## User accounts

Accounts are off by default, and analyst actions are then accepted only from this machine. Creating the first account turns on login for every page and API:

```bash
python scripts/manage_users.py add alice --role analyst   # can decide, run and change
python scripts/manage_users.py add vera --role viewer     # can read and ask NARS
```

Anyone can also register on the login page. The first account can be an analyst, and later sign-ups are viewers unless an analyst creates them. An existing name cannot be registered again. Analyst names in the audit log then come from the account, not from the box on the page. Failed logins lock for 5 minutes after 5 attempts. Set `ALLSAFE_SECRET_KEY` so that sessions survive a restart.

## Tests

```bash
python -m unittest discover -s tests -t .   # unit and API tests
python tests/e2e_pipeline.py                # the whole pipeline against a real server
node tests/e2e_browser.mjs                  # the dashboard in headless Edge or Chrome
python scripts/reproduce_demo.py            # the demonstration, with checks
```

All of them use temporary databases and never touch your data. The pipeline test starts one harmless real PowerShell process on Windows, to check the live endpoint collector.

## Configuration

Settings are optional environment variables, listed in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#setup). Detection rules are in `config/detection_rules.json`, behavioral rules in `config/ueba_rules.json`, model rules in `config/ml_rules.json`, scoring and correlation settings in `config/risk_scoring.json`, and recommended responses and the risk policy in `config/response_playbook.json`. Changes to these files take effect on restart. Risk weights and levels can also be changed under **More > Risk Settings**.

## API

| Method and path | Purpose |
| :--- | :--- |
| `GET /api/stats`, `GET /api/health` | Dashboard counters; what is actually running |
| `GET /api/overview?minutes=` | Chart data for a time range |
| `GET /api/logs?limit=&source=&event_type=&origin=&q=&detected=&exclude_system=&before_id=` | Search events |
| `GET /api/logs/<id>`, `GET /api/logs/facets` | One event with its original record; filter options |
| `GET /api/alerts?limit=&severity=&rule_id=&detection_type=&q=`, `GET /api/alerts/<id>` | Detections; one with its supporting events |
| `GET /api/incidents?limit=&status=&severity=&risk=&q=&sort=`, `GET /api/incidents/<id>` | Incidents; full investigation detail |
| `GET /api/incidents/<id>/report?format=pdf` | One incident's report, as Markdown by default |
| `POST /api/incidents/<id>/status` | Set ACTIVE, INVESTIGATING or RESOLVED (`status`, `analyst`, optional `reason`) |
| `GET /api/incidents/<id>/response-actions`, `GET /api/response-actions?status=` | Recommended actions; the approval queue |
| `POST /api/response-actions/<id>/decision` | Approve, reject, modify or mark for investigation (`decision`, `analyst`, optional `reason`, `target`) |
| `POST /api/response-actions/<id>/execute` | Run an approved action in simulation (`analyst`) |
| `GET /api/simulate`, `POST /api/simulate/<scenario>` | List scenarios and results; run one straight away |
| `GET /api/simulations`, `POST /api/simulations` | Runs; start one in the background (`scenario`, optional `intensity`, `speed`, `background_events`, `seed`) |
| `GET /api/simulations/<id>`, `POST /api/simulations/<id>/stop\|pause\|resume` | A run's status and results; control it |
| `GET /api/simulations/<id>/events`, `GET /api/simulations/<id>/alerts` | What it generated and triggered |
| `GET /api/datasets`, `GET /api/datasets/<id>`, `GET /api/datasets/<id>/events` | Datasets; one analysis in full; its events |
| `POST /api/datasets/validate` | Check a file and store nothing (`file`, optional `source`, `mapping`) |
| `POST /api/datasets/upload` | Validate and analyze a file (also `reanalyze=1`). A threat intelligence feed is imported, and stored events are searched for it. |
| `POST /api/datasets/generate` | Generate and analyze a dataset (`profile`, `count`, `duration_seconds`, optional `seed`) |
| `GET /api/reports`, `POST /api/reports`, `GET /api/reports/<id>?format=json\|pdf\|md\|csv` | List, generate and download reports |
| `GET /api/risk`, `PUT /api/risk/settings` | Scoring settings and response policy; change them |
| `GET /api/ml` | The two models, what they accept, and how they were measured |
| `GET /api/notifications`, `POST /api/notifications/read` | Analyst notifications |
| `GET /api/audit?limit=&incident_id=&actor=&action=` | The audit log |
| `GET /api/rules` | Rules in force, with their activity |
| `GET /api/iocs`, `POST /api/iocs` | List or import threat intelligence |
| `GET /api/iocs/feeds`, `DELETE /api/iocs/feeds/<source>` | Feeds loaded; remove an imported one (`analyst`) |
| `GET /api/iocs/feeds/<source>/analysis`, `POST /api/iocs/feeds/<source>/test` | What a feed contains; plant its indicators in synthetic logs and run the pipeline (optional `count`, `contacts`, `seed`) |
| `GET /api/nars/status`, `POST /api/nars/ask` | The assistant's mode; ask it a question (`question`, optional `context`, `history`, `analyst`) |
| `GET /api/attack-matrix` | Rules on the ATT&CK tactics, with alerts and scenario tests |
| `GET /api/threat-parameters`, `GET /api/logs/<id>/verdict` | Everything that decides what is a threat; those parameters measured for one log |
| `GET /api/simulations/<id>/impact`, `GET /api/datasets/<id>/impact` | What the threat did to the simulated environment |
| `GET /api/flow?minutes=&origin=` | Log counts by log type, verdict and outcome, for the live flow |
| `GET /api/email/status`, `POST /api/email/test` | Alert email status; send a test (`analyst`) |
| `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me` | Sign in and out, when accounts are on |
| `POST /api/ingest/upload`, `POST /api/ingest/events` | Direct ingestion, without a dataset job |
| `POST /api/block`, `GET /api/blocklist` | Record an IP on the blocklist. **This changes no firewall.** Not used by the dashboard. |
| `POST /api/ticket` | Log an escalation. **No external ticket is created.** Not used by the dashboard. |

## License

Developed for **Hack4Hire 2026**. Distributed under the MIT License.
