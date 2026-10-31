# Demonstration Procedure

About 14 minutes. All data is synthetic, and no response action touches a real system.

## Prepare

Start with a clean database, so that every number on screen comes from this demonstration.

```powershell
$env:ALLSAFE_DB_PATH = "data\judges_demo.db"; $env:ALLSAFE_PORT = "5001"; python app.py
```

Open `http://127.0.0.1:5001` and type a name in the **Analyst** box. It goes in the audit log.

To keep the live stream moving during the talk, run this in a second window. It runs synthetic scenarios through the real API.

```powershell
python scripts/demo_feed.py --port 5001
```

To prove the pipeline without the dashboard, run `python scripts/reproduce_demo.py`. It runs everything below with checks, and prints the results. A saved copy is in `docs/sample_reports/RUN_SUMMARY.txt`.

## Start here: what the judges asked (3 minutes)

**"What happens when the simulation data is affected by the threat?"**

1. Open **Simulation Lab**, set **Speed** to `fast`, and click **Run** on **Multi-Stage Attack**.
2. Open **What the threat did to this simulated environment**. Show the assets going from **Normal** to **Compromised** or **Data lost**, the 90 MB sent out, and **How the logs changed**.
3. Run **Benign Activity**. It reports that no asset was affected.

**"On what parameters do you define a log as a threat?"**

1. In the same panel, show **Why these logs count as a threat**: normal logs reached 0.1 MB, attack logs reached 90 MB, and the limit is 50 MB.
2. Open **Threat Parameters**. Show the three classes, and each rule's logs, grouping, measure, limit and window.
3. Open **Live Stream** and select a log. It shows the verdict, what was measured against the limit, and each field checked.

**Say:** "One log is rarely a threat. Five failed logins from one address in five minutes is. Every limit is on this page, and you can check any log against it."

Then show **Live data flow** at the top of the stream. Each moving dot is a real log arriving. When no logs arrive, nothing moves.

## 1. A multi-stage attack (2 minutes)

1. Open **Simulation Lab**. Set **Speed** to `normal` so that progress is visible.
2. Click **Run** on **Multi-Stage Attack**. Point out the progress bar, and the **Pause** and **Stop** controls. A second start is refused while this one runs.
3. When it finishes, show the results: 44 events, 11 alerts, 1 incident, no rule missed, none unexpected. Point out that 19 of those events are normal history, so behavioral baselines have something to compare with.
4. Click **Investigate**. Show the attack progression across tactics, the timeline and which rule fired at each stage, and **How this was scored**, with each factor's points and reason.

**Say:** "These events went through the same ingestion and detection code as real logs. The simulator inserts no alerts."

## 2. Response: the SOC decides the big ones, and small risks are automatic (2 minutes)

1. In the critical incident, scroll to **Recommended response**. Every action waits for the SOC. Point out **Expected impact** and the **Disruptive** tag.
2. Approve **Block test IP**, then click **Run in simulation**. The result says no real system was changed.
3. In **Simulation Lab**, run **Suspicious Process Execution**, which is medium risk. Open **Response** and set **Show** to **Handled automatically**: the safe steps already ran, with nobody deciding. Set it to **Held at small risk**: the process termination did not run, because it is disruptive.
4. Open **More > Audit Log** and show the approval, the execution and the automatic steps.

**Say:** "The highest risks need the SOC's approval. Small risks are handled automatically, but automation only does safe things, like evidence collection. Anything disruptive waits for a person, and even then it is simulated."

## 3. A log file with a threat in it (2 minutes)

1. Open **Log Analysis**. Drop `data/samples/brute_force_windows.csv` on the page and click **Analyze log**. To show that any log type works, also try `data/samples/formats/zeek_conn.log` or `aws_cloudtrail.json`.
2. Show **THREATS DETECTED**, and that the log type was identified as Windows authentication events without being told.
3. Show **Detection engine status**: which engines ran on how many events. The network model is skipped, with the reason.
4. Click a row in **IOA rule matches**. The drawer shows why it fired and its supporting events. Click an event to see the original Windows record beside the normalized fields.
5. Download the **PDF** report.

**Say:** "Windows logs are never fed to the network model. It needs 78 flow features, and guessing them would make its answer meaningless."

## 4. A clean log, and an honest failure (1 minute)

1. Upload `data/samples/clean_activity.csv`. Show **NO THREATS DETECTED**, the statement beneath it, and that a report is still produced.
2. Upload `data/samples/malformed_records.csv`. Five bad rows are listed with their reasons, and the six good ones are still analyzed.

**Say:** "A clean result never claims the environment is safe. And if an engine fails, the result is ANALYSIS INCOMPLETE, never a clean report."

To show that failure live, start the server with `$env:ALLSAFE_LOAD_ML = "0"` and upload `data/samples/network_flows_cicids.csv`. No engine can read those flows, so it shows **ANALYSIS INCOMPLETE**.

## 5. The models, and what they can claim (1 minute)

1. Upload `data/samples/network_flows_cicids.csv` with the model on. Show the classes it predicted, and that no confidence is displayed.
2. Open **Threat Parameters**, then **Machine learning models**. Show the anomaly model's false alarm rate and recall, measured on data it did not train on, and that the network model claims no accuracy.
3. If asked, show the scoring settings and the response policy under **More > Risk Settings**.

**Say:** "Those flow values are random, so that upload shows only that the model runs on compatible data. We claim no accuracy we have not measured."

## 6. Normal activity stays quiet (30 seconds)

In **Simulation Lab**, run **Benign Activity**. Its events resemble attacks: a mistyped password, large internal transfers, `sudo apt update`. Nothing fires.

## 7. NARS, the attack graph and ATT&CK coverage (2 minutes)

1. Open the Multi-Stage Attack incident and click **Ask NARS**. Show that it explains the incident from stored data, and lists what it read under the answer.
2. In **Attack graph**, select the attacker's IP. NARS answers about that address.
3. Type `Approve all pending actions`. It refuses, because it has no tool that can.
4. Open **More > ATT&CK Coverage**. Show the techniques covered, which ones a scenario tests, and the tactics marked **No rule**.

**Say:** "NARS can only read. Every fact comes from a lookup, and you can see which one. We show the gaps on purpose, so you can see what is not covered."

## 8. A public threat intelligence feed (1 minute)

1. In **Log Analysis**, add `data/samples/threat_feed.csv`, or a public IOC feed in CSV with `type` and `value` columns. It is recognised as a feed, not a log.
2. Show what was left out and why: an internal address and an unsupported type.
3. Show **What this feed contains**: types, what the feed claims they are, sources and dates. Then the retro-hunt of stored events, which creates no alerts. Zero matches is expected on synthetic data.
4. Click **Test this feed**. It plants a sample of the indicators in synthetic logs, and the pipeline gives a verdict, incidents and a report.
5. In **More > Threat Intelligence**, show the feed, and remove it.

## The Solution Portal (1 minute)

1. After any run in **Simulation Lab**, scroll to **Recommended solution** for that run, then to **Solution Portal**. The run's threats come first.
2. Open a threat and show how it is detected, how to fix it, who decides, and the real commands.
3. Click **Solution** on any scenario card, or search for a threat such as `password spraying`.

**Say:** "Every threat comes with its solution, read from the same rules and playbook the system runs on, so this page cannot drift from what the system does."

## Optional: a real firewall block (1 minute)

Stop the server, then start it from an Administrator terminal with real mode on. Check it first with `python scripts/check_real_block.py`, which blocks a documentation address, reads the rule back and removes it.

```powershell
$env:ALLSAFE_REAL_RESPONSE = "1"; python app.py
```

1. Run **Multi-Stage Attack**, open its incident, and approve **Block test IP** for `203.0.113.50`. This address is reserved for documentation, so blocking it affects nothing.
2. Click **Block for real**. The result says Windows Firewall now blocks it, and the rule was read back.
3. Open **Windows Defender Firewall with Advanced Security** and show the rule `ALLSAFE-block-203.0.113.50`.
4. Click **Undo: remove the firewall rule**, and show that it has gone.

**Say:** "A person approved this, and it changed the real firewall on this machine, and it can be undone. Automation can never do this. Stopping processes and changing accounts stay as commands an analyst runs by hand, because those are harder to undo."

## If a judge asks

| Question | Honest answer |
| :--- | :--- |
| Is it production ready? | No. `docs/ARCHITECTURE.md` lists what it would still need, starting with TLS and a production web server. |
| Is NARS an AI? | With a key, yes: a model on Groq chooses read-only lookups and writes the answer, and the data it reads goes to Groq. Without a key, it matches question patterns and reads the database. The panel always says which mode is on. |
| Where do the limits come from? | The team chose them as starting values, in `config/detection_rules.json`. They have not been tuned on real traffic. |
| How accurate is it? | On our own synthetic scenarios, it finds what it should with no false alerts. Those were written by the same team as the rules, so that shows it works as designed, not how it would do on real attacks. |
| How accurate is the ML? | The anomaly model is measured on held-out synthetic data, and the numbers are on the Threat Parameters page. The saved network model has not been validated here, and it shows no accuracy or confidence. |
| Does it respond to threats? | It recommends, and by default acts only in simulation. Each action also shows the real commands to run by hand, and optional real mode can add a real firewall block after approval. High and critical risk wait for the SOC. At medium and low risk, safe steps such as evidence collection run automatically and are logged. Blocking, disabling an account and terminating a process never run on their own. |
| Does it catch zero-days? | We do not claim that. |
| Does it read encrypted traffic? | No. It sees metadata only. |
| Why did a step already run on a critical incident? | The attack started at medium risk, so a safe step ran automatically. When the risk rose, everything still open went to the SOC. Nothing disruptive runs on its own. |
| Can it read any log? | Any text log is stored and searched, and many formats are read by name or shape, including EVTX. What it can detect depends on what the log contains: a log with no addresses or users gives rules little to work with, and the result says so. |
