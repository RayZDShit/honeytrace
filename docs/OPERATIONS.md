# HoneyTrace operator guide

## Upgrade this computer

Stop the old dashboard and sensor in their terminals with Ctrl+C. Open PowerShell:

```powershell
cd C:\School\NISec
.\.python\python.exe -m pip install -r requirements.txt
.\.python\python.exe manage.py init
.\.python\python.exe manage.py analyst --username admin
```

The analyst command prompts privately for a password and confirmation. It creates or resets that account. No default dashboard password exists. Resetting a password invalidates that user's existing sessions.

Schema additions preserve imported events, existing sessions, and trained model artifacts. Live updates now preserve session IDs. There is no need to import data or retrain to run the upgraded sensor.

## Start each day

Terminal 1:

```powershell
cd C:\School\NISec
.\.python\python.exe manage.py honeypot
```

Terminal 2:

```powershell
cd C:\School\NISec
.\.python\python.exe manage.py dashboard
```

Open http://127.0.0.1:5000 and sign in. Live monitor is the default page. Leave both terminals running. Ctrl+C stops each service.

On a new clone, use a Python virtual environment and replace .\.python\python.exe with that environment's python. Install requirements, initialize, and create an analyst before starting services. Without a saved model, classification uses the documented rules.

## Sensor behavior

The SSH service listens on 127.0.0.1:2222 by default. It implements real SSH transport. The decoy root login uses the lab value honeytrace-lab, configurable through HONEYTRACE_DECOY_PASSWORD. It is entirely separate from dashboard credentials.

The virtual terminal supports pwd, ls, cd, cat, whoami, id, hostname, uname and echo against a small in-memory filesystem. Other commands are recorded and return simulated errors. It does not execute subprocesses, fetch URLs, access real host files, provide SFTP/SCP, or forward traffic. This guide covers operation; attacker-side exercises are separate.

Defaults bound concurrent connections to 50, channels to four per connection, commands to 100 per channel, input to 256 bytes, authentication to 30 seconds, and a connection to five minutes. The telemetry queue holds at most 4,000 events. Collection and analysis happen in batches on a worker thread.

For a second lab computer, bind the sensor to your specific host-only/private interface using --host YOUR_LAB_IP. The dashboard can remain local while you project/share its screen. Remote dashboard access should use HTTPS and a restricted management interface. No network or firewall changes are made by installing this code.

## Live monitor

- Sensor online/offline comes from a heartbeat every three seconds. A heartbeat older than 15 seconds is offline. A connected dashboard alone does not imply an online sensor.
- The active connection list shows connections from sensors with a current heartbeat.
- Health displays the queue backlog, dropped-event count, and elapsed time of the last processing batch (not a promised end-to-end latency).
- Processing retries a failed batch three times. The dropped-event counter also counts exhausted batches conservatively: some raw events may already be stored even if analysis failed. The in-memory queue is not durable across a crash.
- Counters cover five minutes. The activity chart covers 15 minutes across sensors.
- Feed filters select sensor, time window, and detection severity. Severity filters detections; raw events have no independent threat label.
- Updates poll every two seconds and drain any backlog in bounded batches. The screen retains the latest 100 events and 60 detections; full evidence remains in the database.
- Session revisions update existing cards after classification or model scoring. Click a detection to inspect evidence.
- Pause freezes the view only. Collection continues. Resume catches up; changing filters refreshes the selected window.

## Incident workflow

1. Open Incidents. High/critical classifications from the live sensor create incidents automatically.
2. Repeated behavior within the same behavioral session updates one incident. A later session creates a separate incident.
3. Open an incident, inspect its session and evidence, and select Investigating.
4. Add an analyst note and save. Status changes and notes retain the analyst name and timestamp.
5. Download CSV evidence for reporting. The export contains incident metadata, up to 5,000 evidence events, and investigation history.
6. Mark the incident Resolved after review. New activity in that same session reopens it as New.

Historical imports do not automatically create a flood of incidents. Incidents arise from live analysis. Model confidence is an uncalibrated classifier score; it is not the probability that an attacker is malicious. The existing model was evaluated against rule-generated pseudo-labels.

## Troubleshooting and recovery

- Login required: create/reset your account with manage.py analyst. Never use the SSH decoy password for dashboard access.
- Offline sensor: start the sensor and check its terminal for bind errors. Verify that dashboard and sensor use the same configured database.
- Processing failure/backlog: inspect the sensor terminal. Events persisted before a model error remain available. Stop the sensor before a full offline rebuild with manage.py sessions followed by manage.py apply-model.
- Full rebuilds change session IDs; existing incident reports retain their metadata, but old session references may become stale. Use ordinary live processing for daily operation, not repeated full rebuilds.
- Training is needed only for intentional dataset/model changes. Model files are trusted local artifacts; do not load untrusted joblib files.
- Keep local backups of instance and model while services are stopped. These contain sensitive information and are excluded from GitHub.
- Updates missing after editing: restart the dashboard and hard-refresh the page.

## Verification

```powershell
.\.python\python.exe -m unittest discover -s tests -v
node --check static/dashboard.js
node --check static/operations.js
```

Integration tests use a temporary database and an ephemeral localhost SSH port. They verify actual SSH negotiation, virtual commands, denied forwarding/SFTP, stable session IDs, model revision visibility, authentication/CSRF, sensor outages, incident notes and CSV handling.
