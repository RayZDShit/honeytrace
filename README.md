# HoneyTrace Deception Intelligence

HoneyTrace is a self-built SSH honeypot, behavioral analysis pipeline, and analyst console. AsyncSSH implements SSHv2 transport; HoneyTrace implements decoy authentication, a virtual terminal, telemetry capture, classification, and incident investigation. Cowrie remains a comparison baseline and optional historical data source; no Cowrie service is required.

The sensor supports real encrypted SSH connections and a simulated terminal. It never executes received commands on the host, accesses host files from the terminal, forwards connections, or transfers files.

The operational path is SSH client → AsyncSSH sensor → event queue → SQLite → behavior features/rules/saved model → live dashboard and incidents. The existing architecture image predates the operational upgrades; this description is authoritative.

## Quick start

Create an isolated environment and install the dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python manage.py init
python manage.py analyst --username admin
```

Start the dashboard and contained sensor in separate terminals:

```powershell
python manage.py dashboard
python manage.py honeypot
```

Then open `http://127.0.0.1:5000` and sign in using the analyst account you just created. Choose your own password of at least 12 characters. Press `Ctrl+C` in each PowerShell window to stop the services.

High and critical incidents create persistent dashboard alerts. Alerts are grouped by incident instead of being emitted for every event, and analysts can acknowledge them from the alert drawer. Optional Discord webhook delivery is described in [the operator guide](docs/OPERATIONS.md); it is disabled unless you configure it locally.

On the existing school computer you can use `.\.python\python.exe` instead of `python`; install the updated requirements with that interpreter first. Your existing database and saved model are reused. You do not need to train the model again when reopening the project.

See [the operator guide](docs/OPERATIONS.md) for the complete upgrade, daily startup, incident workflow, and troubleshooting steps.

The repository intentionally excludes Cowrie archives, the generated database, credential-key material, virtual environments, and trained model artifacts. Supply your own authorized Cowrie JSON/ZIP data and run:

```powershell
python manage.py all --path "C:\path\to\authorized-cowrie-logs.zip"
```

### Reference evaluation

The following results were produced locally from an authorized Cowrie archive that is **not included** in this repository:

- 83 Cowrie JSON members imported from 10 sensors
- 3,308,028 unique normalized events
- 47,855 cross-connection behavioral sessions
- 13,429 unique source addresses
- Selected model: Extra Trees
- Training sessions: 22,137
- Protected attacker-group holdout: 5,534
- Balanced accuracy against pseudo-labels: 99.44%
- Macro-F1 against pseudo-labels: 99.68%
- Stored model version: `20260901T180127Z`

The accuracy limitations described below still apply.

## What the project demonstrates

- Streaming import from a Cowrie log directory, one JSON file, or a ZIP archive
- Repeat-safe event deduplication and import provenance
- Privacy-aware credential handling: fingerprints and masked previews, not reusable plaintext
- Cross-connection behavioral session grouping by source and time gap
- Features covering login timing, credential diversity, command behavior, downloads, client versions, and HASSH fingerprints
- Auditable labels for scanning, password spraying, credential stuffing, brute force, dictionary attacks, successful login, reconnaissance, post-exploitation, malware delivery, cryptomining, and botnet activity
- Group-isolated model evaluation so one source identity cannot appear in both training and holdout sets
- Accuracy, balanced accuracy, macro-F1, per-class metrics, confusion matrix, and feature importance
- A near-real-time monitoring view with incremental event and detection updates every two seconds
- Pause/resume controls, visible stream health, five-minute activity counters, and complete source addresses for investigation
- A custom SSHv2 sensor with a contained virtual terminal and bounded connections
- Sensor heartbeats, active connection list, analysis backlog, and a local Chart.js activity chart
- Analyst login, CSRF protection, grouped incidents, persistent high/critical alerts, investigation notes and CSV evidence export
- Optional Discord webhook notifications with masked source addresses by default

## Important accuracy statement

The Cowrie archive does not contain independently reviewed ground-truth attack labels. `labeling.py` therefore creates documented **pseudo-labels** from observable behavior. The model's reported score measures agreement with those labels on held-out attacker groups. It must not be described as independently verified real-world attack accuracy.

This is still a useful project result: it demonstrates a reproducible behavioral-classification pipeline, prevents identity leakage during evaluation, and clearly states the limits of the evidence.

## Project structure

| File | Function |
|---|---|
| `manage.py` | One command-line entry point for the full project |
| `import_cowrie.py` | Streams ZIP/directory logs and records import provenance |
| `ingest.py` | Normalizes and deduplicates events |
| `sessionizer.py` | Groups related connections into timed behavioral sessions |
| `feature_engineering.py` | Produces session-level numeric features |
| `labeling.py` | Assigns transparent rule labels and threat levels |
| `model_service.py` | Selects, trains, evaluates, saves, and applies the model |
| `ssh_honeypot.py`, `virtual_shell.py` | Real SSH transport and contained virtual terminal |
| `app.py`, `live_api.py` | Protected dashboard and incremental telemetry API |
| `operations.py` | Analyst authentication, sensor health and incident workflow |
| `templates/`, `static/` | Dashboard interface |
| `tests/` | Core labeling, feature, privacy, and ingestion tests |

## Step-by-step setup on Windows

Open PowerShell and move into the project:

```powershell
cd C:\School\NISec
```

### 1. Confirm Python

Use Python 3.12 or later (this release was tested with Python 3.14):

```powershell
python --version
```

If `python` is not recognized, install a current 64-bit Python release from the official Python website and enable the installer option that adds Python to your user path. Close and reopen PowerShell afterward.

### 2. Create an isolated environment

```powershell
python -m venv .venv
```

You may activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

If activation is restricted on the computer, activation is optional. Replace `python` in the remaining commands with:

```powershell
.\.venv\Scripts\python.exe
```

### 3. Install project packages

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Run the tests

```powershell
python -m unittest discover -s tests -v
```

### 5. Initialize the database

```powershell
python manage.py init
```

The private working database is created at `instance\nisec.db`. The credential fingerprint key is created when the first credential event is imported.

Create your dashboard account with `python manage.py analyst --username admin` and choose a password of at least 12 characters.

## Importing the Cowrie logs

The default data path is:

```text
C:\School\NISec\archive.zip
```

The importer also accepts an extracted directory or a single Cowrie JSON file.

### 6. Optional small validation import

This confirms that the archive and parser work without processing the full dataset:

```powershell
python manage.py import --path "C:\School\NISec\archive.zip" --max-files 2 --max-lines-per-file 5000
python manage.py sessions
python manage.py status
```

Files limited by `--max-lines-per-file` are marked `partial`, so the later full import will revisit them safely. Previously inserted events will be recognized as duplicates.

### 7. Perform the full import

```powershell
python manage.py import --path "C:\School\NISec\archive.zip"
```

The importer prints progress for each Cowrie file. It can require substantial time and disk space for a large archive. Completed files are skipped if the command is run again, and individual duplicate events are protected by a unique event fingerprint.

### 8. Build behavioral sessions

```powershell
python manage.py sessions
```

The default session gap is 120 seconds. Connections from the same source and sensor belong to one behavioral burst until no event is observed for more than two minutes. To evaluate a different gap:

```powershell
python manage.py sessions --gap 180
```

Rebuilding sessions does not re-import or duplicate the raw normalized events.

### 9. Train and evaluate the model

```powershell
python manage.py train
```

Training performs these operations:

1. Removes `unknown` sessions and categories without enough examples.
2. Caps very large categories so one class does not dominate computation.
3. Keeps all sessions from the same sensor/source identity in one evaluation group.
4. Compares Extra Trees and Random Forest using macro-F1 on grouped cross-validation.
5. Evaluates the selected model once on a protected grouped holdout.
6. Saves the classifier to `model\behavior_model.joblib`.
7. Stores metrics and feature importance in SQLite.
8. Applies predictions and confidence values only to supported, pseudo-labeled behavior. Unknown/out-of-distribution sessions remain unscored.

The terminal prints the balanced accuracy and macro-F1. The dashboard presents the full evaluation and its limitations.

### One-command full build

After packages are installed, steps 5–9 can be run together:

```powershell
python manage.py all --path "C:\School\NISec\archive.zip"
```

## Running and using the dashboard

### 10. Start the dashboard

```powershell
python manage.py dashboard
```

Open this local address in a browser:

```text
http://127.0.0.1:5000
```

The dashboard binds only to the local computer by default and uses Waitress rather than Flask debug mode.

Dashboard sections:

- **Overview:** totals, behavior distribution, threat distribution, and recent telemetry
- **Live monitor:** two-second event updates, automatic classified detections, stream health, five-minute counters, and pause/resume controls
- **Sessions:** filters and drill-down into grouped behavioral evidence
- **Incidents:** grouped high-risk detections, investigation status, analyst notes, and CSV evidence
- **Detection analytics:** balanced accuracy, macro-F1, confusion matrix, per-class results, and feature importance

Sensor health and active connections are shown in Live monitor. Historical import management remains available through `manage.py`; import and source records are retained in the database and protected APIs.

The Live monitor is the primary operational view. The sensor records and analyzes batches during active connections, then applies the saved model if available. Session revisions refresh existing detection cards as behavior changes. Pausing the view stops only on-screen updates, not collection. The Overview refreshes every 15 seconds. Complete source addresses are shown by default so an analyst can correlate evidence. Set `NISEC_MASK_IPS=true` before starting the dashboard to mask them on shared screens.

## Running the contained sensor

In a separate PowerShell window with the same environment:

```powershell
cd C:\School\NISec
.\.python\python.exe manage.py honeypot
```

It listens only on `127.0.0.1:2222` by default. Decoy authentication leads to an in-memory virtual terminal, never the host shell. Its normalized events use the same database, session rules, model, and dashboard as optional imported Cowrie data. See the operator guide for configuration and containment limits.

This guide intentionally stops at operating the sensor. Controlled testing traffic and attacker-side instructions should be documented separately and used only inside the isolated lab.

## Routine commands

```powershell
python manage.py status
python manage.py sessions
python manage.py train
python manage.py apply-model
python manage.py dashboard
```

- `status` reports database, event, session, import, and model state.
- `sessions` rebuilds behavioral bursts after changing the time-gap design.
- `train` creates a new evaluated model version.
- `apply-model` reapplies the existing saved model without retraining.
- `sanitize` removes secret-bearing text duplicated by legacy Cowrie login messages.
- `dashboard` starts the analyst interface.

## Safe operating limits

- Keep the custom sensor in a host-only isolated lab.
- Do not bind the dashboard to a public or student-shared interface.
- Do not use real credentials during demonstrations.
- Do not describe masked imported credentials as verified attacker identities.
- Keep the model disclaimer in presentations and reports.
- Treat any downloaded Cowrie artifacts as potentially malicious; this project analyzes metadata and does not execute them.

## License

HoneyTrace is available under the [MIT License](LICENSE).

## Troubleshooting

### `python` is not recognized

Install Python 3.12+ from the official Python distribution, reopen PowerShell, and run `python --version` again.

### Training says there are not enough supported labels

Finish the full import and rebuild sessions first. A small validation import may not contain enough attacker groups for honest grouped evaluation.

### The dashboard says no model is available

Run:

```powershell
python manage.py train
```

### An interrupted import is restarted

Run the same import command again. Completed source files are skipped; partial files are reread, and previously inserted events are deduplicated.

### Dashboard values do not include recently imported data

After import, rebuild behavioral sessions and apply or retrain the model:

```powershell
python manage.py sessions
python manage.py train
```
