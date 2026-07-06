# DeltaAegis

DeltaAegis is a self-hosted, delta-first network-state monitoring and investigation console powered by NetSniper telemetry.

It ingests finalized NetSniper scan bundles, stores normalized historical snapshots in SQLite, compares accepted scans over time, and turns network changes into analyst-friendly events, alerts, asset context, risk views, and dashboard workflows.

## Current Release — v0.38.0

**DeltaAegis v0.38.0 — TrueAegis Follow-Up Automation**

DeltaAegis v0.38.0 adds guarded TrueAegis validation as an optional follow-up to scheduled NetSniper scans. A schedule can enable `run_trueaegis_after_ingest` to request TrueAegis only after NetSniper completes, auto-ingest records structured evidence, the imported snapshot is verified as `ACCEPTED`, the manifest matches the persisted snapshot, no TrueAegis job is already active, and the configured TrueAegis executable is ready.

Scheduled follow-ups preserve provenance through the originating NetSniper scan job and schedule. Dashboard workers execute asynchronously through the existing guarded worker, while CLI `schedule-run-due` execution is synchronous so the process remains alive through validation, result import, and correlation refresh. The implementation uses fixed argument-vector execution and does not expose arbitrary shell command execution.

The v0.38 release was validated with an isolated real NetSniper scan and accepted ingest, followed by a controlled TrueAegis replay with 81 imported observations and 81 refreshed correlations. A later live dashboard-schedule acceptance test completed with 183 imported observations and 711 refreshed correlations.

## What DeltaAegis Does

DeltaAegis helps answer:

- What changed on the network since the last accepted scan?
- Which services opened or closed?
- Which assets are new, stable, missing, or no longer observed?
- Which alerts need review?
- Which assets have owner, role, criticality, notes, or investigation status?
- Which risks are explainable and worth prioritizing?
- Which NetSniper classifications are strong, weak, contradictory, or uncertain?
- Which NetSniper run is ready to import into the SIEM workflow?

## Architecture

NetSniper telemetry bundle → DeltaAegis ingest → SQLite snapshot history → Delta engine → Events, alerts, and asset context → Risk prioritization and investigation workflow → Dashboard, CLI, and Markdown reports.

NetSniper remains the lightweight scanner and telemetry producer. DeltaAegis is the dashboard, history store, delta engine, analyst workflow layer, and local SIEM-style console.

## Installation

Clone the repository:

```bash
git clone https://github.com/ParkerLee07/DeltaAegis.git
cd DeltaAegis
chmod +x install.sh
./install.sh
```

The installer creates local runtime directories:

```text
data/
events/
reports/
backups/
```

The default installed dashboard database is:

```text
data/deltaaegis.db
```

The installer also creates a local launcher:

```text
~/.local/bin/deltaaegis
```

Make sure `~/.local/bin` is in your shell `PATH`.

## First Login

Start the dashboard:

```bash
deltaaegis dashboard
```

Default URL:

```text
http://127.0.0.1:8090
```

On a fresh install, DeltaAegis redirects to the first-admin setup page. Create the first local ADMIN user there.

Dashboard login is required by default.

## Admin Password Reset

If you lose access to the dashboard, reset or create an ADMIN account:

```bash
python3 tools/reset_dashboard_admin.py
```

The reset helper defaults to the installed dashboard database:

```text
data/deltaaegis.db
```

You can also specify a database path:

```bash
python3 tools/reset_dashboard_admin.py \
  --db data/deltaaegis.db \
  --username admin
```

## Dashboard

Start the dashboard:

```bash
deltaaegis dashboard
```

Start on a specific host and port:

```bash
deltaaegis dashboard --host 127.0.0.1 --port 8090
```

Development-only unauthenticated mode:

```bash
deltaaegis dashboard --no-require-login
```

Do not use unauthenticated mode on exposed networks.

### Dashboard areas

- Overview — current SIEM summary, recent changes, and network state.
- Assets — current and historical asset inventory.
- Risk — explainable risk prioritization.
- Investigations — asset workflow and investigation status.
- Tickets — operator investigation workflow.
- Intelligence — NetSniper classification quality and device-intelligence context.
- Events — delta events from accepted scans.
- Alerts — analyst-facing alert review.
- NetSniper — telemetry status, guarded scan launch, schedules, job history, and completed-run import.
- Admin/User Management — local users, roles, and access controls.

## NetSniper Integration

DeltaAegis expects finalized NetSniper telemetry bundles under:

```text
~/NetSniper/runs/
```

The dashboard NetSniper tab reports:

- NetSniper root path.
- NetSniper script presence.
- Runs directory presence.
- Latest run.
- Latest manifest.
- Import readiness.
- Latest completed run status.

Override the NetSniper root when needed:

```bash
DELTAAEGIS_NETSNIPER_ROOT=/custom/NetSniper deltaaegis dashboard
```

Import the latest completed NetSniper run from the dashboard using the `/netsniper` tab, or use the CLI:

```bash
deltaaegis ingest --runs-dir ~/NetSniper/runs
```

## Security Boundary

DeltaAegis v0.38.0 does not expose arbitrary shell command execution from the dashboard.

Dashboard NetSniper scan controls use guarded job records and fixed argument-vector execution. Scan launch and schedule operations remain protected by the dashboard RBAC policy, and telemetry cleanup remains isolated behind the ADMIN-only `/operator/reset` maintenance page with explicit `DELETE TELEMETRY` confirmation.

The `/api/netsniper/import-latest` endpoint imports completed telemetry and is protected by the `workflow.write` permission. ANALYST and ADMIN users can perform workflow write actions.

Automatic TrueAegis execution from scheduled NetSniper scans is not enabled by default. Schedules with `run_trueaegis_after_ingest` enabled can launch one guarded TrueAegis validation job only after NetSniper completes, structured auto-ingest evidence is recorded, and the matching persisted snapshot is verified as `ACCEPTED`. Schedules without the flag continue to run NetSniper and optional auto-ingest without launching TrueAegis.

## Core CLI Commands

Show configured paths:

```bash
deltaaegis paths
```

Ingest NetSniper telemetry:

```bash
deltaaegis ingest --runs-dir ~/NetSniper/runs
```

Show system summary:

```bash
deltaaegis summary
```

List snapshots:

```bash
deltaaegis snapshots --limit 20
```

Show recent events:

```bash
deltaaegis events --limit 50
```

Show alerts:

```bash
deltaaegis alerts --status OPEN --limit 50
```

Show current risk register:

```bash
deltaaegis risk
```

Show asset detail:

```bash
deltaaegis asset 192.168.4.32
```

Show NetSniper intelligence summary:

```bash
deltaaegis intelligence
```

Generate a Markdown report:

```bash
deltaaegis report
```

## Local Data Layout

Default local runtime layout:

```text
DeltaAegis/
├── data/
│   └── deltaaegis.db
├── events/
│   └── events.jsonl
├── reports/
│   └── generated Markdown reports
├── backups/
│   └── local backup files
├── deltaaegis.py
├── install.sh
└── uninstall.sh
```

Runtime data is local and should not be committed to Git.

## Access Control

DeltaAegis supports local dashboard users and role-based permissions.

Typical roles:

- ADMIN — full dashboard and administrative access.
- ANALYST — investigation and workflow actions.
- VIEWER — read-only dashboard review.

API tokens remain available for automation through the `X-DeltaAegis-Token` header.

## Uninstall

Remove the installed launcher while keeping project files and runtime data:

```bash
./uninstall.sh
```

Remove runtime data directories:

```bash
./uninstall.sh --purge-runtime
```

Remove the entire project directory:

```bash
./uninstall.sh --purge-project --yes
```

Preview uninstall actions without deleting anything:

```bash
./uninstall.sh --dry-run
```

## Validation

Run the complete v0.38 release gate:

```bash
./tools/validate_v0_38_release.sh
```

The release gate chains the v0.38 schedule-intent, planning, queueing,
execution, ingest-provenance, execution-mode, and due-schedule regression
validators.

Basic syntax check:

```bash
python3 -m py_compile deltaaegis.py
```

## Scope and Limitations

DeltaAegis is a local network-state monitoring, investigation, reporting, and SIEM-style dashboard project.

It is not a replacement for a mature enterprise SIEM.

DeltaAegis does not currently:

- Ingest endpoint logs.
- Store full packet captures indefinitely.
- Perform machine-learning anomaly detection.
- Automatically discover business owners for assets.
- Execute raw shell commands from the dashboard.
- Stream NetSniper stdout and stderr live while a scan is still running; the current log files are populated after completion.
- Cancel an already-running scan automatically when its originating schedule is deleted.
- Replace manual analyst review.

Its conclusions are limited to NetSniper telemetry, stored historical snapshots, analyst annotations, investigation state, and local DeltaAegis database records.

## Authorized Use Only

Use DeltaAegis only on networks and systems for which you have explicit authorization.

DeltaAegis is intended for defensive monitoring, lab validation, internship research, and authorized security assessment workflows.

## Related Projects

DeltaAegis works as the orchestration and historical-analysis layer of a
three-project defensive workflow:

- **NetSniper** discovers hosts, collects service evidence, classifies devices,
  and produces versioned telemetry bundles.
- **TrueAegis** performs safe validation, enrichment, and attack-surface
  correlation against accepted NetSniper evidence.
- **DeltaAegis** schedules and ingests NetSniper runs, tracks network changes,
  launches guarded TrueAegis follow-ups, and supports investigation and
  reporting workflows.

## License

MIT License. See `LICENSE`.
