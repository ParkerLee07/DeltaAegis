# DeltaAegis

DeltaAegis is a self-hosted, delta-first network-state monitoring and investigation console powered by NetSniper telemetry.

It ingests finalized NetSniper scan bundles, stores normalized historical snapshots in SQLite, compares accepted scans over time, and turns network changes into analyst-friendly events, alerts, asset context, risk views, and dashboard workflows.

## Current Release — v0.39.0

**DeltaAegis v0.39.0 — Scan Job Lifecycle Observability**

DeltaAegis v0.39.0 adds persistent NetSniper scan-job lifecycle state from `QUEUED` through `RUNNING` to `COMPLETED`, `FAILED`, or `CANCELLED`. The worker records process IDs, heartbeats, bounded live stdout and stderr, terminal exit data, and cancellation evidence while retaining the existing fixed argument-vector execution boundary.

The dashboard adds read-only live job detail, active-job polling, and an authenticated cancellation workflow with a required reason and explicit confirmation. The browser never supplies a process ID or sends operating-system signals; the worker owns process-group termination and escalation.

Schedule deletion preserves every linked job and its original `schedule_id`. A deletion tombstone keeps the removed definition, linked-job status counts, and schedule history visible. Deleting a schedule does not cancel a queued or running job; cancellation remains a separate explicit action.

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
- NetSniper — telemetry status, guarded scan launch, live job detail, authenticated cancellation, schedules, preserved schedule history, and completed-run import.
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

DeltaAegis v0.39.0 does not expose arbitrary shell command execution from the dashboard.

Dashboard NetSniper execution uses guarded job records, validated private IPv4 CIDRs, and fixed argument-vector process creation. Live job-detail reads are bounded and confined to the configured scan-log root.

Cancellation is an authenticated `scan.start` action. The browser submits only the job identifier and reason; it does not supply a PID or send signals. The worker owns process-group termination and preserves cancellation metadata and log evidence.

Schedule deletion preserves linked scan jobs and does not imply cancellation. Operators must use the dedicated cancellation control to stop an active job.

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

Run the complete v0.39 release gate from a clean checkout:

```bash
./tools/validate_v0_39_release_gate.sh
```

The release gate validates lifecycle storage, live execution, read-only job detail, dashboard polling, HTTP execution, cancellation backend and API behavior, dashboard cancellation UX, non-destructive schedule deletion, release metadata, the branch-diff path audit, and v0.38 TrueAegis follow-up compatibility.

For the pre-commit release-hardening checkpoint only:

```bash
./tools/validate_v0_39_release_gate.sh --allow-dirty
```

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
- Run more than one active NetSniper scan job at a time.
- Treat schedule deletion as scan cancellation; cancellation remains a separate explicit action.
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
