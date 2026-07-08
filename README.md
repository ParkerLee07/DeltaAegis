# DeltaAegis

DeltaAegis is a self-hosted, delta-first network-state monitoring and investigation console powered by NetSniper telemetry.

It ingests finalized NetSniper scan bundles, stores normalized historical snapshots in SQLite, compares accepted scans over time, and turns network changes into analyst-friendly events, alerts, asset context, risk views, and dashboard workflows.

## Current Release — v0.41.0

**DeltaAegis v0.41.0 — Data Durability & Recovery**

DeltaAegis v0.41.0 adds a guarded lifecycle for the local SQLite evidence store. Operators can create SQLite-consistent backups, publish checksum and schema manifests, catalog and verify backup bundles, rehearse restores into a non-active database, preview retention decisions, and delete only freshly verified retention-eligible bundles.

Active restore is deliberately split into planning and execution. The preview verifies the selected backup, detects running DeltaAegis dashboard processes, blocks on SQLite WAL/SHM/journal files, checks active and backup file identities, and requires an existing writable safety-backup directory. Execution requires the exact preview digest and confirmation phrase, creates a fresh verified pre-restore safety backup, restores into a temporary database, atomically replaces the active database, verifies the result, and automatically rolls back when post-cutover verification fails.

The default active database remains `data/deltaaegis.db`. An ignored root-level `deltaaegis.db` is treated as legacy local state and is never selected automatically. Use `--db` explicitly when operating on any non-default database.

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

## Data Durability and Recovery

The default active database is:

```text
data/deltaaegis.db
```

Create a SQLite-consistent backup and manifest:

```bash
deltaaegis backup
```

Inspect all top-level backup bundles:

```bash
deltaaegis backup-catalog
```

Verify a specific bundle:

```bash
deltaaegis backup-verify backups/example.db
```

Rehearse a restore without modifying the active database:

```bash
deltaaegis restore-rehearsal backups/example.db
```

Preview retention decisions:

```bash
deltaaegis backup-retention-preview   --keep-newest 5   --minimum-age-days 30
```

Retention execution deletes only bundles that are still verified and eligible when execution begins:

```bash
deltaaegis backup-retention-execute   --keep-newest 5   --minimum-age-days 30   --confirmation "DELETE ELIGIBLE BACKUP BUNDLES"
```

Preview an active restore cutover:

```bash
deltaaegis restore-cutover-preview backups/example.db --json
```

The preview returns a SHA-256 plan digest. After reviewing a blocker-free plan, execute with that exact digest:

```bash
deltaaegis restore-cutover-execute backups/example.db   --plan-digest <preview-plan-digest>   --confirmation "RESTORE ACTIVE DELTAAEGIS DATABASE"   --json
```

Active restore execution requires:

- A valid backup and matching manifest.
- No running DeltaAegis dashboard process using the active database.
- No active SQLite `-wal`, `-shm`, or `-journal` sidecar.
- An unchanged active database, backup, manifest, and preview digest.
- A fresh verified pre-restore safety backup.
- Successful temporary-restore and post-cutover verification.

The safety backup is retained after success or rollback. DeltaAegis does not delete, migrate, or automatically select an ignored root-level `deltaaegis.db`.

## Security Boundary

DeltaAegis v0.41.0 does not expose arbitrary shell command execution from the dashboard.

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

Run the complete v0.41 automated release gate from a clean checkout:

```bash
./tools/validate_v0_41_release_gate.sh
```

The release gate validates release metadata and documentation, rendered dashboard JavaScript, client-disconnect handling, all eight v0.41 durability and recovery checkpoints, the v0.40 operator-action suite, and the v0.39 compatibility suite. Every v0.41 checkpoint validator is invoked directly and exactly once.

Complete the manual backup and restore checklist before merge, tag, or publication:

```text
MANUAL_VERIFICATION_v0.41.0.md
```

Basic syntax check:

```bash
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py
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
- Stop active dashboard processes automatically before a restore.
- Bypass SQLite sidecar, identity, checksum, or preview-digest blockers.
- Delete or migrate an ignored legacy root-level `deltaaegis.db` automatically.

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
