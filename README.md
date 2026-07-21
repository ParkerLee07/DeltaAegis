# DeltaAegis

DeltaAegis is a self-hosted, delta-first network-state monitoring and investigation console powered by NetSniper telemetry.

It ingests finalized NetSniper scan bundles, stores normalized historical snapshots in SQLite, compares accepted scans over time, and turns network changes into analyst-friendly events, alerts, asset context, risk views, and dashboard workflows.

## Current Release — v0.45.0

**DeltaAegis v0.45.0 — Telemetry Trust**

DeltaAegis v0.45.0 introduces a policy-driven trust boundary between immutable
NetSniper evidence and DeltaAegis operational current state. Evidence quality,
uncertainty, review history, and operator overrides remain explicit instead of
every imported bundle being treated as equally authoritative.

Highlights:

- Added deterministic `ACCEPTED`, `DEGRADED`, `QUARANTINED`, and `REJECTED`
  telemetry-quality decisions from versioned policy and content-bound evidence.
- Added immutable automated-decision records plus a separate authenticated
  review and override ledger.
- Added state-aware ingestion effects: accepted evidence may update full state,
  degraded evidence is additive or refresh-only, and quarantined or rejected
  evidence cannot mutate current state.
- Added replayable current-state projection so reviewed decisions rebuild the
  affected scope without rewriting source evidence.
- Added the authenticated Telemetry Quality Center, quality-detail APIs,
  review and policy-permitted override actions, Markdown reporting, and
  progressive technical disclosure.
- Added asset-detail visibility for structured NetSniper v2.1 classification
  context without changing list, event, or risk payload boundaries.
- Preserved the v0.44 modular-core ownership model and the retained v0.42,
  v0.40, and v0.39 compatibility floor.
- Retained `AGPL-3.0-only`; alternative commercial licensing remains available
  only by separate written agreement.

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

The current architecture, completed v0.44 responsibility boundaries, v0.45 telemetry-trust boundary, compatibility facade, and accepted decisions are documented in [`docs/architecture/overview.md`](docs/architecture/overview.md). The v1.0 product boundary is defined in [`V1_SCOPE.md`](V1_SCOPE.md), and supported environments are defined in [`SUPPORTED_VERSIONS.md`](SUPPORTED_VERSIONS.md).

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

## Scan Watchdog and Scheduler Recovery

DeltaAegis checks active NetSniper scan-job rows at dashboard startup and on every scheduled-scan worker pass. A running scan heartbeat is expected to advance every few seconds.

The automatic watchdog waits ten minutes before treating an active row as stale. It then verifies the recorded PID through `/proc/<pid>/cmdline`:

- A missing process or a PID that belongs to an unrelated command is marked `FAILED`, with the original PID, heartbeat, log paths, schedule ID, and recovery reason preserved in `status_json.watchdog`.
- A live process whose command still matches the expected NetSniper executable is not terminated or failed automatically. It remains blocked for operator review.
- A fresh active row is left unchanged.
- After a dead row is recovered, the same scheduler pass can start the oldest overdue schedule.

The existing **Mark stale active scans failed** action remains an explicit ADMIN recovery tool. This preserves the established **ADMIN-only stale scan-job recovery** workflow while adding safe automatic recovery for clearly dead processes. Automatic recovery never signals or kills a live process.

NetSniper schedules run NetSniper and optional auto-ingest only. TrueAegis validation remains a separate guarded workflow unless an existing schedule explicitly enables the separately validated follow-up option.

The established **blocked-schedule retry behavior** is preserved: when another active scan legitimately holds the single-scan lock, the due schedule remains due, its cadence is not advanced, and the scheduler retries it after the blocker clears.



## Dashboard Asset Investigation Completeness

The Investigation asset selector loads the complete scoped asset lifecycle inventory instead of reusing the 25-row dashboard preview. Current identities referenced by Network Activity, Risk Analysis, Security Events, or Alarms are no longer omitted solely because they fall outside a display limit.

Within each network scope, selector entries are ordered by the numeric IP value, with MAC address used only as a tie-breaker.

## Dashboard Evidence Freshness

Every main dashboard tab now shares a persistent evidence-freshness strip. It distinguishes the accepted scan observation time, DeltaAegis import time, and browser refresh time rather than presenting a page refresh as proof that the evidence is current.

A selected logical site and the all-scopes view evaluate every member subnet independently. The strip shows the newest and oldest accepted evidence timestamps, follows the least-fresh scope for its overall state, and warns when the selected scopes contain mixed-age evidence. Missing timestamps render as `Unknown`; no timestamp is synthesized from the browser clock.

Freshness warnings are intentionally actionable rather than merely
informational. The warning panel remains hidden unless a selected subnet has
accepted evidence more than 24 hours old or has no accepted scan. When shown,
it lists each affected private subnet, the supporting scan ID, the evidence
timestamp, and its age.

## Sites Dashboard UX

The Sites dashboard now uses dashboard-native styling for buttons, text
inputs, selectors, and destructive actions. The site-name field no longer
includes an organization-specific example.

Every unassigned observed private subnet is listed with its CIDR, total
snapshots, accepted snapshots, and latest observation time. ADMIN users
can select one or more subnet checkboxes while creating a site. Site
creation and the selected membership assignments are committed together,
so a validation or assignment failure does not leave a partially created
site.

## Scheduled Scan Finalization Recovery

DeltaAegis now reconciles an active scan ledger row when its recorded
NetSniper process has exited but its persisted stdout and configured runs
directory prove that a matching finalized bundle completed successfully.
Recovery validates the manifest target, profile, completion state, run
timestamp, and configured runs-root confinement before finalizing the
original job.

Successful orphan recovery performs idempotent auto-ingest, records the
terminal job in schedule history, advances the linked schedule, and allows
the next oldest overdue subnet to run. A stale dead job without valid
completion evidence is marked failed and its linked schedule is also
advanced so one subnet cannot indefinitely starve later schedules.

Normal dashboard shutdown now waits for an active scheduled scan worker to
finish its job, ingestion, and schedule finalization instead of abandoning
the ledger row after a two-second timeout.

## TrueAegis Tab Containment

The Executive tab now shows only a compact TrueAegis readiness summary: readiness state, latest accepted scan, active-job count, and one navigation control. Full orchestration is contained inside the **TrueAegis** tab.

The TrueAegis tab owns the guarded run action, blocker detail, technical paths, command preview, action receipt, job history, validation import controls, observations, and service correlations. The orchestration panel mounts inside the static TrueAegis foundation instead of being inserted as a top-level sibling after initial tab selection.

This containment changes presentation only. Existing fixed-argument execution, RBAC, subnet-specific operational boundaries, validation ingestion, correlation behavior, action receipts, scheduler follow-up, polling cadence, and APIs remain unchanged.

## Sites Dashboard Management

The main dashboard now includes a dedicated **Sites** tab. All authenticated roles can review active and archived logical sites, member-subnet coverage, accepted-snapshot counts, and unassigned observed private subnets.

ADMIN operators can create sites, rename them, update descriptions, assign or remove private CIDR members, and archive sites without leaving the dashboard. Every mutation reuses the same normalization and one-site-per-subnet invariants as the CLI, returns a human-readable action receipt, derives the actor from the authenticated session, and records access-audit evidence.

Archived sites retain memberships and historical evidence, remain visible in the Sites tab, reject new assignments, and are read-only in the browser. The Executive tab keeps a compact site/scope selector for site-wide SIEM aggregation and subnet drilldown.

## Logical Site Scopes

Logical sites are additive parents for the technical CIDR scopes already used throughout DeltaAegis. NetSniper scan targets, snapshot identity, asset lifecycle identity, events, alerts, and evidence continue to use canonical subnet CIDRs. A building or site name never replaces `network_scope`.

The relationship is intentionally constrained:

```text
one logical site -> many private CIDR subnet scopes
one subnet scope -> zero or one logical site
```

Create and inspect a site:

```bash
python3 deltaaegis.py site-create   "CLS Health - Admin Building"   --description "Administrative building network scopes."

python3 deltaaegis.py site-list
python3 deltaaegis.py site-show SITE_ID
```

Assign private subnet scopes:

```bash
python3 deltaaegis.py site-assign-scope SITE_ID 192.168.4.0/24
python3 deltaaegis.py site-assign-scope SITE_ID 192.168.5.0/24
python3 deltaaegis.py scopes --unassigned
```

Use `--json` on the logical-site commands for structured receipts and payloads. For rehearsal without changing the configured evidence database, pass a temporary database explicitly:

```bash
python3 deltaaegis.py --db /tmp/deltaaegis-site-rehearsal.db   site-create "Rehearsal Site"
```

The dashboard site selector aggregates core read-only SIEM views across member subnets. Each row retains its `network_scope`, and collision-prone identities receive a scope-qualified key. Asset detail and ticket evidence fail closed when the same identifier exists in more than one member subnet.

NetSniper scans remain CIDR-targeted, and TrueAegis execution remains subnet-specific. Select a member subnet before starting those operational workflows.

To expose the authenticated dashboard on the local network:

```bash
python3 deltaaegis.py dashboard --lan --port 8090
```

`--lan` requires at least one active password user or an explicit API token. DeltaAegis continues to serve HTTP directly, so use a trusted LAN or place it behind an HTTPS reverse proxy for broader deployment.

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

DeltaAegis v0.45.0 does not expose arbitrary shell command execution from the dashboard.

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

## Validator Troubleshooter

The health check resolves the effective database by running `python3 deltaaegis.py paths`; it does not infer the active database from hard-coded filenames. Missing legacy database files are not treated as faults.

Open the guided human-readable menu:

    python3 tools/deltaaegis_troubleshooter.py --menu

Running the tool without arguments also opens the menu when stdin and stdout are interactive terminals. The menu provides concise health checks, targeted validator execution, retained reports, and stable `DAE-TRB-NNNN` diagnostic codes. See [the troubleshooter and error-code reference](docs/TROUBLESHOOTER.md).

DeltaAegis includes one repository-aware troubleshooting tool. It reads the validator inventory from the selected checkout, identifies the highest versioned release gate, and runs selected validators in fresh isolated clones. It no longer carries an embedded copy of historical validator scripts that can drift behind the repository.

Run the current release gate in a fresh isolated `$HOME/DeltaAegis` clone:

    python3 tools/deltaaegis_troubleshooter.py

Verify validator Bash syntax and the executable reference graph:

    python3 tools/deltaaegis_troubleshooter.py --self-check
    python3 tools/deltaaegis_troubleshooter.py --self-check --strict-graph

Run the current staged checkpoint wrappers:

    python3 tools/deltaaegis_troubleshooter.py --mode stages

Run every static root once, with a fresh clone per validator:

    python3 tools/deltaaegis_troubleshooter.py --mode all-leaves

Inspect the current validator group:

    python3 tools/deltaaegis_troubleshooter.py --match 'v0_44' --list

Reports include environment details, read-only SQLite integrity checks, validator provenance, individual logs, diagnostic codes, and Markdown and JSON summaries. Historical validator failures are reported individually rather than treated as current-release regressions.

The default branch intentionally retains the active compatibility floor rather than every validator ever published. Retired paths and byte-for-byte archive evidence are recorded in [the validator retention policy](docs/validation-retention-policy.md) and `docs/v0.44.1-validator-retirement.json`; the verified `v0.44.0` tag preserves the pre-retirement tree.

## Validation

Run the complete v0.45.0 automated release gate from a clean checkout:

```bash
./tools/validate_v0_45_release_gate.sh
```

The release gate validates v0.45 release metadata, deterministic telemetry-quality decisions, durable review storage, state-aware effects, replayable current-state projection, authenticated review and override boundaries, the Telemetry Quality Center, regression tests, the deterministic repository audit, and the retained predecessor compatibility floor.

Complete the manual backup and restore checklist before merge, tag, or publication:

```text
operator-managed release verification
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

DeltaAegis v0.45.0 is licensed under the **GNU Affero General Public License, version 3 only** (`AGPL-3.0-only`). See `LICENSE` and `LICENSING.md`.

Alternative commercial licensing may be available from Parker Lee through a separate written agreement. Earlier copies already distributed under the MIT License retain the permissions that accompanied those copies.

The dashboard provides a visible **Corresponding Source** link to the official repository.
