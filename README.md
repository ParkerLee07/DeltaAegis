# DeltaAegis

**Self-hosted, delta-first network-state monitoring and investigation console powered by NetSniper
telemetry.**

DeltaAegis ingests finalized NetSniper telemetry bundles, stores normalized historical snapshots in
SQLite, compares accepted scans over time, and explains what changed on a monitored network.

It is built for conservative, evidence-backed monitoring: asset lifecycle tracking, service-delta
detection, alert review, investigation notes, risk prioritization, NetSniper intelligence review,
Markdown reports, and a local dashboard.

---

## Current Release

**DeltaAegis v0.14.0 — NetSniper Scan Orchestration**

v0.14.0 adds the first controlled NetSniper scan-orchestration workflow to DeltaAegis.
It introduces a scan job registry, a safe CLI scan launcher for NetSniper v1.8 headless
scans, captured stdout/stderr logs, optional auto-ingest, and read-only dashboard scan
job visibility.

Current feature baseline: **DeltaAegis v0.14.0 — NetSniper Scan Orchestration**.

DeltaAegis v0.14.0 adds:

- `scan_jobs` SQLite registry for NetSniper orchestration history.
- `scan-start --target <private-cidr>` for safe NetSniper v1.8 headless scans.
- Private IPv4 CIDR validation before scan launch.
- Fixed NetSniper command execution with `--non-interactive`, `--greenbone no`,
  and `--json-status`.
- Captured scan stdout/stderr logs under the DeltaAegis scan log directory.
- Optional explicit `--auto-ingest` after successful scan completion.
- `/api/scan-jobs` for read-only dashboard scan job history.
- Dashboard Scan Jobs tab for status, target, bundle path, and job messages.
- Expandable dashboard explanations for why assets are Critical, High, Medium, Low, or Info.
- v0.14 validators for scan job registry, scan-start behavior, dashboard wiring,
  and release validation.


## What DeltaAegis Does

DeltaAegis answers:

- What changed between accepted NetSniper scans?
- Which assets appeared, disappeared, or changed state?
- Which services opened or closed?
- Which findings were added or removed?
- Which alerts are open, acknowledged, resolved, or suppressed?
- Which assets need an owner, role, criticality, or analyst review?
- Which NetSniper classifications are strong, weak, contradictory, or review-only?
- Why did DeltaAegis assign risk or review priority to a subject?

Basic flow:

```text
NetSniper telemetry bundle
        ↓
DeltaAegis ingestion
        ↓
SQLite snapshot history
        ↓
Delta engine
        ↓
Events + alerts
        ↓
Asset context + investigation notes
        ↓
Risk prioritization
        ↓
Dashboard + Markdown reports
```

DeltaAegis is intentionally conservative. It exposes confidence, evidence, contradictions, and
review queues so operators can validate uncertain assets instead of treating every classification as
fact.

---

## Core Capabilities

### Snapshot and Delta Monitoring

- Ingests finalized NetSniper telemetry bundles.
- Stores accepted snapshots in SQLite.
- Preserves append-only JSONL event history.
- Applies snapshot-quality and scan-profile compatibility gates.
- Tracks service-opened, service-closed, finding-added, finding-removed, profile-reset, identity, lifecycle, and classification events.
- Supports network-scope isolation so unrelated subnets are not compared as one environment.

### Asset Lifecycle and Identity

- Tracks stable assets across accepted scans.
- Uses MAC-backed identity when available.
- Separates globally administered MACs, locally administered MACs, and IP-only observations.
- Filters unusable network and broadcast addresses.
- Maintains asset annotations for owner, role, criticality, and notes.
- Supports inferred and persisted investigation status.

### Alert and Investigation Workflow

- Maintains operator-facing alerts with `OPEN`, `ACKNOWLEDGED`, `RESOLVED`, and `SUPPRESSED` states.
- Supports alert acknowledgement and suppression notes with analyst-provided reasons.
- Provides asset investigation detail with services, findings, events, alerts, annotations, classification context, and recommended next steps.
- Supports persistent investigation statuses such as `NEW`, `REVIEWING`, `NEEDS_OWNER`, `EXPECTED`, `FALSE_POSITIVE`, `MONITORING`, and `RESOLVED`.

### NetSniper Intelligence

DeltaAegis stores and displays NetSniper classification intelligence, including:

- primary classification type
- category
- confidence score
- confidence band
- decision
- SIEM action
- evidence records
- evidence reasons
- observed hints
- contradictions
- secondary candidates
- findings

v0.12.0 adds per-host NetSniper v1.7 drilldown through:

```bash
deltaaegis intelligence
deltaaegis intelligence-hosts --action review_queue --limit 25
deltaaegis intelligence-host 192.168.4.1
```

The dashboard Intelligence tab also supports clickable host evidence drilldown for NetSniper v1.7
review queue entries.

### Risk and Reporting

- Calculates an explainable risk register for prioritized analyst review.
- Uses classification-aware risk context conservatively.
- Avoids inflating risk from weak or display-only classifications.
- Generates Markdown investigation reports.
- Includes asset context, alert review notes, NetSniper intelligence summaries, risk explanations, events, alerts, and recommended actions.

### Dashboard

The local dashboard includes tabs for:

- Overview
- Investigations
- Risk
- Assets
- Intelligence
- Events
- Alerts

Dashboard features include:

- scope-aware views
- asset inventory
- event and alert tables
- risk register
- asset investigation panel
- investigation status controls
- NetSniper intelligence summary
- NetSniper v1.7 host evidence drilldown

Security note: keep the dashboard bound to `127.0.0.1` unless protected by trusted network controls,
an SSH tunnel, VPN, reverse proxy, or token protection.

---

## Requirements

- Linux
- Python 3.10 or newer
- NetSniper telemetry bundles
- SQLite through the Python standard library

Optional:

- `sqlite3` CLI for manual database inspection
- Git for source control and updates

DeltaAegis does not require a separate database server.

---


## Recent Releases

- DeltaAegis v0.14.0 — NetSniper Scan Orchestration adds controlled scan jobs,
  safe NetSniper v1.8 headless CLI launch, optional auto-ingest, captured logs,
  `/api/scan-jobs`, and read-only dashboard scan job history.
- DeltaAegis v0.13.0 — Current-State SIEM Dashboard added latest accepted snapshot
  state, full NetSniper inventory preservation, current-state dashboard cards,
  separated current/historical risk views, and calibrated current-risk scoring.
- DeltaAegis v0.12.2 — Dashboard Runtime Hotfix fixed the Intelligence tab
  JavaScript runtime error without changing database schema, ingestion behavior,
  or NetSniper intelligence behavior.
- DeltaAegis v0.12.1 — README Metadata Cleanup refreshed project metadata and
  documentation for the v0.12 baseline.
- DeltaAegis v0.12.0 — Intelligence Drilldown established the NetSniper v1.7
  per-host intelligence drilldown baseline.

## Installation

```bash
git clone https://github.com/ParkerLee07/DeltaAegis.git
cd DeltaAegis
chmod +x install.sh
./install.sh
```

After installation:

```bash
deltaaegis
```

Or run directly from the repository:

```bash
python3 deltaaegis.py
```

---

## Common Commands

Launch the interactive menu:

```bash
deltaaegis
```

Ingest new NetSniper telemetry bundles:

```bash
deltaaegis ingest
```

Show system summary:

```bash
deltaaegis summary
```

List imported snapshots:

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

Show snapshot health:

```bash
deltaaegis health --limit 20
```

Show configured telemetry paths:

```bash
deltaaegis paths
```

Show the explainable risk register:

```bash
deltaaegis risk
```

Show risk details for one subject:

```bash
deltaaegis asset-risk SUBJECT_KEY
```

Show latest NetSniper intelligence summary:

```bash
deltaaegis intelligence
```

List NetSniper v1.7 review queue hosts:

```bash
deltaaegis intelligence-hosts --action review_queue --limit 25
```

Inspect one NetSniper v1.7 intelligence host:

```bash
deltaaegis intelligence-host 192.168.4.1
```

Start the dashboard:

```bash
deltaaegis dashboard
```

Start the dashboard on a custom local port:

```bash
deltaaegis dashboard --host 127.0.0.1 --port 8090
```

Start the dashboard with token protection:

```bash
deltaaegis dashboard --token CHANGE_ME
```

---

## Network Scope Isolation

DeltaAegis supports canonical network scope isolation across scan history, baseline selection,
lifecycle state, CLI views, and dashboard views.

Examples:

```bash
deltaaegis scopes
deltaaegis snapshots --scope 192.168.4.0/24
deltaaegis latest --scope 192.168.4.0/24
deltaaegis events --scope 192.168.4.0/24
deltaaegis alerts --scope 192.168.4.0/24
deltaaegis risk --scope 192.168.4.0/24
deltaaegis dashboard --scope 192.168.4.0/24
```

Targets such as `192.168.4.25/24` are normalized to `192.168.4.0/24`.

---

## Investigation Workflow

Show asset history by asset key or current IP:

```bash
deltaaegis asset 192.168.4.32
deltaaegis asset mac:aa:bb:cc:dd:ee:ff
```

Show timeline for a specific subject key:

```bash
deltaaegis asset-timeline 'SUBJECT_KEY'
deltaaegis asset-timeline 'ip:192.168.4.32'
deltaaegis asset-timeline '192.168.4.32:tcp/8080'
deltaaegis asset-timeline 'mac:aa:bb:cc:dd:ee:ff'
```

Set investigation status:

```bash
deltaaegis investigate-asset 'mac:aa:bb:cc:dd:ee:ff' \
  --scope 192.168.4.0/24 \
  --status MONITORING \
  --reason "Known device under review"
```

---

## Alert Review

Acknowledge an alert:

```bash
deltaaegis ack ALERT_ID --reason "Reviewed and confirmed expected behavior"
```

Suppress an alert:

```bash
deltaaegis suppress ALERT_ID --reason "Known recurring lab service"
```

Show detailed alert context:

```bash
deltaaegis alert-detail ALERT_ID
```

Show review notes for an alert:

```bash
deltaaegis alert-notes ALERT_ID
```

---

## Asset Annotations

Annotate an asset:

```bash
deltaaegis annotate-asset 'ASSET_KEY' \
  --owner "IT" \
  --role "Printer" \
  --criticality "LOW" \
  --notes "Known office printer"
```

Show notes for one asset:

```bash
deltaaegis asset-notes 'ASSET_KEY'
```

List annotations:

```bash
deltaaegis asset-annotations
```

---

## Reports

Generate a Markdown report:

```bash
deltaaegis report --limit 100
```

Reports include:

- snapshot summary
- asset lifecycle context
- event summary
- alert context
- alert review notes
- asset annotations
- NetSniper intelligence summary
- classification review context
- explainable risk register
- recommended next actions

---

## Validation

Current release validation:

```bash
tools/validate_v0_12_release.sh
```

Important v0.14 validators:

- `tools/validate_v0_14_scan_job_registry.sh`
- `tools/validate_v0_14_scan_start.sh`
- `tools/validate_v0_14_scan_jobs_dashboard.sh`
- `tools/validate_v0_14_risk_explanations.sh`
- `tools/validate_v0_14_release.sh`

Important v0.13 validators:

- `tools/validate_v0_13_full_inventory_ingest.sh`
- `tools/validate_v0_13_current_state_payload.sh`
- `tools/validate_v0_13_current_state_dashboard_ui.sh`
- `tools/validate_v0_13_current_risk.sh`
- `tools/validate_v0_13_release.sh`

Important v0.12 validators:

```bash
tools/validate_v0_12_intelligence_drilldown.sh
tools/validate_v0_12_dashboard_intelligence_api.sh
tools/validate_v0_12_dashboard_intelligence_panel.sh
tools/validate_v0_12_release.sh
```

General Python checks:

```bash
python3 -m py_compile deltaaegis.py
pytest -q
```

---

## Version Highlights

### v0.14.0 — NetSniper Scan Orchestration

- `scan_jobs` registry for NetSniper orchestration history.
- Safe `scan-start --target <private-cidr>` CLI command.
- Fixed NetSniper v1.8 headless command execution.
- Captured scan stdout/stderr logs.
- Optional explicit auto-ingest after successful scan completion.
- `/api/scan-jobs` read-only dashboard API.
- Dashboard Scan Jobs tab for job status and bundle visibility.

### v0.13 compatibility notes

The v0.13 current-state SIEM dashboard baseline remains available through:

- `/api/current-state` for latest accepted snapshot state.
- `/api/current-risk` for latest-snapshot-only current risk.
- Current Risk Subjects and Historical Risk Context dashboard sections.

### v0.13.0 — Current-State SIEM Dashboard

- Full NetSniper inventory preservation during ingest.
- Latest accepted snapshot current-state API.
- Dashboard Current Network State cards.
- Current Risk Subjects separated from Historical Risk Context.
- Current-risk scoring calibrated against all-CRITICAL saturation.
- v0.13 release validators for ingest, API payloads, dashboard UI wiring, and risk scoring.

### v0.12.0 — Intelligence Drilldown

- Per-host NetSniper v1.7 intelligence storage.
- `intelligence-hosts` CLI command.
- `intelligence-host` CLI command.
- Dashboard API for per-host intelligence evidence.
- Clickable dashboard host evidence drilldown panel.

### v0.11.x — Intelligence Review Dashboard

- NetSniper v1.7 run-level intelligence summary storage.
- Dashboard Intelligence tab summary cards.
- Review queue samples.
- v0.11.1 metadata cleanup.

### v0.10.0 — NetSniper v1.6 Intelligence Integration

- First-class calibrated classification fields.
- SIEM action policy handling.
- Conservative classification-aware risk behavior.

### v0.9.0 — Investigation Workflow

- Dashboard-driven investigation workflow.
- Persistent asset investigation statuses.
- Clickable risk, event, and alert subjects.
- Dashboard investigation status controls.

Earlier history is tracked in `CHANGELOG.md`.

---

## Project Status

DeltaAegis is still pre-v1.0.

It is functional as a local-first network-state monitoring and investigation console, but v1.0
should wait until configuration, installation, documentation, release validation, dashboard
workflows, and operator review actions are stable enough for normal users.

---

## Related Project

DeltaAegis is powered by NetSniper telemetry.

NetSniper performs network discovery and produces immutable telemetry bundles. DeltaAegis ingests
those bundles and focuses on historical state, deltas, review workflow, and reporting.

---

## License

MIT License.
