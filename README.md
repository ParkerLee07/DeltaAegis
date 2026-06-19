# DeltaAegis

Self-hosted, delta-first network-state monitoring and investigation console powered by NetSniper telemetry.

DeltaAegis ingests finalized NetSniper telemetry bundles, stores normalized historical snapshots in SQLite, compares accepted scans over time, and explains what changed on a monitored network. It focuses on conservative, evidence-backed network-state monitoring, asset investigation, risk prioritization, analyst review notes, Markdown reports, and a local dashboard.

---

## Current Release

Current release: **DeltaAegis v0.11.1 — Metadata Cleanup**

DeltaAegis v0.11.1 is a documentation and metadata cleanup release for the v0.11 Intelligence Review Dashboard line. It keeps the v0.11 feature set unchanged while correcting stale v0.10 labels in README and CLI metadata.

### v0.11 Intelligence Review Dashboard

DeltaAegis v0.11.x adds first-class visibility for NetSniper v1.7 device-intelligence artifacts.

Key capabilities:

- Ingests NetSniper v1.7 manifest-addressable intelligence artifacts:
  - analysis.enriched.json
  - classification_quality.json
  - classification_quality.md
- Stores NetSniper v1.7 run-level intelligence summaries in SQLite.
- Adds the intelligence CLI command for reviewing the latest imported NetSniper intelligence summary.
- Adds dashboard visibility for host counts, classified hosts, possible/review hosts, unknown hosts, false-confidence candidates, unknown exposed-service hosts, top device types, confidence bands, and review queue samples.

Run the intelligence summary command:

    python3 deltaaegis.py intelligence

The dashboard includes a NetSniper v1.7 Bundle Intelligence section inside the Intelligence tab.
## What v0.10.0 Adds

- First-class storage for NetSniper v1.6 classification fields.
- Stored calibrated confidence band, calibrated decision, SIEM action, calibration reason, validation state, contradiction count, validator summary, and validator details.
- Risk scoring now respects NetSniper v1.6 `siem_action`.
- `display_only` classifications no longer inflate asset risk.
- `review_queue` classifications add only a small manual-review nudge.
- `alert_eligible`, `risk_context`, and `contradiction_review` remain available for stronger role-aware risk context.
- v0.10 storage validation through `tools/validate_v0_10_netsniper_v1_6_storage.sh`.
- v0.10 risk policy validation through `tools/validate_v0_10_netsniper_v1_6_risk_policy.sh`.
- v0.10 release validation through `tools/validate_v0_10_release.sh`.

The v0.9 investigation workflow remains included:

- Asset investigation detail payloads with services, findings, events, alerts, annotations, classification evidence, and recommended next steps.
- Clickable risk, event, and alert subjects that open the asset investigation panel.
- Inferred NEEDS_OWNER status for active assets without owner or annotation context.
- Persistent asset investigation status storage through asset_investigations and asset_investigation_history.
- investigate-asset CLI command for saving investigation status and analyst reason.
- Dashboard-side investigation status controls through POST /api/investigate-asset.
- Tabbed dashboard layout for Overview, Investigations, Risk, Assets, Intelligence, Events, and Alerts.
- Dashboard tab validation to prevent broken tab initialization or collapsed-card regressions.
- v0.9 investigation workflow validation remains available through the v0.9 workflow validators.

---

## What DeltaAegis Does

DeltaAegis compares accepted NetSniper snapshots over time and turns network changes into structured events, alerts, asset context, and reports.

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
    Asset context + analyst notes
            ↓
    Risk prioritization
            ↓
    Dashboard investigation workflow + Markdown reports

DeltaAegis helps answer:

- What changed on the network?
- Which services appeared or disappeared?
- Which assets are stable, missing, or newly observed?
- Which alerts have been reviewed?
- Why did an analyst acknowledge, suppress, or monitor an item?
- What owner, role, or criticality is associated with an asset?
- Which subjects should be reviewed first based on explainable risk scoring?
- Which device classifications are confirmed, weak, contradictory, or uncertain?

---

## Core Features

- Ingests finalized netsniper-run-v1 and netsniper-run-v2 bundles.
- Parses Nmap XML service telemetry.
- Uses archived neighbor-table enrichment for MAC-backed local identity correlation.
- Separates globally administered MAC, locally administered MAC, and IP-only observations.
- Filters unusable network and broadcast addresses.
- Preserves historical snapshots and append-only JSONL events.
- Applies snapshot-quality and scan-profile compatibility gates.
- Tracks stable asset lifecycle with a three-accepted-scan removal threshold.
- Emits service-opened, service-closed, finding-added, finding-removed, profile-reset, identity, and classification events.
- Stores NetSniper classification intelligence, including type, decision, confidence, evidence, contradictions, and candidate roles.
- Maintains operator-facing alerts with OPEN, ACKNOWLEDGED, RESOLVED, and SUPPRESSED states.
- Supports alert review notes with analyst-provided reasons.
- Supports asset owner, role, criticality, and notes.
- Supports persistent asset investigation status.
- Calculates an explainable risk register for prioritized analyst review.
- Generates Markdown investigation reports.
- Provides a tabbed local dashboard for investigation workflow, risk review, assets, intelligence, events, and alerts.
- Provides an interactive terminal menu and automation-friendly direct commands.

---

## Investigation Status Workflow

Introduced in v0.9.0, DeltaAegis supports persistent asset investigation status.

Supported statuses:

    NEW
    REVIEWING
    NEEDS_OWNER
    EXPECTED
    FALSE_POSITIVE
    MONITORING
    RESOLVED

Set an investigation status from the CLI:

    deltaaegis investigate-asset 'mac:aa:bb:cc:dd:ee:ff' \
      --scope 192.168.4.0/24 \
      --status MONITORING \
      --reason "Known device under review"

The dashboard can also update investigation status through the asset detail panel.

DeltaAegis distinguishes inferred status from persisted operator status. For example, an unannotated active asset may be inferred as NEEDS_OWNER, while an analyst can persist REVIEWING, EXPECTED, or MONITORING with a reason.

---

## Dashboard

Start the local dashboard:

    deltaaegis dashboard

Default URL:

    http://127.0.0.1:8090

Start on a custom local port:

    deltaaegis dashboard --host 127.0.0.1 --port 8090

Start with token protection:

    deltaaegis dashboard --token CHANGE_ME

The dashboard includes tabs for:

- Overview — metrics, scope selection, scan context, legend, and recommended next steps.
- Investigations — asset detail, investigation status, next steps, timeline, alerts, services, findings, and context.
- Risk — top risk subjects with explainable scoring.
- Assets — asset inventory and annotations.
- Intelligence — NetSniper classification summary and review context.
- Events — recent delta events.
- Alerts — recent operator-facing alerts.

Dashboard API examples:

    /api/scopes
    /api/summary?scope=192.168.4.0/24
    /api/scan-context?scope=192.168.4.0/24
    /api/assets?scope=192.168.4.0/24&limit=25
    /api/asset?scope=192.168.4.0/24&identifier=mac:aa:bb:cc:dd:ee:ff
    /api/risk?scope=192.168.4.0/24
    /api/events?scope=192.168.4.0/24
    /api/alerts?scope=192.168.4.0/24
    /api/annotations?scope=192.168.4.0/24
    /api/investigate-asset
    /healthz

Security note: keep the dashboard bound to 127.0.0.1 unless it is protected by trusted network controls, an SSH tunnel, VPN, reverse proxy, or token protection. The dashboard allows investigation status updates but does not run arbitrary shell commands, perform remediation, or launch scans by itself.

---

## NetSniper Intelligence

DeltaAegis stores and displays NetSniper classification intelligence, including:

- primary classification type
- confidence score
- confidence label
- classification decision
- evidence records
- contradictions
- secondary candidates

DeltaAegis remains intentionally conservative. It exposes weak, possible, contradictory, and high-confidence classifications so analysts can validate uncertain assets instead of treating every classification as fact.

Low-confidence classifications should be treated as review context, not confirmed identity.

---

## Core Commands

Ingest new NetSniper telemetry bundles:

    deltaaegis ingest

Show system summary:

    deltaaegis summary

List imported snapshots:

    deltaaegis snapshots --limit 20

Show recent delta events:

    deltaaegis events --limit 50

Filter events by severity:

    deltaaegis events --severity HIGH --limit 50

Show alerts:

    deltaaegis alerts --status OPEN --limit 50

Show snapshot health:

    deltaaegis health --limit 20

Show configured telemetry paths:

    deltaaegis paths

Show the explainable risk register:

    deltaaegis risk

Show detailed risk scoring reasons:

    deltaaegis risk --details

Show risk details for one subject:

    deltaaegis asset-risk SUBJECT_KEY

---

## Asset Investigation

Show asset history by asset key or current IP:

    deltaaegis asset 192.168.4.32
    deltaaegis asset mac:aa:bb:cc:dd:ee:ff

Show timeline for a specific subject key:

    deltaaegis asset-timeline 'SUBJECT_KEY'

Examples:

    deltaaegis asset-timeline 'ip:192.168.4.32'
    deltaaegis asset-timeline '192.168.4.32:tcp/8080'
    deltaaegis asset-timeline 'mac:aa:bb:cc:dd:ee:ff'

Filter an asset timeline by severity:

    deltaaegis asset-timeline 'SUBJECT_KEY' --severity HIGH

---

## Alert Review

Acknowledge an alert:

    deltaaegis ack ALERT_ID --reason "Reviewed and confirmed expected behavior"

Suppress an alert:

    deltaaegis suppress ALERT_ID --reason "Known recurring lab service"

Show detailed alert context:

    deltaaegis alert-detail ALERT_ID

Show review notes for an alert:

    deltaaegis alert-notes ALERT_ID

Alert review notes preserve analyst decisions over time.

---

## Asset Annotations

Annotate an asset:

    deltaaegis annotate-asset 'ASSET_KEY' \
      --owner "IT" \
      --role "Printer" \
      --criticality "LOW" \
      --notes "Known office printer"

Show notes for one asset:

    deltaaegis asset-notes 'ASSET_KEY'

Show annotation history:

    deltaaegis asset-notes 'ASSET_KEY' --history

List saved annotations:

    deltaaegis asset-annotations

---

## Reports

Generate a Markdown investigation report:

    deltaaegis report

Write a report to a specific output path:

    deltaaegis report --output reports/example-report.md

Limit report event count:

    deltaaegis report --limit 100

Reports can include metadata, event totals, severity counts, event type counts, open alert context, annotated asset context, alert review notes, NetSniper intelligence summaries, risk subjects, and recommended follow-up guidance.

---

## Network Scope Isolation

DeltaAegis isolates scan history, baselines, lifecycle state, CLI views, dashboard views, and reports by normalized network scope.

Examples:

    deltaaegis scopes
    deltaaegis snapshots --scope 192.168.4.0/24
    deltaaegis latest --scope 192.168.4.0/24
    deltaaegis events --scope 192.168.4.0/24
    deltaaegis alerts --scope 192.168.4.0/24
    deltaaegis risk --scope 192.168.4.0/24
    deltaaegis dashboard --scope 192.168.4.0/24

Targets such as 192.168.4.25/24 are normalized to 192.168.4.0/24, preventing unrelated subnets from being compared as if they were the same environment.

---

## Runtime Data

Runtime state remains local and is excluded from Git.

Default paths:

    ~/DeltaAegis/
    ├── data/
    │   └── deltaaegis.db
    ├── events/
    │   └── events.jsonl
    ├── reports/
    │   └── generated Markdown reports
    └── backups/
        └── local backup files

NetSniper telemetry remains under:

    ~/NetSniper/runs/

---

## Data Model

DeltaAegis stores local state in SQLite.

Core tables include:

    snapshots
    asset_observations
    service_observations
    finding_observations
    delta_events
    asset_lifecycle
    alerts
    alert_notes
    asset_annotations
    asset_annotation_history
    asset_investigations
    asset_investigation_history

---

## Validation

Run the v0.10 release gate:

```bash
./tools/validate_v0_10_release.sh
```


```bash
./tools/validate_v0_10_netsniper_v1_6_storage.sh
./tools/validate_v0_10_netsniper_v1_6_risk_policy.sh
./tools/validate_v0_9_release.sh
```


    ./tools/validate_v0_9_release.sh

Basic syntax check:

    python3 -m py_compile deltaaegis.py

Basic tests:

    pytest -q

---

## Scope and Limitations

DeltaAegis is a network-state monitoring, investigation, risk prioritization, reporting, and dashboard prototype. It is not a replacement for a mature enterprise SIEM.

DeltaAegis does not currently:

- ingest endpoint logs
- store full packet captures indefinitely
- perform machine-learning anomaly detection
- send email or chat notifications
- automatically discover business owners for assets
- launch NetSniper scan jobs from the dashboard through a controlled scan runner
- replace manual analyst review

Its conclusions are limited to NetSniper telemetry, stored historical snapshots, analyst annotations, and local DeltaAegis state.

---

## Authorized Use Only

Use DeltaAegis only on networks and systems for which you have explicit authorization.

DeltaAegis is intended for defensive monitoring, lab validation, internship research, and authorized security assessment workflows.

---

## Related Project

DeltaAegis is designed to work with NetSniper telemetry. NetSniper performs network discovery and scan-bundle generation. DeltaAegis ingests those bundles and tracks how the monitored network changes over time.

---

## License

MIT License. See LICENSE.
