# Changelog

## v0.5.1 — Network Scope Isolation

- Added first-class `network_scope` tracking for imported NetSniper snapshots.
- Added automatic backfill for existing snapshots based on canonical CIDR scope.
- Added `deltaaegis scopes` for viewing known network scopes.
- Added `--scope` filters for snapshots, latest, events, alerts, risk, and asset-risk workflows.
- Updated baseline selection so snapshots only compare against accepted baselines from the same network scope.
- Isolated asset lifecycle state with a `(network_scope, asset_key)` primary key to prevent cross-subnet lifecycle contamination.
- Added dashboard scope selector support and scope-aware dashboard APIs.
- Added scope-aware identity enrichment for dashboard events, alerts, risk, and annotations.
- Preserved support for generic private/local CIDR ranges, including `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`-style networks.


## v0.5.0 — Read-Only Dashboard Foundation

### Added

- Added `dashboard` command.
- Added local read-only dashboard at `127.0.0.1:8090` by default.
- Added optional dashboard token protection with `--token`.
- Added `/healthz` endpoint.
- Added `/api/summary` endpoint.
- Added `/api/scan-context` endpoint.
- Added `/api/risk` endpoint.
- Added `/api/events` endpoint.
- Added `/api/alerts` endpoint.
- Added `/api/annotations` endpoint.
- Added NetSniper scan context panel showing latest scan, baseline scan, and delta comparison pairs.
- Added scan freshness status.
- Added observed asset, IP, MAC, and MAC+IP identity coverage counts.
- Added dashboard identity confidence labels.
- Added MAC and IP identity columns to dashboard risk, event, alert, and annotation tables.
- Added dashboard explanation panel for first-time users.
- Added risk and identity legend.
- Added recommended next steps panel.

### Changed

- Expanded DeltaAegis from a CLI/reporting prototype into a local dashboard-backed monitoring console.
- Improved digestibility for users who did not create the system by explaining scans, baselines, deltas, identity confidence, and risk scoring.

### Security Notes

- Dashboard is read-only in v0.5.0.
- Dashboard does not run scans, modify alerts, change annotations, or perform remediation.
- Dashboard binds to `127.0.0.1` by default.
- Token protection is available with `--token`.
- Public exposure should only be done behind proper access controls.

### Notes

- NetSniper ingestion compatibility is unchanged.
- v0.5.0 is the foundation for future hosted dashboard work.
- Future dashboard updates can add search, asset detail pages, alert detail pages, service deployment, and reverse-proxy guidance.

---

## v0.4.0 — Risk Register

### Added

- Added explainable risk scoring helpers.
- Added `risk` command.
- Added `risk --details` command.
- Added `risk --subject SUBJECT_KEY` filter.
- Added `asset-risk SUBJECT_KEY` command.
- Added risk levels based on score thresholds.
- Added scoring based on event severity, open alerts, acknowledged alerts, repeated recent activity, asset criticality, and missing annotations.
- Added visible scoring reasons so risk output remains explainable instead of opaque.

### Changed

- Updated DeltaAegis version language from v0.3.5 to v0.4.0.
- Expanded DeltaAegis scope from investigation reporting into risk prioritization.

### Notes

- v0.4.0 does not change NetSniper ingestion compatibility.
- v0.4.0 does not add the hosted dashboard yet.
- Risk register integration into reports is planned for v0.4.1.

---

All notable changes to DeltaAegis are documented here.

---

## v0.3.5 — Report Alert Review Notes

### Added

- Added alert review-note integration to Markdown investigation reports.
- Added report-level `Alert Review Notes` section.
- Reports now summarize alert action, status, severity, subject, reason, and timestamp when review notes match report subjects.
- Connected alert review workflow to generated investigation artifacts.

### Fixed

- Removed a misplaced per-alert review-note call that could trigger an `UnboundLocalError` during report generation.

---

## v0.3.4 — Report Asset Context

### Added

- Added asset annotation integration to Markdown investigation reports.
- Added `Annotated Asset Context` section to reports.
- Reports now show owner, role, criticality, and notes for matching annotated subjects.
- Added per-event asset context blocks for matching delta events.

### Fixed

- Fixed missing per-event report asset-context insertion after initial v0.3.4 implementation.

---

## v0.3.3 — Asset Owner Notes

### Added

- Added `asset_annotations` table.
- Added `asset_annotation_history` table.
- Added `annotate-asset` command.
- Added `asset-notes` command.
- Added `asset-annotations` command.
- Added owner, role, criticality, notes, updated timestamp, and annotation history support.

---

## v0.3.2 — Alert Review Notes

### Added

- Added `alert_notes` table.
- Added `ack ALERT_ID --reason "..."`.
- Added `suppress ALERT_ID --reason "..."`.
- Added `alert-notes ALERT_ID` command.
- Added alert review-note display inside `alert-detail`.

---

## v0.3.1 — Investigation Detail Commands

### Added

- Added `asset-timeline SUBJECT_KEY` command.
- Added `alert-detail ALERT_ID` command.
- Added deeper event and alert investigation workflow.
- Added alert-detail follow-up guidance and related-event display.

---

## v0.3.0 — Investigation Reports

### Added

- Added Markdown investigation report generation.
- Added `report` command.
- Added report output path support.
- Added event, severity, alert, and recommendation sections.

---

## v0.2.0 — Stateful Delta Engine

### Added

- Added SQLite-backed state tracking.
- Added imported snapshot history.
- Added delta event generation.
- Added alert lifecycle support.
- Added snapshot health review.
- Added baseline approval workflow.

---

## v0.1.0 — Initial Prototype

### Added

- Initial DeltaAegis prototype.
- NetSniper telemetry ingestion.
- Basic event and snapshot inspection.
