# Changelog

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
