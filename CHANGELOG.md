# Changelog

## v0.13.0 — Current-State SIEM Dashboard

### Added

- Preserved full NetSniper inventory during DeltaAegis ingest, including discovered hosts with no monitored open services.
- Added `/api/current-state` for latest accepted snapshot inventory and intelligence state.
- Added dashboard Current Network State cards for assets, intelligence hosts, service-observed assets, discovery/no-open-service assets, classification counts, false-confidence candidates, and MAC identity coverage.
- Added `/api/current-risk` for latest-snapshot-only risk scoring.
- Added separate dashboard sections for Current Risk Subjects and Historical Risk Context.
- Added v0.13 validators:
  - `tools/validate_v0_13_full_inventory_ingest.sh`
  - `tools/validate_v0_13_current_state_payload.sh`
  - `tools/validate_v0_13_current_state_dashboard_ui.sh`
  - `tools/validate_v0_13_current_risk.sh`
  - `tools/validate_v0_13_release.sh`

### Changed

- Calibrated current-risk scoring so normal printer/web management exposure does not automatically saturate to CRITICAL.
- Kept historical event-driven risk available separately as context instead of mixing it into current risk.

### Validation

- Verified against NetSniper v1.8.0-dev bundle `20260623-123007`.
- Verified latest accepted snapshot state:
  - 49 assets
  - 49 intelligence hosts
  - 23 service-observed assets
  - 26 discovery/no-open-service assets
  - 12 classified
  - 9 possible/review
  - 28 unknown
- Verified current-risk rows are latest-snapshot subjects only.
- Verified current-risk scoring has zero all-100 saturation in the top current-risk rows.
- Verified v0.12 dashboard intelligence drilldown regression validators still pass.







## v0.12.2 — Dashboard Runtime Hotfix

### Fixed

- Fixed a dashboard JavaScript runtime error where the Intelligence tab could attempt to access
  `v17Block` before initialization.
- Restored reliable loading of the NetSniper v1.7 Intelligence dashboard section.

### Validation

- Verified dashboard intelligence panel validation.
- Verified README current-release metadata validation.
- Verified v0.12.1 README cleanup validation.
## v0.12.1 — README Metadata Cleanup

### Changed

- Refreshed README.md for the current v0.12 project state.
- Removed stale README positioning from older v0.8, v0.9, v0.10, and v0.11-era content.
- Added README current-release validation with formatting sanity checks.
- Kept v0.12.0 Intelligence Drilldown as the current feature baseline.

### Validation

- Verified README current-release metadata.
- Verified README formatting sanity checks.
- Verified v0.12 intelligence drilldown validators still pass.
## v0.12.0 — Intelligence Drilldown

### Added

- Added SQLite storage for per-host NetSniper v1.7 enriched intelligence from analysis.enriched.json.
- Added intelligence-hosts CLI command for listing review-queue host drilldown rows.
- Added intelligence-host CLI command for inspecting one host by host ID, IP, MAC, or hostname.
- Added dashboard API endpoint for per-host NetSniper v1.7 intelligence evidence.
- Added clickable dashboard Host Evidence Drilldown panel inside the Intelligence tab.
- Added rendering for observed hints, observed summary, evidence, evidence reasons, contradictions, secondary candidates, and findings.
- Added v0.12 validators:
  - tools/validate_v0_12_intelligence_drilldown.sh
  - tools/validate_v0_12_dashboard_intelligence_api.sh
  - tools/validate_v0_12_dashboard_intelligence_panel.sh
  - tools/validate_v0_12_release.sh

### Validation

- Verified against NetSniper v1.7 bundle 20260619-134116.
- Verified 82 per-host intelligence rows are stored.
- Verified 192.168.4.1 drilldown includes:
  - Web Server / Web Application Host
  - confidence 15
  - weak confidence band
  - possible decision
  - review_queue SIEM action
  - http_80 evidence on tcp/80
## v0.11.1 — Metadata Cleanup

### Fixed

- Corrected README current-release wording so v0.11 is presented as the active release line instead of v0.10.
- Removed duplicate appended v0.11 README release text.
- Updated stale DeltaAegis v0.10 CLI metadata to v0.11.1.
- Updated CLI summary heading from v0.10.0 to v0.11.1.
- Added a v0.11.1 metadata validator to catch stale release labels.

### Validation

- Carried forward the v0.11 release validator.
- Verified README, CHANGELOG, CLI description, and summary label metadata.
## v0.11.0 — Intelligence Review Dashboard

### Added

- Added SQLite storage for NetSniper v1.7 intelligence summary artifacts.
- Added manifest-aware ingestion for NetSniper v1.7 analysis.enriched.json, classification_quality.json, and classification_quality.md.
- Added the intelligence CLI command for reviewing the latest imported NetSniper intelligence summary.
- Added dashboard payload support for NetSniper v1.7 run-level intelligence summaries.
- Added dashboard Intelligence-tab visibility for host counts, classification counts, false-confidence candidates, unknown exposed-service hosts, top device types, confidence bands, and review queue samples.
- Added v0.11 validation scripts:
  - tools/validate_v0_11_intelligence_artifacts.sh
  - tools/validate_v0_11_dashboard_intelligence.sh
  - tools/validate_v0_11_release.sh

### Validation

- Verified ingestion against NetSniper v1.7 bundle 20260619-134116.
- Verified expected summary values:
  - 82 hosts
  - 13 classified
  - 33 possible/review
  - 36 unknown
  - 0 false-confidence candidates
  - 0 unknown exposed-service hosts
## v0.10.0 - 2026-06-19

### Added
- Added first-class storage for NetSniper v1.6 classification fields, including confidence band, calibrated decision, SIEM action, calibration reason, validation state, contradiction count, validator summary, and validator details.
- Added `tools/validate_v0_10_netsniper_v1_6_storage.sh` to validate v1.6 classification persistence and snapshot output.
- Added `tools/validate_v0_10_netsniper_v1_6_risk_policy.sh` to validate calibrated classification risk behavior.

### Changed
- Updated classification-aware risk scoring to respect NetSniper v1.6 `siem_action` values.
- `display_only` classifications no longer inflate asset risk.
- `review_queue` classifications now add only a small manual-review risk nudge.
- `alert_eligible` and `risk_context` classifications retain normal role-aware risk context.
- `contradiction_review` classifications remain visible as meaningful risk context.

### Validation
- Verified Python syntax with `python3 -m py_compile deltaaegis.py`.
- Verified v0.10 classification storage validation.
- Verified v0.10 classification risk policy validation.
- Verified existing v0.8.5 role-aware risk regression validation.

## v0.9.0 - 2026-06-19

### Added
- Added asset investigation detail payloads for dashboard-driven review.
- Added clickable risk, event, and alert subjects that open the asset investigation panel.
- Added inferred `NEEDS_OWNER` status for active assets without owner or annotation context.
- Added persistent asset investigation status storage through `asset_investigations`.
- Added persistent investigation history through `asset_investigation_history`.
- Added `investigate-asset` CLI command for saving investigation status and analyst reason.
- Added dashboard controls for saving investigation status through `POST /api/investigate-asset`.
- Added tabbed dashboard layout for Overview, Investigations, Risk, Assets, Intelligence, Events, and Alerts.
- Added dashboard tab validation to prevent broken tab initialization and collapsed-card regressions.
- Added `tools/validate_v0_9_release.sh` as the v0.9 release gate.
- Added `tools/validate_v0_9_asset_investigation_detail.sh`.
- Added `tools/validate_v0_9_clickable_investigation_rows.sh`.
- Added `tools/validate_v0_9_persistent_investigation_status.sh`.
- Added `tools/validate_v0_9_dashboard_investigation_controls.sh`.
- Added `tools/validate_v0_9_dashboard_tabs.sh`.

### Changed
- Dashboard mode now supports controlled investigation status updates instead of being purely read-only.
- Asset detail now distinguishes inferred status from persisted operator status.
- Dashboard information is separated into tabs to reduce visual overload.
- Dashboard wording now describes local investigation workflow instead of read-only visibility only.
- Release validation now includes v0.9 investigation workflow and dashboard tab checks.

### Fixed
- Fixed dashboard tab initialization so tab buttons bind correctly.
- Removed redundant collapse/expand controls after dashboard sections were separated into tabs.
- Repaired dashboard tab initialization regression before release.

### Validation
- `pytest -q`
- `tools/validate_v0_9_release.sh`
- `tools/validate_v0_9_asset_investigation_detail.sh`
- `tools/validate_v0_9_clickable_investigation_rows.sh`
- `tools/validate_v0_9_persistent_investigation_status.sh`
- `tools/validate_v0_9_dashboard_investigation_controls.sh`
- `tools/validate_v0_9_dashboard_tabs.sh`

### Notes
- DeltaAegis v0.9.0 remains local-first and conservative.
- Low-confidence NetSniper classifications are shown as review context and should not be treated as confirmed identity without supporting evidence.
- The dashboard does not run arbitrary shell commands or launch scans in v0.9.0.


## v0.8.6 - 2026-06-18

### Fixed

- Fixed dashboard risk, event, and alert tables rendering as empty even when backend data existed.
- Fixed Top Risk Subjects column alignment.
- Fixed Recent Delta Events column alignment.
- Fixed Recent Alerts column alignment.
- Added a Type column to Recent Alerts so alert event types are not displayed under IP or MAC fields.
- Restored dashboard severity and risk-level color styling for CRITICAL, HIGH, MEDIUM, LOW, and INFO values.

### Added

- Dashboard table rendering validator.
- Dashboard column alignment validator.
- Dashboard severity color validator.

### Notes

- This is a dashboard polish and reliability release following the v0.8.5 classification-aware risk milestone.
- No database migration is required.
<!-- DELTAAEGIS_V086_CHANGELOG_END -->


<!-- DELTAAEGIS_V085_CHANGELOG_START -->
## v0.8.5 - 2026-06-17

### Added

- Classification-aware risk context in the risk register.
- Conservative role-aware risk points for suspected printers, cameras/NVRs, web servers, domain controllers, databases, container infrastructure, and unknown assets.
- Explainable classification risk reasons merged into normal risk explanations.
- Role-aware recommended actions for risk subjects.
- Dashboard recommendation guidance that includes role-aware follow-up items.
- Markdown report section for Role-Aware Recommended Actions.
- Recommendation wording polish that distinguishes truly unknown assets from suspected roles with low confidence.
- Validation script: `tools/validate_v0_8_5_role_aware_risk.sh`.
- Validation script: `tools/validate_v0_8_5_role_aware_recommendations.sh`.
- Validation script: `tools/validate_v0_8_5_recommendation_polish.sh`.
- Validation script: `tools/validate_v0_8_5_docs.sh`.

### Changed

- Risk scoring now considers classification-aware role context while preserving event severity, alert state, repeated activity, asset criticality, and annotation logic.
- Reports now explain that risk scores include classification-aware role context.
- Recommendations now use clearer suspected-role language for low-confidence classifications.

### Notes

- DeltaAegis v0.8.5 does not automatically trust NetSniper classifications. It uses classification data as explainable context and keeps confidence, evidence, and uncertainty visible.

## v0.8.0 - 2026-06-17

### Added

- Dashboard asset inventory classification columns.
- Asset detail NetSniper Intelligence panel.
- Dashboard NetSniper Intelligence Summary cards.
- Classification review queue.
- Markdown report NetSniper Intelligence Summary section.
- Report top classifications and classification review queue.
- Validation script: `tools/validate_v0_8_visibility.sh`.
- Validation script: `tools/validate_v0_8_intelligence_summary.sh`.
- Validation script: `tools/validate_v0_8_report_intelligence_summary.sh`.

### Changed

- Dashboard and reports now expose NetSniper classification intelligence to operators instead of only storing it in the database.

## v0.7.0 - 2026-06-17

### Added

- NetSniper v1.4 classification intelligence ingestion.
- Classification fields in `asset_observations`.
- Classification storage for type, primary type, confidence, confidence label, decision, method, evidence, contradictions, and candidates.
- Classification delta events:
  - `DEVICE_CLASSIFICATION_CHANGED`
  - `DEVICE_CLASSIFICATION_CONFIDENCE_CHANGED`
  - `DEVICE_CLASSIFICATION_WEAK`
  - `DEVICE_CLASSIFICATION_CONTRADICTION`
- Baseline-noise protections so pre-v1.4 snapshots do not create false classification events.

### Changed

- DeltaAegis can now remember and compare NetSniper classification intelligence across accepted snapshots.
<!-- DELTAAEGIS_V085_CHANGELOG_END -->


## v0.6.0 — Investigation Dashboard and Scope-Aware Reporting

- Added `deltaaegis assets` for scope-aware asset inventory review.
- Added `--scope`, `--state`, `--identity`, and `--limit` filters for asset inventory workflows.
- Updated `deltaaegis asset` with `--scope` support to avoid cross-subnet ambiguity.
- Added dashboard asset inventory API support through `/api/assets`.
- Added dashboard asset detail API support through `/api/asset`.
- Added an Asset Inventory dashboard table.
- Added an Asset Detail dashboard panel with lifecycle state, latest observation, services, findings, events, alerts, and annotation context.
- Added an asset selector dropdown for quickly loading device detail views.
- Added clickable asset/subject links across Asset Inventory, Risk Subjects, Delta Events, and Alerts.
- Added collapsible dashboard cards to reduce visual overload during investigations.
- Expanded Markdown reports with Network Scope Summary, Asset Lifecycle Summary, Asset Inventory, Dashboard/API Usage Notes, and Recommended Next Actions.
- Added `deltaaegis report --scope` and `--asset-limit`.
- Fixed report filtering so scoped reports do not mix events or alerts from unrelated network scopes.
- Added missing risk severity scoring constants used by the expanded risk/reporting path.

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
