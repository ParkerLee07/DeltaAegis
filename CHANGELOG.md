# Changelog

## DeltaAegis v0.25.0 — Dashboard Session UX

### Added

- Protected `/operator` page that loads authenticated operator identity from `/api/session`.
- Dashboard `Operator` link for easier access to the operator session page.
- Client-side `Refresh session` action on the operator page.
- Client-side `Copy /api/session JSON` action on the operator page.
- v0.25 release gate and single-purpose validators.

### Preserved

- Username/password login, logout, session cookies, and `/api/session` from v0.24.
- API-token automation support through `X-DeltaAegis-Token`.
- v0.23 access model and v0.22 triage marker coverage.

### Security Notes

- v0.25 does not add a new backend endpoint for session data.
- Operator identity data continues to come from the protected `/api/session` route.

## DeltaAegis v0.24.0 — Dashboard Session Login

DeltaAegis v0.24.0 replaces the failed browser API-token prompt direction with a proper enterprise-style dashboard login flow.

### Added

- Dashboard username/password login backed by the local `access_users` model.
- Persistent `access_sessions` schema for dashboard sessions.
- HttpOnly, SameSite=Lax dashboard session cookie support.
- `/login` and `/logout` routes for browser operators.
- `user-password` CLI command for setting or rotating access-user passwords.
- `/api/session` endpoint exposing the authenticated operator identity, role, session id, expiration, and auth type.
- Session audit events for successful login, failed login, logout, and expiration.

### Preserved

- API-token authentication remains available for automation through `X-DeltaAegis-Token`.
- v0.23 enterprise access control, audit visibility, and dashboard token-auth behavior remain compatibility validated.
- v0.22 operator triage behavior remains covered through the v0.23 compatibility gate.

### Validation

- Added `tools/validate_v0_24_session_model.sh`.
- Added `tools/validate_v0_24_login_logout_routes.sh`.
- Added `tools/validate_v0_24_api_session.sh`.
- Added `tools/validate_v0_24_backward_compatibility.sh`.
- Added `tools/validate_v0_24_release_metadata.sh`.
- Added `tools/validate_v0_24_release.sh`.


## v0.23.0 — Enterprise Access Control

DeltaAegis v0.23.0 introduces enterprise access-control foundations for multi-operator use. This release adds local users and roles, database-backed API tokens, dashboard database-token authentication, role-aware dashboard write controls, token usage tracking, and access audit visibility.

### Added

- Access user model with `ADMIN`, `ANALYST`, and `VIEWER` roles.
- API token model with hashed token storage, token prefixes, active state, optional expiration, and last-used timestamps.
- CLI commands for `user-create`, `users`, `api-token-create`, `api-tokens`, and `access-audit`.
- Dashboard database-backed token authentication through `X-DeltaAegis-Token`.
- Role-aware dashboard authorization for workflow write actions.
- Access audit log entries for user creation, token creation, ticket workflow updates, and asset investigation updates.
- Dashboard `/api/access-audit` endpoint and audit visibility panel.
- v0.23 release validators for access schema, CLI/token workflows, dashboard auth, audit visibility, metadata, and compatibility.

### Compatibility

- Retains legacy dashboard `--token` authentication.
- Keeps v0.22 operator triage behavior compatible.
- Keeps v0.21, v0.20, and v0.19 compatibility gates in the v0.23 release validator.

## v0.22.0 — Operator Triage Intelligence

DeltaAegis v0.22.0 improves Investigation Center operator workflow by adding deterministic triage state, triage urgency, triage filters, dashboard triage controls, and report-level triage summaries.

### Added

- Operator triage state model for Investigation Center queue rows.
- Triage buckets for review prioritization:
  - `CHANGED_SINCE_REVIEW`
  - `NEEDS_REVIEW`
  - `NEEDS_CONTEXT`
  - `STALE_CLOSED`
  - `BASELINE_CONTEXT`
  - `MONITOR`
- Triage urgency labels:
  - `IMMEDIATE`
  - `HIGH`
  - `NORMAL`
  - `LOW`
- CLI and dashboard API filters for `triage_bucket` and `triage_urgency`.
- Dashboard triage summary cards and row-level triage badges.
- Report Investigation Command Center triage summary and triage columns.
- v0.22 validators for triage state, triage queue API/CLI, dashboard triage panel, report triage summary, and release metadata.

### Compatibility

- Keeps the v0.21 ticket evidence workflow compatible.
- Keeps v0.20 ticket evidence payload, CLI, dashboard, and report compatibility validators in the v0.22 release gate.
- No NetSniper bundle format change is required.

## v0.21.0 — Evidence Timeline Intelligence

DeltaAegis v0.21.0 improves ticket evidence so operators can quickly understand what matters, why it matters now, and which evidence categories support the ticket.

### Added

- Balanced ticket evidence timeline selection across current risk, alerts, delta events, MAC-port behavior, and ticket workflow history.
- Deterministic `Why now` summaries in the shared ticket evidence payload.
- CLI `ticket-evidence` output for `Why now`.
- Report Ticket Evidence Appendix support for `Why now`.
- Dashboard Ticket Evidence Drilldown polish with a dedicated **Why Now** block and readable timeline category labels.
- v0.21 release validators for evidence timeline intelligence, why-now summaries, dashboard timeline polish, and release metadata.

### Validation

- `tools/validate_v0_21_balanced_evidence_timeline.sh`
- `tools/validate_v0_21_why_now_summary.sh`
- `tools/validate_v0_21_dashboard_timeline_polish.sh`
- `tools/validate_v0_21_release_metadata.sh`
- `tools/validate_v0_21_release.sh`

## v0.20.0 — Ticket Evidence Drilldown

DeltaAegis v0.20.0 turns Investigation Center tickets into evidence-backed drilldowns across the backend, dashboard, CLI, and reports.

### Added

- Ticket evidence backend payloads that aggregate workflow state, ticket history, current risk reasoning, recent delta events, open alerts, MAC-port behavior, and asset identity context.
- `/api/ticket-evidence` dashboard API endpoint.
- Dashboard **View Evidence** action on Investigation Center tickets.
- Ticket Evidence Drilldown panel with evidence counts, timeline samples, current risk, alerts, events, port behavior, and ticket history.
- `ticket-evidence` CLI command for terminal-based investigation.
- Markdown report **Ticket Evidence Appendix** for top Investigation Center subjects.
- v0.20 release validator covering payload, dashboard, CLI, report appendix, and compatibility regression gates.

### Changed

- Investigation Center tickets now have a shared evidence model that can be reused consistently by dashboard, CLI, and Markdown reports.
- Markdown reports now preserve the supporting evidence behind top ticket priorities instead of only listing queue summaries.

### Validation

- `tools/validate_v0_20_ticket_evidence_payload.sh`
- `tools/validate_v0_20_dashboard_ticket_evidence.sh`
- `tools/validate_v0_20_ticket_evidence_cli.sh`
- `tools/validate_v0_20_report_ticket_evidence.sh`
- `tools/validate_v0_20_release.sh`


## v0.19.0 — Workflow Filters and Operator Views

DeltaAegis v0.19.0 makes the v0.18 investigation workflow easier to operate by adding workflow filters, signal filters, total-vs-visible counters, CLI operator context, and report workflow summaries.

### Added

- Investigation Center backend filters for workflow status:
  - `ALL`
  - `OPEN`
  - `IN_REVIEW`
  - `RESOLVED`
  - `SUPPRESSED`
- Investigation Center backend filters for ticket signal:
  - `ALL`
  - `ACTIONABLE`
  - `MEANINGFUL_CHANGE`
  - `BASELINE_CONTEXT`
- Dashboard filter controls for workflow state and signal label.
- Filter-aware `/api/investigation-center` query parameters:
  - `ticket_status`
  - `ticket_signal`
- Dashboard counters for visible filtered items and total queue items.
- Full-queue workflow summary counters.
- Full-queue signal summary counters.
- CLI operator context showing active filters, visible-vs-total counts, workflow summary, and signal summary.
- Markdown report Investigation Queue Operator Summary.
- Workflow and Signal columns in the report Investigation Command Center table.
- v0.19 release validator covering backend filters, dashboard filters, workflow counters, operator views, and release validation.

### Changed

- Investigation Center dashboard summaries now distinguish the current filtered view from the total queue.
- Ticket workflow actions refresh the current filtered Investigation Center view.
- Report dashboard usage notes now document ticket filter API parameters.

### Validation

- `tools/validate_v0_19_backend_filters.sh`
- `tools/validate_v0_19_dashboard_filters.sh`
- `tools/validate_v0_19_workflow_counters.sh`
- `tools/validate_v0_19_operator_views.sh`
- `tools/validate_v0_19_release.sh`


## v0.18.0 — Investigation Workflow Actions

DeltaAegis v0.18.0 turns the SIEM ticket queue into a persistent analyst workflow.

### Added

- Persistent investigation ticket state model for `OPEN`, `IN_REVIEW`, `RESOLVED`, and `SUPPRESSED`.
- Ticket workflow history with previous state, new state, analyst, note, and timestamp context.
- CLI commands for ticket workflow review and updates:
  - `ticket-status`
  - `ticket-list`
  - `ticket-history`
- Dashboard workflow status badges in Investigation Center tickets.
- Dashboard ticket-card workflow actions for Open, In Review, Resolve, and Suppress.
- `/api/ticket-status` for dashboard-driven workflow updates.
- Legacy `/api/investigate-asset` compatibility sync into ticket workflow state when statuses align.
- No-op workflow guard to prevent repeated same-status audit noise.
- Consolidated v0.18 release validator for the ticket workflow contract.

### Fixed

- Dashboard workflow tags now update after ticket workflow actions.
- Repeated same-status ticket updates no longer create noisy history rows such as `RESOLVED -> RESOLVED`.

### Validation

- `tools/validate_v0_18_ticket_state_model.sh`
- `tools/validate_v0_18_ticket_history.sh`
- `tools/validate_v0_18_workflow_visibility.sh`
- `tools/validate_v0_18_ticket_workflow_dashboard_actions.sh`
- `tools/validate_v0_18_ticket_noop_guard.sh`
- `tools/validate_v0_18_release.sh`


## v0.17.0 — Executive SIEM Dashboard Refresh

### Added

- Added executive SIEM-style dashboard shell.
- Added SIEM-aligned dashboard labels:
  - `Executive`
  - `Tickets`
  - `Risk Analysis`
  - `Network Activity`
  - `Taxonomy`
  - `Security Events`
  - `Alarms`
  - `Data Sources`
- Added executive analytics panels for:
  - Security-event top categories
  - Current-risk priority distribution
  - Asset classification mix
  - MAC-port behavior
- Added ticket-style investigation queue cards.
- Added ticket signal tuning for printer-like baseline inventory context.
- Added visible ticket signal labels:
  - `Actionable`
  - `Meaningful change`
  - `Baseline context`
- Added v0.17 validators:
  - `tools/validate_v0_17_dashboard_shell_theme.sh`
  - `tools/validate_v0_17_siem_charts.sh`
  - `tools/validate_v0_17_ticket_queue_layout.sh`
  - `tools/validate_v0_17_ticket_signal_tuning.sh`
  - `tools/validate_v0_17_ticket_signal_badges.sh`
  - `tools/validate_v0_17_release.sh`

### Changed

- Reframed the dashboard around SIEM-familiar workflows.
- Reduced stable printer inventory noise in the investigation queue.
- Kept meaningful printer behavior changes visible.
- Preserved v0.16 Investigation Command Center behavior.
- Preserved v0.15 MAC-port behavior correlation.
- Preserved v0.14 NetSniper scan orchestration.
- Preserved v0.13 current-state/current-risk dashboard behavior.
- Preserved v0.12 NetSniper intelligence drilldown behavior.
- Updated README current-release metadata to v0.17.0.

### Validation

- Verified dashboard shell/theme HTML contract.
- Verified SIEM chart panel HTML contract.
- Verified ticket queue card layout.
- Verified synthetic ticket signal tuning behavior.
- Verified visible ticket signal badge behavior.
- Verified v0.16, v0.15, v0.14, v0.13, and v0.12 regression gates.


## v0.16.0 — Investigation Command Center

### Added

- Added `/api/investigation-center` for a prioritized analyst queue.
- Added dashboard Command Center tab.
- Added `investigation-center` CLI command.
- Added Markdown report section `Investigation Command Center`.
- Added queue triggers for `CURRENT_RISK`, `OPEN_ALERT`, `RECENT_EVENT`, and
  `PORT_BEHAVIOR`.
- Added v0.16 validators:
  - `tools/validate_v0_16_investigation_center_api.sh`
  - `tools/validate_v0_16_command_center_dashboard.sh`
  - `tools/validate_v0_16_investigation_center_cli.sh`
  - `tools/validate_v0_16_investigation_center_report.sh`
  - `tools/validate_v0_16_release.sh`

### Changed

- Promoted the dashboard from separate detail tabs only into an analyst-first
  triage workflow.
- Preserved v0.15 MAC-port behavior correlation.
- Preserved v0.14 NetSniper scan orchestration.
- Preserved v0.13 current-state/current-risk dashboard behavior.
- Preserved v0.12 NetSniper intelligence drilldown behavior.
- Updated README current-release metadata to v0.16.0.

### Validation

- Verified synthetic Investigation Command Center payload generation.
- Verified dashboard Command Center HTML, tab allowlist, and API wiring.
- Verified terminal `investigation-center` CLI output.
- Verified Markdown reports include the Investigation Command Center section.
- Verified v0.15, v0.14, v0.13, and v0.12 regression gates.


## v0.15.0 — MAC-Port Behavior Correlation

### Added

- Added `port-behavior` CLI command for MAC-backed open-port behavior review.
- Added MAC identity normalization for port behavior correlation.
- Added detection for `UNEXPECTED_PORT_OPENED`, `PORT_FLAPPING`,
  `PORT_NO_LONGER_OBSERVED`, and `PORT_BASELINE_ESTABLISHED`.
- Added `/api/port-behavior` dashboard API.
- Added dashboard Port Behavior tab.
- Added current-risk integration for unexpected or volatile MAC-backed ports.
- Added conservative current-risk contribution caps for MAC-port behavior.
- Added role-aware recommended action text for reviewing MAC-port behavior changes.
- Added Markdown report section `MAC-Port Behavior Changes`.
- Added report dashboard/API usage note for `/api/port-behavior?limit=25&lookback=5`.
- Added v0.15 validators:
  - `tools/validate_v0_15_port_behavior_cli.sh`
  - `tools/validate_v0_15_port_behavior_dashboard.sh`
  - `tools/validate_v0_15_port_behavior_risk.sh`
  - `tools/validate_v0_15_port_behavior_report.sh`
  - `tools/validate_v0_15_release.sh`

### Changed

- Preserved v0.14 scan orchestration behavior.
- Preserved v0.13 current-state/current-risk dashboard behavior.
- Preserved v0.12 NetSniper intelligence drilldown behavior.
- Updated README current-release metadata to v0.15.0.

### Validation

- Verified synthetic MAC-port behavior detection.
- Verified dashboard Port Behavior HTML and payload wiring.
- Verified current risk integrates unexpected MAC-port behavior.
- Verified Markdown reports include MAC-Port Behavior Changes.
- Verified v0.14, v0.13, and v0.12 regression gates.


## v0.14.0 — NetSniper Scan Orchestration

### Added

- Added `scan_jobs` SQLite registry for NetSniper scan orchestration history.
- Added `scan-start --target <private-cidr>` for safe synchronous NetSniper v1.8
  headless scan execution.
- Added private IPv4 CIDR validation before scan launch.
- Added fixed NetSniper command construction using `--non-interactive`,
  `--greenbone no`, and `--json-status`.
- Added captured stdout/stderr scan logs.
- Added optional explicit `--auto-ingest` after successful scan completion.
- Added `/api/scan-jobs` dashboard API for read-only scan job history.
- Added read-only dashboard Scan Jobs tab.
- Added expandable dashboard risk explanations showing score band, scoring reasons, and suggested follow-up actions.
- Added v0.14 validators:
  - `tools/validate_v0_14_scan_job_registry.sh`
  - `tools/validate_v0_14_scan_start.sh`
  - `tools/validate_v0_14_scan_jobs_dashboard.sh`
  - `tools/validate_v0_14_risk_explanations.sh`
  - `tools/validate_v0_14_release.sh`

### Changed

- Kept dashboard scan job visibility read-only for this release.
- Preserved v0.13 current-state dashboard and current-risk behavior.
- Preserved v0.12 NetSniper intelligence drilldown regression behavior.

### Validation

- Verified scan job registry schema, payload conversion, CLI listing, and safe command builder.
- Verified `scan-start` with a fake NetSniper executable.
- Verified fixed command arguments:
  `--non-interactive --target 192.168.5.0/24 --greenbone no --json-status`
- Verified public CIDR rejection.
- Verified read-only dashboard Scan Jobs wiring.
- Verified v0.13 release regression gate against NetSniper run `20260623-123007`.


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
