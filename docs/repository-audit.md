# DeltaAegis v1.0 Stage 1–2 Repository Audit

Schema: `deltaaegis-repository-audit-v3`

This deterministic inventory describes the combined v1.0 Stage 1–2 candidate based on released v0.45.0. Regenerate it with `python3 tools/audit_v0_44_repository.py --write`.

## Inventory summary

| Measure | Count |
|---|---:|
| Repository files in audit scope | 173 |
| `deltaaegis.py` lines | 35349 |
| Root top-level functions | 691 |
| Root top-level classes | 6 |
| Internal core modules | 12 |
| Distinct CLI commands | 67 |
| Distinct `/api` route literals | 73 |
| Declared schema tables | 28 |
| Validator scripts | 89 |
| Validator version groups | 9 |

Root source SHA-256: `a4b1a35cd9cf4c2cbe6c966ea4784b32c47f465137e22eb0bc77afdc2676bc64`

## Modular core inventory

| Module | Lines | Functions | Classes | Internal dependencies | SHA-256 |
|---|---:|---:|---:|---|---|
| `deltaaegis_core/api_v1.py` | 968 | 19 | 2 | None | `799d0d01946797fc94b0ed49924a68b8c15f6e00a0c25eaf7dc2d71fb9125467` |
| `deltaaegis_core/auth.py` | 1544 | 52 | 2 | None | `39d5072e86213b7dcfcbe34fdf35338f75f2aee50f9786883958a86de552211b` |
| `deltaaegis_core/config.py` | 80 | 1 | 1 | None | `0860bf7e2b193aa22c4ad41f69f3f3f4a2f3360c3635052ef7fe1959d1f17217` |
| `deltaaegis_core/current_state.py` | 1578 | 34 | 0 | None | `731dbc2f93f348dea37dafb305637118608e4b5d602f0d41c7d911b3544276cd` |
| `deltaaegis_core/db.py` | 25 | 1 | 0 | None | `8637f696f78a861a2d2f1ea00e5e671a1f5dd239659fcb99eb16b6c9154e3488` |
| `deltaaegis_core/ingest.py` | 788 | 25 | 1 | `auth` | `321d00cfeb0eee57f6fb9bdae0d50adc51e6ad5ded1325cd20a3cbd77057d7c9` |
| `deltaaegis_core/jobs.py` | 1857 | 46 | 1 | `auth` | `11ae9f4c1c16dc4c362c441ee5c1dabef0d69634a117d4added03fc9b34ee3d5` |
| `deltaaegis_core/migrations.py` | 861 | 19 | 3 | None | `8ec287329f7d17eb4cb9175ca70ed4a8627fe74e03dcc62e0acbba09a16581cd` |
| `deltaaegis_core/reports.py` | 891 | 38 | 1 | `telemetry_quality` | `687bdd1a77a785a57e5ef58b1d7f4ed4e5df43ef1e20568db19056225bb14d4f` |
| `deltaaegis_core/sites.py` | 654 | 20 | 0 | `auth`, `ingest` | `a59a9ab1fdd700ef5b1be1957e35d7e11c84c500e786fac6eafa5293b32d84ce` |
| `deltaaegis_core/telemetry_quality.py` | 2257 | 50 | 1 | None | `057a69dd2d15e0a5408925444b3051cbfe4a543782d446caef83d521a8a56ce9` |
| `deltaaegis_core/web.py` | 4918 | 22 | 0 | `api_v1`, `auth` | `5ad1207421098689da7b4089bb3f32a95a1542a1e46aa00d98051ec5638aa1d1` |

Forbidden imports of the root `deltaaegis` module from internal core modules: None detected.

## Findings and disposition

| ID | Severity | Area | Evidence | Planned disposition |
|---|---|---|---|---|
| DA044-001 | MEDIUM | compatibility facade | deltaaegis.py remains 35349 lines with 691 top-level functions; 12 core modules contain 16421 lines. | Retain the facade through v1 compatibility; continue only owned incremental extraction behind characterization evidence. |
| DA044-002 | MEDIUM | source-order coupling | Repeated top-level function names in the compatibility facade: build_current_risk_register, dashboard_asset_detail_payload, dashboard_assets_payload, dashboard_current_state_payload, dashboard_index_html, dashboard_operator_session_shell_html, dashboard_summary_payload. | Remove only with characterization evidence and explicit compatibility ownership. |
| DA044-003 | INFO | storage migrations | Stage 1 inventories 28 declared tables behind an ordered checksummed migration ledger and verified pre-migration backup. | Delivered for the supported v0.42.x origins; retain interruption, restore-rehearsal, convergence, and tamper tests in every v1 gate. |
| DA044-004 | INFO | HTTP/API contract | Stage 2 exposes 12 stable /api/v1 route literals while 61 pre-existing route literals remain private compatibility interfaces. | Delivered for the Stage 1–2 checkpoint; keep runtime, tracked OpenAPI, authorization, HTTP, and private-route transition inventories release-gated. |
| DA044-005 | LOW | validation estate | 89 validator scripts span 9 version groups; 216 historical validators are preserved by a byte-verified retirement manifest. | Retain the current compatibility floor and require manifest-backed replacement evidence for any further validator retirement. |
| DA044-006 | MEDIUM | TrueAegis compatibility | TrueAegis remains contract-validated but not pinned to a published semantic-version range. | Publish or pin the supported TrueAegis range before v1.0. |
| DA044-007 | LOW | documentation | 0 known historical architecture document marker remains. | Keep docs/architecture/overview.md authoritative and clean historical prose only in an owned documentation change. |

## Duplicate root definitions

| Name | Definition lines |
|---|---|
| `build_current_risk_register` | 16442, 34312 |
| `dashboard_asset_detail_payload` | 15543, 34287 |
| `dashboard_assets_payload` | 15423, 34261, 35330 |
| `dashboard_current_state_payload` | 15315, 34219 |
| `dashboard_index_html` | 25812, 25838, 25997, 26115, 27113 |
| `dashboard_operator_session_shell_html` | 27137, 27596, 33897 |
| `dashboard_summary_payload` | 14158, 34240 |

## Command, route, and schema catalogs

### CLI commands (67)

`access-audit`, `ack`, `alert-detail`, `alert-notes`, `alerts`, `annotate-asset`, `api-token-create`, `api-tokens`, `approve`, `asset`, `asset-annotations`, `asset-notes`, `asset-risk`, `asset-timeline`, `assets`, `backup`, `backup-catalog`, `backup-retention-execute`, `backup-retention-preview`, `backup-verify`, `dashboard`, `events`, `health`, `ingest`, `intelligence`, `intelligence-host`, `intelligence-hosts`, `investigate-asset`, `investigation-center`, `latest`, `menu`, `paths`, `port-behavior`, `report`, `restore-cutover-execute`, `restore-cutover-preview`, `restore-rehearsal`, `risk`, `scan-jobs`, `scan-start`, `schedule-create`, `schedule-delete`, `schedule-disable`, `schedule-enable`, `schedule-list`, `schedule-run-due`, `scopes`, `site-archive`, `site-assign-scope`, `site-create`, `site-description`, `site-list`, `site-remove-scope`, `site-rename`, `site-show`, `snapshots`, `summary`, `suppress`, `ticket-evidence`, `ticket-history`, `ticket-list`, `ticket-status`, `user-create`, `user-password`, `users`, `validation-ingest`, `validations`

### API route literals (73)

`/api/access-audit`, `/api/admin/users`, `/api/alerts`, `/api/annotations`, `/api/asset`, `/api/assets`, `/api/current-risk`, `/api/current-state`, `/api/events`, `/api/intelligence-host`, `/api/investigate-asset`, `/api/investigation-center`, `/api/latest-network-changes`, `/api/netsniper/hourly-monitoring`, `/api/netsniper/import-latest`, `/api/netsniper/job-detail`, `/api/netsniper/scan-cancel`, `/api/netsniper/scan-start`, `/api/netsniper/schedule-`, `/api/netsniper/schedule-create`, `/api/netsniper/schedule-delete`, `/api/netsniper/schedule-disable`, `/api/netsniper/schedule-enable`, `/api/netsniper/schedule-history`, `/api/netsniper/schedule-run-due`, `/api/netsniper/schedules`, `/api/netsniper/stale-scan-fail`, `/api/netsniper/status`, `/api/port-behavior`, `/api/risk`, `/api/scan-context`, `/api/scan-freshness`, `/api/scan-jobs`, `/api/scopes`, `/api/session`, `/api/site-archive`, `/api/site-assign-scope`, `/api/site-create`, `/api/site-description`, `/api/site-detail`, `/api/site-management`, `/api/site-remove-scope`, `/api/site-rename`, `/api/sites`, `/api/summary`, `/api/telemetry-cleanup/audit-events`, `/api/telemetry-cleanup/clear-all`, `/api/telemetry-cleanup/preview`, `/api/telemetry-quality`, `/api/telemetry-quality/detail`, `/api/telemetry-quality/override`, `/api/telemetry-quality/review`, `/api/ticket-evidence`, `/api/ticket-status`, `/api/trueaegis-jobs`, `/api/trueaegis/context`, `/api/trueaegis/run`, `/api/v1`, `/api/v1/alerts`, `/api/v1/assets`, `/api/v1/events`, `/api/v1/openapi.json`, `/api/v1/scan-jobs`, `/api/v1/scopes`, `/api/v1/session`, `/api/v1/sites`, `/api/v1/summary`, `/api/v1/telemetry-quality/decisions`, `/api/v1/validations`, `/api/validation-correlations`, `/api/validation-ingest`, `/api/validation-summary`, `/api/validations`

### Schema tables (28)

`alert_notes`, `alerts`, `api_idempotency_keys`, `asset_annotation_history`, `asset_annotations`, `asset_investigation_history`, `asset_investigations`, `asset_lifecycle`, `asset_lifecycle_scoped_migration`, `asset_observations`, `delta_events`, `finding_observations`, `investigation_ticket_history`, `investigation_ticket_state`, `logical_site_memberships`, `logical_sites`, `netsniper_intelligence_hosts`, `netsniper_intelligence_summaries`, `scan_jobs`, `scan_schedule_deletions`, `scan_schedules`, `schema_migrations`, `service_observations`, `snapshots`, `trueaegis_jobs`, `validation_correlations`, `validation_observations`, `validation_runs`

## Validator inventory

| Version group | Scripts |
|---|---:|
| unversioned | 2 |
| v0.39 | 15 |
| v0.40 | 11 |
| v0.41 | 9 |
| v0.42 | 15 |
| v0.43 | 1 |
| v0.44 | 17 |
| v0.45 | 13 |
| v1.0 | 6 |

## Validator retirement evidence

- Manifest: `docs/v0.44.1-validator-retirement.json`
- Archive tag: `v0.44.0`
- Retired tool files: 219
- Retired validator scripts: 216
- Retained validator scripts: 68
- Retained shell-validator inventory: 51
- Replacement report contract: `tools/validate_v0_44_1_report_contracts.py`
- Policy: `docs/validation-retention-policy.md`

## Stale and historical documents

No known stale architecture-document marker was found.

## v1 delivery map

| Stage | Status | Owned work |
|---|---|---|
| Stage 1 | Delivered in this checkpoint | Forward migrations, exact supported origins, verified backup, interruption recovery, and restore rehearsal |
| Stage 2 | Delivered in this checkpoint | `/api/v1`, OpenAPI 3.1, scoped tokens, CSRF, security headers, request bounds, and durable idempotency |
| Stage 3 | Deferred | Sensor/scope identity, evidence provenance, replay protection, and overlapping CIDRs |
| Stage 4 | Deferred | Versioned deterministic detection rules and explainable results |
| Later v1 gates | Deferred | Health/readiness, structured operations, low-resource and performance evidence, pinned TrueAegis compatibility, and final blocker audit |

## Audit constraints

- The audit is read-only except when explicitly writing its deterministic Markdown report.
- Counts use Git cached and non-ignored untracked candidate files and exclude runtime data roots and the generated report.
- The v1 Stage 1–2 checkpoint adds checksummed forward migrations, verified recovery evidence, and the stable authenticated /api/v1 contract while preserving released v0.45 telemetry trust and v0.44 modular compatibility.
- This audit is checkpoint evidence and does not declare v1.0 GA; every remaining V1_SCOPE.md definition-of-done item still applies.
- Historical validator retirement is allowed only when exact prior bytes remain verified at an immutable release tag, current behavior has replacement-contract evidence, and the retained execution graph is complete.
