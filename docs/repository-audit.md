# DeltaAegis v1.0 Stage 3–5 Repository Audit

Schema: `deltaaegis-repository-audit-v3`

This deterministic inventory describes the combined v1.0 Stage 3–5 candidate, including the preserved Stage 1–2 foundation, based on released v0.45.0. Regenerate it with `python3 tools/audit_v0_44_repository.py --write`.

## Inventory summary

| Measure | Count |
|---|---:|
| Repository files in audit scope | 191 |
| `deltaaegis.py` lines | 35953 |
| Root top-level functions | 703 |
| Root top-level classes | 6 |
| Internal core modules | 15 |
| Distinct CLI commands | 74 |
| Distinct `/api` route literals | 78 |
| Declared schema tables | 47 |
| Validator scripts | 92 |
| Validator version groups | 9 |

Root source SHA-256: `98cce99544475ce15ccf8962e6de56c87738061f622a4af77011fcbce24df527`

## Modular core inventory

| Module | Lines | Functions | Classes | Internal dependencies | SHA-256 |
|---|---:|---:|---:|---|---|
| `deltaaegis_core/api_v1.py` | 1140 | 19 | 2 | None | `55eea2a8e1c8ad4f0c687fd5c890ef0ac86a09172be0497dea4c2b94ad3cdebe` |
| `deltaaegis_core/auth.py` | 1547 | 52 | 2 | None | `7b35209e7bcd15dd82d5763b8f70198c6ae03811e9a731a5e4f308a1f851c7c1` |
| `deltaaegis_core/config.py` | 80 | 1 | 1 | None | `0860bf7e2b193aa22c4ad41f69f3f3f4a2f3360c3635052ef7fe1959d1f17217` |
| `deltaaegis_core/current_state.py` | 1578 | 34 | 0 | None | `731dbc2f93f348dea37dafb305637118608e4b5d602f0d41c7d911b3544276cd` |
| `deltaaegis_core/db.py` | 25 | 1 | 0 | None | `8637f696f78a861a2d2f1ea00e5e671a1f5dd239659fcb99eb16b6c9154e3488` |
| `deltaaegis_core/detection.py` | 580 | 13 | 1 | None | `25ceb17bde445deb70c6fe5fa0d65918b0408a9b1b98c8ac099b541f0e2b48b4` |
| `deltaaegis_core/identity.py` | 1653 | 36 | 1 | None | `b7b8d68a8f24a4c16ac4e6cc09d3f0c9b108593386f4647596d030cabff0bc24` |
| `deltaaegis_core/ingest.py` | 788 | 25 | 1 | `auth` | `321d00cfeb0eee57f6fb9bdae0d50adc51e6ad5ded1325cd20a3cbd77057d7c9` |
| `deltaaegis_core/jobs.py` | 2002 | 46 | 1 | `auth`, `identity` | `f06bc0bd9387012d6ff005d02014746991964fc4b93844b292720c8a28c8340f` |
| `deltaaegis_core/migrations.py` | 861 | 19 | 3 | None | `8ec287329f7d17eb4cb9175ca70ed4a8627fe74e03dcc62e0acbba09a16581cd` |
| `deltaaegis_core/operations.py` | 461 | 14 | 1 | `detection`, `identity` | `f3107852b099f3ac97e03d924de31e13c861e2ab486e29f473fff388bdb9ab29` |
| `deltaaegis_core/reports.py` | 891 | 38 | 1 | `telemetry_quality` | `687bdd1a77a785a57e5ef58b1d7f4ed4e5df43ef1e20568db19056225bb14d4f` |
| `deltaaegis_core/sites.py` | 700 | 20 | 0 | `auth`, `identity`, `ingest` | `f9f9c1c74675cd7abee76e5c074f74d8e662e31d02dafc3bf35bb87312d741f1` |
| `deltaaegis_core/telemetry_quality.py` | 2257 | 50 | 1 | None | `057a69dd2d15e0a5408925444b3051cbfe4a543782d446caef83d521a8a56ce9` |
| `deltaaegis_core/web.py` | 5085 | 22 | 0 | `api_v1`, `auth`, `detection`, `identity`, `operations` | `5e499ca14708867f2c8f652b6a44715eb6f22c298968ab9d551a48ca53210599` |

Forbidden imports of the root `deltaaegis` module from internal core modules: None detected.

## Findings and disposition

| ID | Severity | Area | Evidence | Planned disposition |
|---|---|---|---|---|
| DA044-001 | MEDIUM | compatibility facade | deltaaegis.py remains 35953 lines with 703 top-level functions; 15 core modules contain 19648 lines. | Retain the facade through v1 compatibility; continue only owned incremental extraction behind characterization evidence. |
| DA044-002 | MEDIUM | source-order coupling | Repeated top-level function names in the compatibility facade: build_current_risk_register, dashboard_asset_detail_payload, dashboard_assets_payload, dashboard_current_state_payload, dashboard_index_html, dashboard_operator_session_shell_html, dashboard_summary_payload. | Remove only with characterization evidence and explicit compatibility ownership. |
| DA044-003 | INFO | storage migrations | Stage 1 inventories 47 declared tables behind an ordered checksummed migration ledger and verified pre-migration backup. | Delivered for the supported v0.42.x origins; retain interruption, restore-rehearsal, convergence, and tamper tests in every v1 gate. |
| DA044-004 | INFO | HTTP/API contract | Stages 2–5 expose 17 stable /api/v1 route literals while 61 pre-existing route literals remain private compatibility interfaces. | Delivered through the Stage 3–5 candidate; keep runtime, tracked OpenAPI, authorization, HTTP, and private-route transition inventories release-gated. |
| DA044-005 | LOW | validation estate | 92 validator scripts span 9 version groups; 216 historical validators are preserved by a byte-verified retirement manifest. | Retain the current compatibility floor and require manifest-backed replacement evidence for any further validator retirement. |
| DA044-006 | INFO | integration compatibility | NetSniper is pinned to v2.1.0 commit 0624a36550f6eb62ed0daa6862e5cc25a0d93236; optional TrueAegis is pinned to >=1.2.0,<2.0.0, a witness commit, and a fixture-validated result contract. | Retain exact pins, fixtures, scope-containment tests, and fail-closed integration readiness in every v1 gate. |
| DA044-007 | LOW | documentation | 0 known historical architecture document marker remains. | Keep docs/architecture/overview.md authoritative and clean historical prose only in an owned documentation change. |

## Duplicate root definitions

| Name | Definition lines |
|---|---|
| `build_current_risk_register` | 16901, 34869 |
| `dashboard_asset_detail_payload` | 16002, 34844 |
| `dashboard_assets_payload` | 15882, 34818, 35934 |
| `dashboard_current_state_payload` | 15774, 34776 |
| `dashboard_index_html` | 26271, 26297, 26456, 26574, 27572 |
| `dashboard_operator_session_shell_html` | 27596, 28055, 34454 |
| `dashboard_summary_payload` | 14584, 34797 |

## Command, route, and schema catalogs

### CLI commands (74)

`access-audit`, `ack`, `alert-detail`, `alert-notes`, `alerts`, `annotate-asset`, `api-token-create`, `api-tokens`, `approve`, `asset`, `asset-annotations`, `asset-notes`, `asset-risk`, `asset-timeline`, `assets`, `backup`, `backup-catalog`, `backup-retention-execute`, `backup-retention-preview`, `backup-verify`, `dashboard`, `detection-review`, `detections`, `diagnostics`, `events`, `health`, `ingest`, `intelligence`, `intelligence-host`, `intelligence-hosts`, `investigate-asset`, `investigation-center`, `latest`, `menu`, `paths`, `port-behavior`, `readiness`, `report`, `restore-cutover-execute`, `restore-cutover-preview`, `restore-rehearsal`, `risk`, `scan-jobs`, `scan-start`, `schedule-create`, `schedule-delete`, `schedule-disable`, `schedule-enable`, `schedule-list`, `schedule-run-due`, `scopes`, `scopes-v1`, `sensor-enroll`, `sensors-v1`, `site-archive`, `site-assign-scope`, `site-create`, `site-description`, `site-list`, `site-remove-scope`, `site-rename`, `site-show`, `snapshots`, `summary`, `suppress`, `ticket-evidence`, `ticket-history`, `ticket-list`, `ticket-status`, `user-create`, `user-password`, `users`, `validation-ingest`, `validations`

### API route literals (78)

`/api/access-audit`, `/api/admin/users`, `/api/alerts`, `/api/annotations`, `/api/asset`, `/api/assets`, `/api/current-risk`, `/api/current-state`, `/api/events`, `/api/intelligence-host`, `/api/investigate-asset`, `/api/investigation-center`, `/api/latest-network-changes`, `/api/netsniper/hourly-monitoring`, `/api/netsniper/import-latest`, `/api/netsniper/job-detail`, `/api/netsniper/scan-cancel`, `/api/netsniper/scan-start`, `/api/netsniper/schedule-`, `/api/netsniper/schedule-create`, `/api/netsniper/schedule-delete`, `/api/netsniper/schedule-disable`, `/api/netsniper/schedule-enable`, `/api/netsniper/schedule-history`, `/api/netsniper/schedule-run-due`, `/api/netsniper/schedules`, `/api/netsniper/stale-scan-fail`, `/api/netsniper/status`, `/api/port-behavior`, `/api/risk`, `/api/scan-context`, `/api/scan-freshness`, `/api/scan-jobs`, `/api/scopes`, `/api/session`, `/api/site-archive`, `/api/site-assign-scope`, `/api/site-create`, `/api/site-description`, `/api/site-detail`, `/api/site-management`, `/api/site-remove-scope`, `/api/site-rename`, `/api/sites`, `/api/summary`, `/api/telemetry-cleanup/audit-events`, `/api/telemetry-cleanup/clear-all`, `/api/telemetry-cleanup/preview`, `/api/telemetry-quality`, `/api/telemetry-quality/detail`, `/api/telemetry-quality/override`, `/api/telemetry-quality/review`, `/api/ticket-evidence`, `/api/ticket-status`, `/api/trueaegis-jobs`, `/api/trueaegis/context`, `/api/trueaegis/run`, `/api/v1`, `/api/v1/alerts`, `/api/v1/assets`, `/api/v1/detections`, `/api/v1/diagnostics`, `/api/v1/events`, `/api/v1/health`, `/api/v1/openapi.json`, `/api/v1/readiness`, `/api/v1/scan-jobs`, `/api/v1/scopes`, `/api/v1/sensors`, `/api/v1/session`, `/api/v1/sites`, `/api/v1/summary`, `/api/v1/telemetry-quality/decisions`, `/api/v1/validations`, `/api/validation-correlations`, `/api/validation-ingest`, `/api/validation-summary`, `/api/validations`

### Schema tables (47)

`access_api_tokens`, `access_audit_log`, `access_sessions`, `access_users`, `alert_notes`, `alerts`, `api_idempotency_keys`, `asset_annotation_history`, `asset_annotations`, `asset_investigation_history`, `asset_investigations`, `asset_lifecycle`, `asset_lifecycle_scoped_migration`, `asset_observations`, `delta_events`, `detection_results`, `detection_reviews`, `finding_observations`, `identity_current_assets`, `identity_current_findings`, `identity_current_services`, `identity_evidence_receipts`, `identity_scope_heads`, `identity_scopes`, `identity_sensors`, `identity_site_memberships`, `investigation_ticket_history`, `investigation_ticket_state`, `logical_site_memberships`, `logical_sites`, `netsniper_intelligence_hosts`, `netsniper_intelligence_summaries`, `scan_jobs`, `scan_schedule_deletions`, `scan_schedules`, `schema_migrations`, `service_observations`, `snapshots`, `telemetry_current_assets`, `telemetry_current_findings`, `telemetry_current_services`, `telemetry_quality_decisions`, `telemetry_quality_reviews`, `trueaegis_jobs`, `validation_correlations`, `validation_observations`, `validation_runs`

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
| v1.0 | 9 |

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
| Stage 1 | Preserved and release-gated | Forward migrations, exact supported origins, verified backup, interruption recovery, and restore rehearsal |
| Stage 2 | Preserved and release-gated | `/api/v1`, OpenAPI 3.1, scoped tokens, CSRF, security headers, request bounds, and durable idempotency |
| Stage 3 | Implemented and candidate-gated | Sensor/scope identity, evidence provenance, replay protection, per-sensor concurrency, and overlapping CIDRs |
| Stage 4 | Implemented and candidate-gated | Versioned deterministic immutable detections, explanations, replay, and separate reviews |
| Stage 5 | Implementation gate passed; GA soak pending | Health/readiness, diagnostics, low-resource and performance evidence, pinned integrations, and soak harness |
| Final GA gate | Pending external-duration evidence | 24-hour release-evidence soak and final blocker audit |

## Audit constraints

- The audit is read-only except when explicitly writing its deterministic Markdown report.
- Counts use Git cached and non-ignored untracked candidate files and exclude runtime data roots and the generated report.
- The v1 candidate preserves Stage 1–2 migrations, recovery, stable API, and security while adding sensor/scope isolation, immutable detection, operational readiness, performance thresholds, and pinned integrations.
- This audit is candidate evidence and does not declare v1.0 GA; the mandatory 24-hour soak and final blocker review still apply.
- Historical validator retirement is allowed only when exact prior bytes remain verified at an immutable release tag, current behavior has replacement-contract evidence, and the retained execution graph is complete.
