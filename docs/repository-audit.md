# DeltaAegis v0.44.1 Repository Audit

Schema: `deltaaegis-repository-audit-v2`

This deterministic inventory describes the v0.44.1 Repository Hygiene and Validation Retention maintenance candidate. Regenerate it with `python3 tools/audit_v0_44_repository.py --write`.

## Inventory summary

| Measure | Count |
|---|---:|
| Repository files in audit scope | 148 |
| `deltaaegis.py` lines | 33843 |
| Root top-level functions | 661 |
| Root top-level classes | 6 |
| Internal core modules | 8 |
| Distinct CLI commands | 67 |
| Distinct `/api` route literals | 57 |
| Declared schema tables | 26 |
| Validator scripts | 84 |
| Validator version groups | 6 |

Root source SHA-256: `c8e51cda413b1c3601906fd58365c8cc8d7cede81535a6eeb7f187becb554fff`

## Modular core inventory

| Module | Lines | Functions | Classes | Internal dependencies | SHA-256 |
|---|---:|---:|---:|---|---|
| `deltaaegis_core/auth.py` | 1234 | 40 | 2 | None | `a219c97ce1b73744567866959fb61365202bb36d81697d1d39eda553c702e11f` |
| `deltaaegis_core/config.py` | 76 | 1 | 1 | None | `5155b29f0cf665989722b235e58104f9d39276bedbf6f4fbf9ffe2888e8719cb` |
| `deltaaegis_core/db.py` | 25 | 1 | 0 | None | `8637f696f78a861a2d2f1ea00e5e671a1f5dd239659fcb99eb16b6c9154e3488` |
| `deltaaegis_core/ingest.py` | 788 | 25 | 1 | `auth` | `321d00cfeb0eee57f6fb9bdae0d50adc51e6ad5ded1325cd20a3cbd77057d7c9` |
| `deltaaegis_core/jobs.py` | 1857 | 46 | 1 | `auth` | `11ae9f4c1c16dc4c362c441ee5c1dabef0d69634a117d4added03fc9b34ee3d5` |
| `deltaaegis_core/reports.py` | 796 | 37 | 1 | None | `26b5ddf1e2f93261f510dccb3b76636f5e860fc8b71974d7921edf5a83301e90` |
| `deltaaegis_core/sites.py` | 654 | 20 | 0 | `auth`, `ingest` | `a59a9ab1fdd700ef5b1be1957e35d7e11c84c500e786fac6eafa5293b32d84ce` |
| `deltaaegis_core/web.py` | 3736 | 15 | 0 | `auth` | `530eaf29168581e64a3499610cd6b1e65a8879e793871b3fcbb7c260649de0e6` |

Forbidden imports of the root `deltaaegis` module from internal core modules: None detected.

## Findings and disposition

| ID | Severity | Area | Evidence | Planned disposition |
|---|---|---|---|---|
| DA044-001 | MEDIUM | compatibility facade | deltaaegis.py remains 33843 lines with 661 top-level functions; the eight core modules contain 9166 lines. | Retain the facade through the planned migration/API releases; continue only owned incremental extraction. |
| DA044-002 | MEDIUM | source-order coupling | Repeated top-level function names in the compatibility facade: dashboard_assets_payload, dashboard_index_html, dashboard_operator_session_shell_html. | Remove only with characterization evidence and explicit compatibility ownership. |
| DA044-003 | MEDIUM | storage migrations | 26 table names remain declared through the root-owned schema bootstrap. | Introduce the forward-only migration ledger and supported upgrade paths in v0.45. |
| DA044-004 | MEDIUM | HTTP/API contract | 57 unversioned /api route literals remain implementation endpoints. | Introduce /api/v1, OpenAPI, CSRF, and deprecation policy implementation in v0.46. |
| DA044-005 | LOW | validation estate | 84 validator scripts span 6 version groups; 200 historical validators are preserved by a byte-verified retirement manifest. | Retain the current compatibility floor and require manifest-backed replacement evidence for any further validator retirement. |
| DA044-006 | MEDIUM | TrueAegis compatibility | TrueAegis remains contract-validated but not pinned to a published semantic-version range. | Publish or pin the supported TrueAegis range before v1.0. |
| DA044-007 | LOW | documentation | 0 known historical architecture document marker remains. | Keep docs/architecture/overview.md authoritative and clean historical prose only in an owned documentation change. |

## Duplicate root definitions

| Name | Definition lines |
|---|---|
| `dashboard_assets_payload` | 14592, 33824 |
| `dashboard_index_html` | 24979, 25005, 25164, 25282, 26280 |
| `dashboard_operator_session_shell_html` | 26304, 26763 |

## Command, route, and schema catalogs

### CLI commands (67)

`access-audit`, `ack`, `alert-detail`, `alert-notes`, `alerts`, `annotate-asset`, `api-token-create`, `api-tokens`, `approve`, `asset`, `asset-annotations`, `asset-notes`, `asset-risk`, `asset-timeline`, `assets`, `backup`, `backup-catalog`, `backup-retention-execute`, `backup-retention-preview`, `backup-verify`, `dashboard`, `events`, `health`, `ingest`, `intelligence`, `intelligence-host`, `intelligence-hosts`, `investigate-asset`, `investigation-center`, `latest`, `menu`, `paths`, `port-behavior`, `report`, `restore-cutover-execute`, `restore-cutover-preview`, `restore-rehearsal`, `risk`, `scan-jobs`, `scan-start`, `schedule-create`, `schedule-delete`, `schedule-disable`, `schedule-enable`, `schedule-list`, `schedule-run-due`, `scopes`, `site-archive`, `site-assign-scope`, `site-create`, `site-description`, `site-list`, `site-remove-scope`, `site-rename`, `site-show`, `snapshots`, `summary`, `suppress`, `ticket-evidence`, `ticket-history`, `ticket-list`, `ticket-status`, `user-create`, `user-password`, `users`, `validation-ingest`, `validations`

### API route literals (57)

`/api/access-audit`, `/api/admin/users`, `/api/alerts`, `/api/annotations`, `/api/asset`, `/api/assets`, `/api/current-risk`, `/api/current-state`, `/api/events`, `/api/intelligence-host`, `/api/investigate-asset`, `/api/investigation-center`, `/api/latest-network-changes`, `/api/netsniper/hourly-monitoring`, `/api/netsniper/import-latest`, `/api/netsniper/job-detail`, `/api/netsniper/scan-cancel`, `/api/netsniper/scan-start`, `/api/netsniper/schedule-`, `/api/netsniper/schedule-create`, `/api/netsniper/schedule-delete`, `/api/netsniper/schedule-disable`, `/api/netsniper/schedule-enable`, `/api/netsniper/schedule-history`, `/api/netsniper/schedule-run-due`, `/api/netsniper/schedules`, `/api/netsniper/stale-scan-fail`, `/api/netsniper/status`, `/api/port-behavior`, `/api/risk`, `/api/scan-context`, `/api/scan-freshness`, `/api/scan-jobs`, `/api/scopes`, `/api/session`, `/api/site-archive`, `/api/site-assign-scope`, `/api/site-create`, `/api/site-description`, `/api/site-detail`, `/api/site-management`, `/api/site-remove-scope`, `/api/site-rename`, `/api/sites`, `/api/summary`, `/api/telemetry-cleanup/audit-events`, `/api/telemetry-cleanup/clear-all`, `/api/telemetry-cleanup/preview`, `/api/ticket-evidence`, `/api/ticket-status`, `/api/trueaegis-jobs`, `/api/trueaegis/context`, `/api/trueaegis/run`, `/api/validation-correlations`, `/api/validation-ingest`, `/api/validation-summary`, `/api/validations`

### Schema tables (26)

`alert_notes`, `alerts`, `asset_annotation_history`, `asset_annotations`, `asset_investigation_history`, `asset_investigations`, `asset_lifecycle`, `asset_lifecycle_scoped_migration`, `asset_observations`, `delta_events`, `finding_observations`, `investigation_ticket_history`, `investigation_ticket_state`, `logical_site_memberships`, `logical_sites`, `netsniper_intelligence_hosts`, `netsniper_intelligence_summaries`, `scan_jobs`, `scan_schedule_deletions`, `scan_schedules`, `service_observations`, `snapshots`, `trueaegis_jobs`, `validation_correlations`, `validation_observations`, `validation_runs`

## Validator inventory

| Version group | Scripts |
|---|---:|
| v0.39 | 15 |
| v0.40 | 13 |
| v0.41 | 12 |
| v0.42 | 18 |
| v0.43 | 6 |
| v0.44 | 20 |

## Validator retirement evidence

- Manifest: `docs/v0.44.1-validator-retirement.json`
- Archive tag: `v0.44.0`
- Retired tool files: 201
- Retired validator scripts: 200
- Retained validator scripts: 84
- Retained shell-validator inventory: 62
- Replacement report contract: `tools/validate_v0_44_1_report_contracts.py`
- Policy: `docs/validation-retention-policy.md`

## Stale and historical documents

No known stale architecture-document marker was found.

## Deferred work map

| Release | Owned work after v0.44 |
|---|---|
| v0.45 | Migration ledger, supported upgrades, and backup-integrated recovery |
| v0.46 | `/api/v1`, OpenAPI, CSRF, sessions/tokens, and web security headers |
| v0.47 | Sensor/scope identity and overlapping CIDRs |
| v0.48 | Versioned deterministic detection rules |
| v0.49 | Health/readiness, diagnostics, performance targets, failure tests, and soak |

## Audit constraints

- The audit is read-only except when explicitly writing its deterministic Markdown report.
- Counts use Git cached and non-ignored untracked candidate files and exclude runtime data roots and the generated report.
- v0.44.1 retains the v0.44 module boundaries and introduces no database-schema or stable-API change.
- Historical validator retirement is allowed only when exact prior bytes remain verified at an immutable release tag, current behavior has replacement-contract evidence, and the retained execution graph is complete.
