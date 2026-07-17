# DeltaAegis v0.44.1 Repository Audit

Schema: `deltaaegis-repository-audit-v2`

This deterministic inventory describes the v0.44.1 Repository Hygiene and Validation Retention maintenance candidate. Regenerate it with `python3 tools/audit_v0_44_repository.py --write`.

## Inventory summary

| Measure | Count |
|---|---:|
| Repository files in audit scope | 154 |
| `deltaaegis.py` lines | 34692 |
| Root top-level functions | 677 |
| Root top-level classes | 6 |
| Internal core modules | 10 |
| Distinct CLI commands | 67 |
| Distinct `/api` route literals | 61 |
| Declared schema tables | 26 |
| Validator scripts | 78 |
| Validator version groups | 7 |

Root source SHA-256: `d77ee27801d45f1bec1a38c74872bdf5db1b620456e84472017b73fd8f451c3a`

## Modular core inventory

| Module | Lines | Functions | Classes | Internal dependencies | SHA-256 |
|---|---:|---:|---:|---|---|
| `deltaaegis_core/auth.py` | 1241 | 40 | 2 | None | `5bc0931d6d764172ae7a6dd7dba1e4398019ae7bc4f2761b7fe9f7d908c1d451` |
| `deltaaegis_core/config.py` | 80 | 1 | 1 | None | `0860bf7e2b193aa22c4ad41f69f3f3f4a2f3360c3635052ef7fe1959d1f17217` |
| `deltaaegis_core/current_state.py` | 1506 | 32 | 0 | None | `e67e9ff0380b9b0a4a68c2fd8fc8f90d1facc83798f7790e576429b0756cf433` |
| `deltaaegis_core/db.py` | 25 | 1 | 0 | None | `8637f696f78a861a2d2f1ea00e5e671a1f5dd239659fcb99eb16b6c9154e3488` |
| `deltaaegis_core/ingest.py` | 788 | 25 | 1 | `auth` | `321d00cfeb0eee57f6fb9bdae0d50adc51e6ad5ded1325cd20a3cbd77057d7c9` |
| `deltaaegis_core/jobs.py` | 1857 | 46 | 1 | `auth` | `11ae9f4c1c16dc4c362c441ee5c1dabef0d69634a117d4added03fc9b34ee3d5` |
| `deltaaegis_core/reports.py` | 891 | 38 | 1 | None | `687bdd1a77a785a57e5ef58b1d7f4ed4e5df43ef1e20568db19056225bb14d4f` |
| `deltaaegis_core/sites.py` | 654 | 20 | 0 | `auth`, `ingest` | `a59a9ab1fdd700ef5b1be1957e35d7e11c84c500e786fac6eafa5293b32d84ce` |
| `deltaaegis_core/telemetry_quality.py` | 1897 | 40 | 1 | None | `a192a0455dfb5c24f3733c528bdf17b066d28546964ee3e75fb42089f3e599a5` |
| `deltaaegis_core/web.py` | 3886 | 15 | 0 | `auth` | `d67257473e6faba0d53c2dedbc4b5965e1810ea5956a63d30aed28217751d9d6` |

Forbidden imports of the root `deltaaegis` module from internal core modules: None detected.

## Findings and disposition

| ID | Severity | Area | Evidence | Planned disposition |
|---|---|---|---|---|
| DA044-001 | MEDIUM | compatibility facade | deltaaegis.py remains 34692 lines with 677 top-level functions; the eight core modules contain 12825 lines. | Retain the facade through the planned migration/API releases; continue only owned incremental extraction. |
| DA044-002 | MEDIUM | source-order coupling | Repeated top-level function names in the compatibility facade: build_current_risk_register, dashboard_asset_detail_payload, dashboard_assets_payload, dashboard_current_state_payload, dashboard_index_html, dashboard_operator_session_shell_html, dashboard_summary_payload. | Remove only with characterization evidence and explicit compatibility ownership. |
| DA044-003 | MEDIUM | storage migrations | 26 table names remain declared through the root-owned schema bootstrap. | Introduce the forward-only migration ledger and supported upgrade paths in v0.45. |
| DA044-004 | MEDIUM | HTTP/API contract | 61 unversioned /api route literals remain implementation endpoints. | Introduce /api/v1, OpenAPI, CSRF, and deprecation policy implementation in v0.46. |
| DA044-005 | LOW | validation estate | 78 validator scripts span 7 version groups; 216 historical validators are preserved by a byte-verified retirement manifest. | Retain the current compatibility floor and require manifest-backed replacement evidence for any further validator retirement. |
| DA044-006 | MEDIUM | TrueAegis compatibility | TrueAegis remains contract-validated but not pinned to a published semantic-version range. | Publish or pin the supported TrueAegis range before v1.0. |
| DA044-007 | LOW | documentation | 0 known historical architecture document marker remains. | Keep docs/architecture/overview.md authoritative and clean historical prose only in an owned documentation change. |

## Duplicate root definitions

| Name | Definition lines |
|---|---|
| `build_current_risk_register` | 15875, 33680 |
| `dashboard_asset_detail_payload` | 14976, 33655 |
| `dashboard_assets_payload` | 14856, 33629, 34673 |
| `dashboard_current_state_payload` | 14748, 33587 |
| `dashboard_index_html` | 25243, 25269, 25428, 25546, 26544 |
| `dashboard_operator_session_shell_html` | 26568, 27027, 33328 |
| `dashboard_summary_payload` | 13591, 33608 |

## Command, route, and schema catalogs

### CLI commands (67)

`access-audit`, `ack`, `alert-detail`, `alert-notes`, `alerts`, `annotate-asset`, `api-token-create`, `api-tokens`, `approve`, `asset`, `asset-annotations`, `asset-notes`, `asset-risk`, `asset-timeline`, `assets`, `backup`, `backup-catalog`, `backup-retention-execute`, `backup-retention-preview`, `backup-verify`, `dashboard`, `events`, `health`, `ingest`, `intelligence`, `intelligence-host`, `intelligence-hosts`, `investigate-asset`, `investigation-center`, `latest`, `menu`, `paths`, `port-behavior`, `report`, `restore-cutover-execute`, `restore-cutover-preview`, `restore-rehearsal`, `risk`, `scan-jobs`, `scan-start`, `schedule-create`, `schedule-delete`, `schedule-disable`, `schedule-enable`, `schedule-list`, `schedule-run-due`, `scopes`, `site-archive`, `site-assign-scope`, `site-create`, `site-description`, `site-list`, `site-remove-scope`, `site-rename`, `site-show`, `snapshots`, `summary`, `suppress`, `ticket-evidence`, `ticket-history`, `ticket-list`, `ticket-status`, `user-create`, `user-password`, `users`, `validation-ingest`, `validations`

### API route literals (61)

`/api/access-audit`, `/api/admin/users`, `/api/alerts`, `/api/annotations`, `/api/asset`, `/api/assets`, `/api/current-risk`, `/api/current-state`, `/api/events`, `/api/intelligence-host`, `/api/investigate-asset`, `/api/investigation-center`, `/api/latest-network-changes`, `/api/netsniper/hourly-monitoring`, `/api/netsniper/import-latest`, `/api/netsniper/job-detail`, `/api/netsniper/scan-cancel`, `/api/netsniper/scan-start`, `/api/netsniper/schedule-`, `/api/netsniper/schedule-create`, `/api/netsniper/schedule-delete`, `/api/netsniper/schedule-disable`, `/api/netsniper/schedule-enable`, `/api/netsniper/schedule-history`, `/api/netsniper/schedule-run-due`, `/api/netsniper/schedules`, `/api/netsniper/stale-scan-fail`, `/api/netsniper/status`, `/api/port-behavior`, `/api/risk`, `/api/scan-context`, `/api/scan-freshness`, `/api/scan-jobs`, `/api/scopes`, `/api/session`, `/api/site-archive`, `/api/site-assign-scope`, `/api/site-create`, `/api/site-description`, `/api/site-detail`, `/api/site-management`, `/api/site-remove-scope`, `/api/site-rename`, `/api/sites`, `/api/summary`, `/api/telemetry-cleanup/audit-events`, `/api/telemetry-cleanup/clear-all`, `/api/telemetry-cleanup/preview`, `/api/telemetry-quality`, `/api/telemetry-quality/detail`, `/api/telemetry-quality/override`, `/api/telemetry-quality/review`, `/api/ticket-evidence`, `/api/ticket-status`, `/api/trueaegis-jobs`, `/api/trueaegis/context`, `/api/trueaegis/run`, `/api/validation-correlations`, `/api/validation-ingest`, `/api/validation-summary`, `/api/validations`

### Schema tables (26)

`alert_notes`, `alerts`, `asset_annotation_history`, `asset_annotations`, `asset_investigation_history`, `asset_investigations`, `asset_lifecycle`, `asset_lifecycle_scoped_migration`, `asset_observations`, `delta_events`, `finding_observations`, `investigation_ticket_history`, `investigation_ticket_state`, `logical_site_memberships`, `logical_sites`, `netsniper_intelligence_hosts`, `netsniper_intelligence_summaries`, `scan_jobs`, `scan_schedule_deletions`, `scan_schedules`, `service_observations`, `snapshots`, `trueaegis_jobs`, `validation_correlations`, `validation_observations`, `validation_runs`

## Validator inventory

| Version group | Scripts |
|---|---:|
| v0.39 | 15 |
| v0.40 | 11 |
| v0.41 | 9 |
| v0.42 | 15 |
| v0.43 | 1 |
| v0.44 | 17 |
| v0.45 | 10 |

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
