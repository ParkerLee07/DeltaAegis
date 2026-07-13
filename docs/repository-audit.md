# DeltaAegis v0.43 Repository Audit

Schema: `deltaaegis-repository-audit-v1`

This is a deterministic, read-only inventory of the v0.43.0 release candidate and its architecture-baseline artifacts. Regenerate it with `python3 tools/audit_v0_43_repository.py --write`.

## Inventory summary

| Measure | Count |
|---|---:|
| Repository files in audit scope | 318 |
| `deltaaegis.py` lines | 42553 |
| Top-level functions | 661 |
| Top-level classes | 8 |
| Distinct CLI commands | 67 |
| Distinct `/api` route literals | 57 |
| Declared schema tables | 30 |
| Validator scripts | 266 |
| Validator version groups | 39 |

Source SHA-256: `02cd1262710a856675950da710febac3f3ef71c38f1884fb4f60f6f1ad8b0420`

## Findings and disposition

| ID | Severity | Area | Evidence | Planned disposition |
|---|---|---|---|---|
| DA043-001 | HIGH | module boundaries | deltaaegis.py has 42553 lines and 661 top-level functions. | Map and incrementally extract responsibilities in v0.44; do not perform a broad v0.43 rewrite. |
| DA043-002 | HIGH | source-order coupling | Repeated top-level function names: dashboard_assets_payload, dashboard_index_html, dashboard_operator_session_shell_html. | Preserve behavior with characterization tests, then remove late overrides during owned v0.44 extractions. |
| DA043-003 | MEDIUM | storage ownership | 30 table names are declared from the monolithic source bootstrap/migration path. | Introduce the migration ledger in v0.45 after the v0.44 database boundary is extracted. |
| DA043-004 | MEDIUM | HTTP/API ownership | 57 distinct /api route literals occur in the application source. | Inventory current routes now; introduce the stable /api/v1 contract in v0.46. |
| DA043-005 | MEDIUM | validation estate | 266 validator scripts span 39 version groups. | Record contract ownership before retiring any validator; the v0.43 gate must compose focused validators exactly once. |
| DA043-006 | MEDIUM | documentation | 1 known stale current-architecture document was identified. | Use docs/architecture/overview.md as current authority and reconcile historical prose during v0.44. |
| DA043-007 | MEDIUM | TrueAegis compatibility | TrueAegis is enforced by an execution/output contract but has no pinned semantic-version range in the current repository. | Publish or pin a TrueAegis semantic version and fixture contract before DeltaAegis v1.0. |

## Duplicate top-level definitions

| Name | Definition lines |
|---|---|
| `dashboard_assets_payload` | 19704, 42534 |
| `dashboard_index_html` | 30112, 30138, 30297, 30415, 31413 |
| `dashboard_operator_session_shell_html` | 31437, 31575, 32069 |

These definitions are classified as source-order coupling. The audit does not assume that the earlier definitions are unreachable or safe to delete.

## Command, route, and schema catalogs

### CLI commands (67)

`access-audit`, `ack`, `alert-detail`, `alert-notes`, `alerts`, `annotate-asset`, `api-token-create`, `api-tokens`, `approve`, `asset`, `asset-annotations`, `asset-notes`, `asset-risk`, `asset-timeline`, `assets`, `backup`, `backup-catalog`, `backup-retention-execute`, `backup-retention-preview`, `backup-verify`, `dashboard`, `events`, `health`, `ingest`, `intelligence`, `intelligence-host`, `intelligence-hosts`, `investigate-asset`, `investigation-center`, `latest`, `menu`, `paths`, `port-behavior`, `report`, `restore-cutover-execute`, `restore-cutover-preview`, `restore-rehearsal`, `risk`, `scan-jobs`, `scan-start`, `schedule-create`, `schedule-delete`, `schedule-disable`, `schedule-enable`, `schedule-list`, `schedule-run-due`, `scopes`, `site-archive`, `site-assign-scope`, `site-create`, `site-description`, `site-list`, `site-remove-scope`, `site-rename`, `site-show`, `snapshots`, `summary`, `suppress`, `ticket-evidence`, `ticket-history`, `ticket-list`, `ticket-status`, `user-create`, `user-password`, `users`, `validation-ingest`, `validations`

### API route literals (57)

`/api/access-audit`, `/api/admin/users`, `/api/alerts`, `/api/annotations`, `/api/asset`, `/api/assets`, `/api/current-risk`, `/api/current-state`, `/api/events`, `/api/intelligence-host`, `/api/investigate-asset`, `/api/investigation-center`, `/api/latest-network-changes`, `/api/netsniper/hourly-monitoring`, `/api/netsniper/import-latest`, `/api/netsniper/job-detail`, `/api/netsniper/scan-cancel`, `/api/netsniper/scan-start`, `/api/netsniper/schedule-`, `/api/netsniper/schedule-create`, `/api/netsniper/schedule-delete`, `/api/netsniper/schedule-disable`, `/api/netsniper/schedule-enable`, `/api/netsniper/schedule-history`, `/api/netsniper/schedule-run-due`, `/api/netsniper/schedules`, `/api/netsniper/stale-scan-fail`, `/api/netsniper/status`, `/api/port-behavior`, `/api/risk`, `/api/scan-context`, `/api/scan-freshness`, `/api/scan-jobs`, `/api/scopes`, `/api/session`, `/api/site-archive`, `/api/site-assign-scope`, `/api/site-create`, `/api/site-description`, `/api/site-detail`, `/api/site-management`, `/api/site-remove-scope`, `/api/site-rename`, `/api/sites`, `/api/summary`, `/api/telemetry-cleanup/audit-events`, `/api/telemetry-cleanup/clear-all`, `/api/telemetry-cleanup/preview`, `/api/ticket-evidence`, `/api/ticket-status`, `/api/trueaegis-jobs`, `/api/trueaegis/context`, `/api/trueaegis/run`, `/api/validation-correlations`, `/api/validation-ingest`, `/api/validation-summary`, `/api/validations`

### Schema tables (30)

`access_api_tokens`, `access_audit_log`, `access_sessions`, `access_users`, `alert_notes`, `alerts`, `asset_annotation_history`, `asset_annotations`, `asset_investigation_history`, `asset_investigations`, `asset_lifecycle`, `asset_lifecycle_scoped_migration`, `asset_observations`, `delta_events`, `finding_observations`, `investigation_ticket_history`, `investigation_ticket_state`, `logical_site_memberships`, `logical_sites`, `netsniper_intelligence_hosts`, `netsniper_intelligence_summaries`, `scan_jobs`, `scan_schedule_deletions`, `scan_schedules`, `service_observations`, `snapshots`, `trueaegis_jobs`, `validation_correlations`, `validation_observations`, `validation_runs`

## Validator inventory

| Version group | Scripts |
|---|---:|
| unversioned | 1 |
| v0.10 | 3 |
| v0.11 | 4 |
| v0.12 | 5 |
| v0.13 | 5 |
| v0.14 | 5 |
| v0.15 | 5 |
| v0.16 | 5 |
| v0.17 | 6 |
| v0.18 | 6 |
| v0.19 | 5 |
| v0.20 | 6 |
| v0.21 | 5 |
| v0.22 | 6 |
| v0.23 | 7 |
| v0.24 | 6 |
| v0.25 | 6 |
| v0.26 | 8 |
| v0.27 | 8 |
| v0.28 | 9 |
| v0.29 | 5 |
| v0.30 | 4 |
| v0.31 | 10 |
| v0.32 | 4 |
| v0.33 | 5 |
| v0.34 | 9 |
| v0.35 | 5 |
| v0.36 | 6 |
| v0.37 | 9 |
| v0.38 | 9 |
| v0.39 | 18 |
| v0.40 | 13 |
| v0.41 | 12 |
| v0.42 | 18 |
| v0.43 | 6 |
| v0.44 | 2 |
| v0.7 | 3 |
| v0.8 | 11 |
| v0.9 | 6 |

## Stale and historical documents

| Path | Evidence | Disposition |
|---|---|---|
| `docs/architecture.md` | Historical v0.8.5 architecture narrative; superseded as the current map by docs/architecture/overview.md. | Retain as historical context until v0.44 decides whether to archive or merge it. |

## Dependency surface

Top-level Python imports: `__future__`, `argparse`, `collections`, `dataclasses`, `datetime`, `deltaaegis_core`, `hashlib`, `hmac`, `html`, `ipaddress`, `json`, `os`, `pathlib`, `re`, `secrets`, `signal`, `sqlite3`, `subprocess`, `sys`, `tempfile`, `threading`, `time`, `typing`, `urllib`, `uuid`, `xml`

The runtime remains standard-library based. NetSniper, TrueAegis, Node.js, Git, browsers, and supported platform expectations are defined in `SUPPORTED_VERSIONS.md`.

## Deferred work map

| Release | Owned work from this audit |
|---|---|
| v0.44 | Incremental module extraction and removal of characterized source-order overrides |
| v0.45 | Migration ledger, supported upgrades, and backup-integrated recovery |
| v0.46 | `/api/v1`, OpenAPI, CSRF, sessions/tokens, and web security headers |
| v0.47 | Sensor/scope identity and overlapping CIDRs |
| v0.48 | Versioned deterministic detection rules |
| v0.49 | Health/readiness, diagnostics, performance targets, failure tests, and soak |

## Audit constraints

- No runtime source or database schema is changed by this audit.
- Counts use Git cached and non-ignored untracked candidate files, excluding runtime data roots and this generated report.
- A finding is architecture debt unless a focused defect reproduction proves otherwise.
- No historical validator is removed without replacement-contract evidence.
