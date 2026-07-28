# DeltaAegis v1.0.1 Maintenance Release checklist

This checklist records the completed v1.0.0 implementation, retained
qualification evidence, and the v1.0.1 dashboard-lock maintenance release. It does not replace the requirement for separate explicit
authorization of tag creation, GitHub Release publication, or branch deletion.

## Baseline and migration

- [x] Release is based on the exact preserved Stage 1–2 tree `e259130de5e54c6673a5e294c88244f6b0ab4048`.
- [x] Stage 1 migration tests cover every supported v0.42.x origin plus clean, telemetry-expanded, and exact historical-additive v0.45 origins.
- [x] Migration checksums 0001–0003 remain unchanged.
- [x] Migrations 0004 and 0005 apply once, validate, and converge on fresh and upgraded schema contracts.
- [x] Protected history, quick check, foreign keys, backup, restore, interruption, and concurrency tests pass.

## Stage 3 — identity and provenance

- [x] Legacy rows receive explicit default sensor and deterministic or unassigned scope identity.
- [x] Managed sensor enrollment rejects unknown, inactive, malformed, or unscoped evidence.
- [x] Equal CIDRs under two sensors produce different scope and internal scan identities.
- [x] Exact duplicate evidence is idempotent and conflicting digest reuse fails closed.
- [x] Older evidence cannot roll the current scope head backward.
- [x] Assets, services, findings, jobs, schedules, validations, and correlations retain sensor and scope provenance.
- [x] TrueAegis hosts outside the assigned scope fail closed.
- [x] One active scan per sensor is transactional while different sensors may scan concurrently.

## Stage 4 — deterministic detection

- [x] Tracked and runtime rulesets are identical.
- [x] Result IDs replay exactly for identical canonical evidence.
- [x] Rule/schema versions, scope, scan, decision, bundle digest, evidence digest, and explanation are present.
- [x] Result and review update or delete attempts fail.
- [x] Review, suppression, and unsuppression append separate authenticated history.
- [x] Stable list, detail, and review endpoints enforce scopes and idempotency.

## Stage 5 — operations and compatibility

- [x] Public liveness reveals no database or integration detail.
- [x] Authenticated readiness covers migrations, SQLite, workers, identity, detection, integrations, and capacity.
- [x] Diagnostics are bounded and secret-redacted.
- [x] Missing NetSniper, read-only database, malformed TrueAegis evidence, and low-cache fixtures fail closed.
- [x] NetSniper and TrueAegis tracked pins equal runtime contracts.
- [x] Synthetic performance evidence passes every v0.43-derived threshold.
- [x] Install, reinstall, uninstall, runtime purge, and external database preservation pass with all v1 modules.

## v1.0.1 dashboard-lock maintenance

- [x] Runtime and background-worker connections do not invoke forward migrations.
- [x] Forward migrations execute once before the threaded dashboard starts.
- [x] Eight runtime opens invoke zero migration calls.
- [x] 32 concurrent runtime reads succeed while another connection holds `BEGIN IMMEDIATE`.
- [x] 48 concurrent live dashboard requests succeed under the same reserved writer.
- [x] Dashboard logs contain no `database is locked` error or traceback.
- [x] `/favicon.ico` returns public HTTP 204 without database access.
- [x] Pull request #9 merged validated hotfix `b0dbe7e45346253bc18df7eb063bf9866b25e44c` as exact main commit `836b2ac25e27c344f292e2a9cacbe0a4f757fe1f`.
- [x] Exact-main CI run `30393445773` passed the complete release gate.
- [x] Schema, migration checksums, stable API, detection, evidence, and integration contracts remain unchanged.
- [x] The retained v1.0.0 24-hour soak and supported matrix remain applicable baseline evidence.
- [x] No additional 24-hour soak is required for this focused maintenance correction.

## Release gate

```bash
./tools/validate_v1_0_stage3_5_gate.sh
```

- [x] Complete gate finishes within the 600-second limit.
- [x] Deterministic repository audit matches.
- [x] Validation does not mutate source or Git state.
- [x] Release metadata identifies v1.0.1 and preserves the historical v1.0.0 record.

## Completed GA evidence

- [x] The uninterrupted 24-hour release-evidence soak completed on 2026-07-24 with 1,431 samples.
- [x] The soak reported zero integrity, readiness, and unplanned-worker failures.
- [x] Final blocker review found no open release-blocking category.
- [x] Main CI run `30290071519` passed the complete gate.
- [x] Release-matrix run `30291887915` attempt 2 passed all eight required jobs.
- [x] Pull request #7 merged the validated runtime candidate at `338f6ed44e9db330fd7f67f3242fd682fab11fab`.
- [x] Post-soak CI and metadata corrections preserved every runtime and operational Git object.
- [x] Merge, metadata finalization, tag creation, release publication, and branch deletion each require their own explicit authorization.
