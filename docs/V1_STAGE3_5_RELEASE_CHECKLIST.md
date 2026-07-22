# DeltaAegis v1.0 combined Stage 3–5 checklist

This checklist covers the combined implementation upgrade. It does not by
itself authorize a `v1.0.0` tag; the 24-hour soak and final blocker audit are
separate mandatory evidence.

## Baseline and migration

- [ ] Candidate is based on exact Stage 1–2 tree `e259130de5e54c6673a5e294c88244f6b0ab4048`.
- [ ] Stage 1 migration tests still cover every supported v0.42.x and v0.45 origin.
- [ ] Migration checksums 0001–0003 remain unchanged.
- [ ] Migration 0004 and 0005 apply once, validate, and converge on fresh and upgraded databases.
- [ ] Protected history, quick check, foreign keys, backup, restore, and interruption tests pass.

## Stage 3 — identity and provenance

- [ ] Legacy rows receive explicit default sensor and deterministic/unassigned scope identity.
- [ ] Managed sensor enrollment rejects unknown, inactive, malformed, or unscoped evidence.
- [ ] Equal CIDRs under two sensors produce different scope and internal scan identities.
- [ ] Exact duplicate evidence is idempotent; conflicting digest reuse fails closed.
- [ ] Older evidence cannot roll the current scope head backward.
- [ ] Assets, services, findings, jobs, schedules, validations, and correlations retain sensor/scope provenance.
- [ ] TrueAegis hosts outside the assigned scope fail closed.
- [ ] One active scan per sensor is transactional; two different sensors may scan concurrently.

## Stage 4 — deterministic detection

- [ ] Tracked and runtime rulesets are identical.
- [ ] Result IDs replay exactly for identical canonical evidence.
- [ ] Rule/schema versions, scope, scan, decision, bundle digest, evidence digest, and explanation are present.
- [ ] Result and review update/delete attempts fail.
- [ ] Review, suppression, and unsuppression append separate authenticated history.
- [ ] Stable list/detail/review endpoints enforce scopes and idempotency.

## Stage 5 — operations and compatibility

- [ ] Public liveness reveals no database or integration detail.
- [ ] Authenticated readiness covers migrations, SQLite, workers, identity, detection, integration configuration, and capacity.
- [ ] Diagnostics are bounded and secret-redacted.
- [ ] Missing NetSniper, read-only database, malformed TrueAegis evidence, and low-cache fixtures behave fail-closed.
- [ ] NetSniper and TrueAegis tracked pins equal runtime contracts.
- [ ] Synthetic performance receipt passes every v0.43-derived threshold.
- [ ] Install, reinstall, uninstall, runtime purge, and external database preservation pass with all new modules.

## Candidate gate

```bash
./tools/validate_v1_0_stage3_5_gate.sh
```

- [ ] Combined gate completes within 600 seconds.
- [ ] Deterministic repository audit matches.
- [ ] Validation does not mutate source or Git state.
- [ ] Exact diff, receipt, and backup are reviewed before any live application.

## GA evidence still required

- [ ] A 24-hour run of `run_v1_stage5_soak.py --release-evidence` completes without interruption.
- [ ] Soak receipt reports zero integrity, readiness, and unplanned worker failures.
- [ ] Supported-platform evidence is recorded honestly; untested platforms are not claimed.
- [ ] Final audit finds no open security, integrity, migration, data-loss, or authorization blocker.
- [ ] Merge, tag, release, or branch deletion occurs only under separate explicit authorization.
