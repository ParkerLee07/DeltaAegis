# ADR 0011: Replayable telemetry-trust current-state projection

- Status: Accepted for DeltaAegis v0.45
- Date: 2026-07-17

## Context

DeltaAegis historically treated the latest `ACCEPTED` snapshot as both the
immutable evidence record and operational current state. The v0.45 policy adds
`DEGRADED` telemetry that is safe for positive evidence but unsafe for absence
semantics. A single latest-snapshot model cannot combine those guarantees
without either discarding useful observations or allowing degraded evidence to
remove state.

## Decision

Keep snapshot and observation tables as immutable historical evidence and add a
replayable current-state projection keyed by network scope and asset identity.

- `ACCEPTED` evidence may replace projected positive state and may apply absence
  effects only when the quality decision proves negative-evidence coverage.
- `DEGRADED` evidence is additive/refresh-only.
- `QUARANTINED` and `REJECTED` evidence never enter the projection.
- A reviewed-state change rebuilds the affected scope and lifecycle state from
  the latest legacy accepted seed plus retained v0.45 decisions.
- Automated decisions remain immutable and reviewed state is stored separately.
- Positive-evidence provenance is retained per asset, service, and finding;
  accepted support is not inferred from the parent asset for new degraded
  records.
- Run identifiers are content-bound across legacy snapshots and v0.45 decisions;
  unverifiable or conflicting reuse fails closed.

## Consequences

This adds storage and replay complexity, but makes the policy enforceable,
auditable, and reversible. Historical evidence remains stable. Current-state
queries gain explicit source-quality provenance. Degraded-only risk is capped at
`MEDIUM` while accepted evidence can independently support higher risk.

## Compatibility initialization rule

The v0.45 ledger and projection schemas are lazy feature migrations. Ordinary
connection startup retains the v0.44 characterized table inventory; the first
telemetry-trust operation initializes the additive tables and seeds the legacy
accepted projection transactionally.
