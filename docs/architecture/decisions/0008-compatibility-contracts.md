# ADR 0008: Define compatibility at explicit contracts

- Status: Accepted
- Date: 2026-07-13
- Applies to: DeltaAegis, NetSniper, TrueAegis, and release gates

## Context

Historical validators preserve valuable behavior, but version-number accumulation alone does not explain which compatibility promises remain public. DeltaAegis also depends on sensor and validation evidence owned by separate projects.

## Decision

Compatibility is defined at four explicit boundaries: supported database upgrade origins, `/api/v1`, NetSniper finalized-bundle schemas, and TrueAegis validation schemas. Each boundary has fixtures, an owning document/ADR, and a release-gate entry.

DeltaAegis v1.0 supports upgrades from all v0.42.x databases. NetSniper v2.0.0 remains the sensor baseline through DeltaAegis v0.46; v2.1.0 introduces sensor identity with compatibility aliases. TrueAegis remains contract-pinned until it publishes a semantic version required before v1.0.

Historical validators may be retired only when an inventory maps their protected contract to an equal or stronger current validator. Deletion based solely on age or filename is prohibited.

## Consequences

- The v0.43 audit records validator ownership and duplication candidates.
- Clean-clone release gates compose each owned validator once.
- Unsupported input fails closed with actionable evidence rather than best-effort guessing.
- Compatibility exceptions require an ADR or documented security emergency.
