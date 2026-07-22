# ADR 0008: Define compatibility at explicit contracts

- Status: Implemented through the v1 Stage 3–5 candidate
- Date: 2026-07-13
- Applies to: DeltaAegis, NetSniper, TrueAegis, and release gates

## Context

Historical validators preserve valuable behavior, but version-number accumulation alone does not explain which compatibility promises remain public. DeltaAegis also depends on sensor and validation evidence owned by separate projects.

## Decision

Compatibility is defined at four explicit boundaries: supported database upgrade origins, `/api/v1`, NetSniper finalized-bundle schemas, and TrueAegis validation schemas. Each boundary has fixtures, an owning document/ADR, and a release-gate entry.

DeltaAegis v1.0 supports upgrades from all v0.42.x databases. NetSniper is pinned to v2.1.0 commit `0624a36550f6eb62ed0daa6862e5cc25a0d93236`; legacy v2.0 evidence remains positive-only degraded-compatible. TrueAegis is optional and pinned to `>=1.2.0,<2.0.0`, the `trueaegis-validation-results-v1` array contract, and witness commit `16b9e88b232aac568859ab8d68e2eaa26558c4e7`.

Historical validators may be retired only when an inventory maps their protected contract to an equal or stronger current validator. Deletion based solely on age or filename is prohibited.

## Consequences

- The v0.43 audit records validator ownership and duplication candidates.
- Clean-clone release gates compose each owned validator once.
- Unsupported input fails closed with actionable evidence rather than best-effort guessing.
- Compatibility exceptions require an ADR or documented security emergency.
