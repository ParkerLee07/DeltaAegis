# ADR 0009: Use semantic versioning and bounded deprecation

- Status: Accepted
- Date: 2026-07-13
- Applies to: release policy through and after v1.0

## Context

The pre-1.0 series has evolved quickly while preserving extensive predecessor behavior. v1.0 needs a predictable rule for storage, API, identity, integration, and operator-facing compatibility without preventing urgent security corrections.

## Decision

Before v1.0, minor releases may implement the approved roadmap and patch releases remain backward-compatible maintenance. Every supported upgrade origin and breaking pre-1.0 contract change is documented explicitly.

At v1.0, DeltaAegis adopts semantic versioning for the public API, supported storage/upgrade path, sensor/validation contracts, and documented CLI automation. An incompatible change to those contracts requires a major release.

A normal deprecation is announced in the cumulative CHANGELOG and relevant reference documentation, emits a machine-visible or operator-visible notice where practical, identifies its replacement, and remains available for at least two minor releases and normally 180 days. The longer period controls. Security, data-integrity, or legal necessity may require faster removal; the reason and migration action must be documented.

## Consequences

- Internal HTML, private helpers, and unversioned implementation endpoints are not public merely because they are visible in source.
- Patch releases cannot silently remove supported behavior.
- The release gate checks deprecation metadata for removed stable contracts.
- Maintainers may fix an unsafe interface immediately but must provide the safest practical migration path.
