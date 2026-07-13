# ADR 0002: Use forward-only transactional schema migrations

- Status: Accepted
- Date: 2026-07-13
- Applies to: migration framework introduced in v0.45

## Context

The current `connect` path combines initial schema creation with many additive compatibility checks. It is effective for the historical v0.x series but does not provide a durable ordered record of which transformations ran. v1.0 requires an upgrade path from v0.42.x and interruption-safe recovery.

## Decision

DeltaAegis will introduce a `schema_migrations` ledger containing a unique migration identifier, checksum, application timestamp, application version, and outcome evidence. Migrations are ordered, forward-only, idempotence-aware, and transactional wherever SQLite permits.

Before the first pending migration, DeltaAegis creates and verifies a SQLite-consistent backup. A migration validates preconditions, applies one bounded transformation, validates postconditions and foreign keys, then commits its ledger row. Changed migration bytes with an already-recorded identifier fail closed.

There is no automated schema downgrade. Rollback restores the verified pre-migration backup using the existing guarded restore boundary.

## Consequences

- Legacy additive helpers remain compatibility inputs until encoded migrations supersede them.
- Fresh installs and upgrades must converge on the same schema.
- Every migration needs fresh, predecessor, interruption, idempotence, and recovery fixtures.
- Destructive cleanup is deferred until retained data and supported upgrade paths are proven safe.
