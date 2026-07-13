# ADR 0001: SQLite remains the authoritative v1.0 store

- Status: Accepted
- Date: 2026-07-13
- Applies to: v0.43 planning baseline through v1.0

## Context

DeltaAegis is a self-hosted single-node application with tightly related evidence, workflow, job, authentication, and audit records. SQLite already provides transactional behavior, foreign keys, consistent backup APIs, and simple operator ownership. Replacing it before v1.0 would expand deployment and recovery risk without advancing the defined product scope.

## Decision

SQLite remains the sole authoritative database through v1.0. The active database is a local filesystem file opened through one owned connection policy. DeltaAegis enables foreign keys, uses explicit transactions for invariants, treats WAL/journal sidecars as part of safety checks, and never supports an active database on a network filesystem.

Raw sensor artifacts remain immutable files referenced by normalized database records. The database does not become an arbitrary blob archive, and filesystem evidence is not accepted as authoritative without its manifest/checksum contract.

## Consequences

- v0.44 may move storage code into modules but may not replace SQLite.
- v0.45 introduces a migration ledger and upgrade lifecycle within SQLite.
- Multi-process writers and high-availability clustering remain unsupported.
- A future database backend requires a new major-version ADR and migration strategy.
