# ADR 0007: Make verified backup the recovery boundary

- Status: Accepted
- Date: 2026-07-13
- Applies to: backup, restore, and migration lifecycle

## Context

DeltaAegis v0.41 established consistent backups, manifests, checksums, catalogs, restore rehearsals, retention, and guarded cutover. Schema migration work must reuse those controls rather than create an independent copy mechanism.

## Decision

The SQLite backup API and the DeltaAegis backup manifest remain the only supported active-database backup boundary. A backup is usable only after checksum, SQLite integrity, foreign-key, identity, and sidecar policy validation.

Every upgrade with pending migrations creates and verifies a pre-migration backup. Restore rehearsal always targets a separate database. Active cutover requires a fresh preview digest, exact confirmation, a safety backup of the current database, confined paths, and rollback evidence.

## Consequences

- File-copy-only instructions for a live database are unsupported.
- Migration rollback restores a verified database rather than attempting reverse SQL.
- Release gates exercise backup creation, verification, rehearsal, cutover blockers, and external-database preservation.
- Backup retention never deletes an unverified or outside-root artifact implicitly.
