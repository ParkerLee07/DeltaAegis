# DeltaAegis v0.41.0 — Data Durability & Recovery

DeltaAegis v0.41.0 adds an operator-controlled durability and recovery lifecycle for the local SQLite evidence store. The release emphasizes verifiable state, explicit planning, no-overwrite behavior, exact confirmation, rollback, and preservation of recovery evidence.

## Highlights

### SQLite-consistent backup bundles

`deltaaegis backup` uses the SQLite backup API against a read-only source connection. Backups are created through secure temporary files, checked with SQLite integrity validation, and published without overwriting an existing destination.

Every successful backup publishes a `deltaaegis-backup-manifest-v1` sidecar containing:

- SHA-256 checksum and byte size.
- SQLite application, page, user, and schema version metadata.
- Schema fingerprint.
- DeltaAegis version and creation time.

A bundle is not considered complete unless both the database and manifest are published.

### Verification, catalog, and restore rehearsal

`backup-catalog` classifies top-level bundles as `VALID`, `INVALID`, or `INCOMPLETE`. `backup-verify` performs full bundle verification.

`restore-rehearsal` verifies the selected bundle and restores it into a separate non-active database. The restored copy must match the backup’s integrity status, schema fingerprint, and logical fingerprint. The active database is never modified during rehearsal.

### Guarded retention

`backup-retention-preview` is read-only. It keeps the newest verified bundles, keeps bundles younger than the configured minimum age, marks older verified bundles eligible, and protects anything invalid, incomplete, malformed, future-dated, or tied to the active database.

`backup-retention-execute` requires the exact phrase:

```text
DELETE ELIGIBLE BACKUP BUNDLES
```

Execution recomputes the plan, re-verifies every eligible bundle, checks file identity, quarantines with hard links, performs identity-aware deletion, restores files when a later step fails, and emits a structured receipt.

### Active restore cutover planning

`restore-cutover-preview` verifies the restore bundle and checks:

- The active database and its parent directory.
- Backup, manifest, and active-database file identities.
- Running DeltaAegis dashboard processes using the active database.
- SQLite WAL, SHM, and journal sidecars.
- The required safety-backup directory.
- Restore checksums, integrity, schema, and logical fingerprint.

The preview is non-destructive and returns a stable SHA-256 plan digest. Active-database content inspection is skipped when sidecars are present so the preview does not alter SQLite runtime state.

### Guarded active restore and rollback

`restore-cutover-execute` requires both the preview digest and the exact phrase:

```text
RESTORE ACTIVE DELTAAEGIS DATABASE
```

Execution:

1. Recomputes and matches the preview plan.
2. Creates and verifies a fresh pre-restore safety backup.
3. Rechecks active, backup, manifest, process, and sidecar state.
4. Restores and verifies a temporary database in the active data directory.
5. Creates a rollback hard link to the original active database.
6. Atomically replaces the active database.
7. Verifies the new active database.
8. Automatically restores and verifies the original database if post-cutover verification fails.

The safety backup is retained after success or rollback. Structured receipts record completion, rollback, retained recovery paths, verification evidence, and review requirements.

## Database path policy

The default active database remains:

```text
data/deltaaegis.db
```

Ignored root-level `deltaaegis.db` files are treated as legacy local state. DeltaAegis does not select, delete, or migrate them automatically. Use `--db` explicitly to operate on a non-default database.

## Security boundaries

- No arbitrary shell command execution is added.
- Existing dashboard processes must be stopped by the operator before active restore.
- SQLite sidecar blockers cannot be bypassed.
- Backup checksums, identities, schema fingerprints, logical fingerprints, and plan digests are fail-closed.
- Retention and active restore require exact confirmation phrases.
- Existing destinations are not silently overwritten by backup or rehearsal workflows.
- Production databases and existing backup bundles are not used by automated destructive tests.

## Validation

Run the complete clean-tree release gate:

```bash
./tools/validate_v0_41_release_gate.sh
```

Complete `MANUAL_VERIFICATION_v0.41.0.md` before merge, tag, or publication.
