# DeltaAegis v1.0 Stage 1 — Supported upgrades and recovery

Status: implemented and release-gated in the combined Stage 1–2 candidate. This document does not declare the complete v1.0 product ready for GA.

## Supported database origins

Stage 1 accepts a fresh local SQLite database, a valid database already carrying the v1 migration ledger, or an exact supported v0.42–v0.45 schema. The immutable v0.42 sources used by the upgrade gate are:

| Origin | Commit | `deltaaegis.py` SHA-256 |
|---|---|---|
| v0.42.0 | `5c78e0c764e5c5352a68d3e78b8f3fa79b1128ba` | `986212b74db632e39b4ff2edf5e8b5cb0605276ab1a09655d3ea9eddc1addfad` |
| v0.42.1 | `dce4897e335a3d6978a6e3c0d6da54a194ade158` | `5458a1399dda7c973388ec846dd9a7c9eef403c7f038ba20a7393735d015e725` |
| v0.42.2 | `cc8d099604083ae75f1bad595d53fd2b23433941` | `09e8ef6b7eae6a9431de3daf8c859cfa84d77026d92191ba04bdeb96aa7448d4` |

Those three releases and the clean v0.45 database have the same schema fingerprint, `781be13dec43b657c383c9c7a217c3df83040319cbb8469d1d175667edf63b32`. SQLite therefore cannot prove which patch executable originally created an unledgered database. The ledger records the honest shared origin `v0.42.0-v0.45.0-identical-base-schema`; the validator separately proves every immutable tag source and upgrade path.

The published v0.45.0 release commit is `493df20dabed527757381e3cbae7cad3201b9c57` with tree `ab2c059806e0bbd3908f32200d79cb357e8fa61c`. The validator prefers that published commit when it is present. A disposable checkout may instead use witness `74cba5ec5aa3d35cd57416c3891c161d8bf5fd4b`, but only after proving that it has the same released tree. The released `deltaaegis.py` SHA-256 is `e277bfeed6e5422d567c5207d14b6bc9a43c5fc8486f95be9c0b73d8c5706c12`. The validator builds both a clean database and a telemetry-runtime-expanded database (schema `7b15660af4a2a6f442b1c6dc7c9fceaee962c998cd0ad7754bb3ed6051be654`) from those released bytes before upgrading them.

An incomplete, unknown, extra-table, or definition-drifted unledgered schema fails closed. The active database must be a regular local path, not a symlink or a known network filesystem.

## Ordered migration ledger

`schema_migrations` records:

- a unique ordered migration ID;
- a SHA-256 checksum bound to the migration description, declared material, and apply/validation implementation;
- the UTC application timestamp and application version;
- the recognized source origin; and
- deterministic JSON outcome evidence, including schema fingerprints and the verified pre-migration backup for the first applied migration.

Migration checksums bind the migration functions, declared SQL and constants, and the source of every helper that can change migration output. Historical migration definitions and their bound helpers are immutable; a later storage change must append a new migration rather than rewrite these definitions.

The combined candidate contains three forward migrations:

1. `0001-v045-foundation` converges the supported v0.42–v0.45 foundation.
2. `0002-v045-telemetry-trust` materializes telemetry quality, current-state projection, and NetSniper intelligence storage.
3. `0003-v1-api-security` adds bounded token scopes, session CSRF state, and durable API mutation idempotency.

Unknown IDs, gaps, changed checksums, malformed timestamps, inconsistent origins, broken schema-fingerprint chains, live-schema drift, or altered outcome evidence stop startup. There is no reverse-SQL downgrade.

## Safety order

For a database with pending migrations, DeltaAegis:

1. acquires a SQLite `BEGIN IMMEDIATE` write reservation;
2. recognizes the database and validates any existing ledger;
3. fingerprints protected evidence and operator history;
4. creates a SQLite-consistent backup with the established DeltaAegis manifest;
5. verifies the backup checksum, integrity, schema, and logical fingerprint;
6. applies one migration and its ledger row in the same transaction;
7. validates foreign keys, SQLite integrity, postconditions, and protected-history fingerprints; and
8. commits before advancing to the next migration.

Concurrent starters serialize at the write reservation. A fresh database does not create an unnecessary pre-migration backup. Reopening a completed database is idempotent and creates no additional backup.

The default database uses the configured `backups/` directory. A custom database path uses a sibling `migration-backups/` directory so its recovery artifact remains near the operator-selected database without writing into NetSniper or TrueAegis.

## Interruption and recovery

The Stage 1 validator injects failures after backup creation and before/after apply, ledger insertion, and commit boundaries for the first two migrations. Before-commit interruptions leave no partial migration or ledger row. An interruption immediately after commit leaves the complete migration and ledger row, and the next startup safely resumes at the following ID.

Recovery is restore-based:

```bash
python3 deltaaegis.py --db data/deltaaegis.db backup-verify \
  --backup backups/deltaaegis-pre-migration-...db \
  --manifest backups/deltaaegis-pre-migration-...db.manifest.json

python3 deltaaegis.py --db data/deltaaegis.db restore-rehearsal \
  --backup backups/deltaaegis-pre-migration-...db \
  --manifest backups/deltaaegis-pre-migration-...db.manifest.json
```

Use the existing guarded restore-cutover preview and execute workflow only after the rehearsal succeeds. Never replace an active SQLite database with a live file copy and never delete WAL/journal sidecars to force an upgrade.

## Validation

Run the dedicated Stage 1 gate:

```bash
python3 tools/validate_v1_stage1_migrations.py
```

It creates only temporary databases and validates exact v0.42.0, v0.42.1, and v0.42.2 origins, clean-install convergence, backup verification, restore rehearsal, protected-history retention, interruption recovery, concurrent startup, foreign keys, integrity, idempotence, and fail-closed ledger behavior.
