# DeltaAegis v0.41.0 Manual Verification

**Release:** Data Durability & Recovery
**Publication status:** **HOLD — do not push, merge, tag, or publish until this checklist is completed and Parker explicitly approves publication.**

Use disposable databases and backup directories for destructive verification. Do not test active restore against the normal production database.

## Paths and legacy database state

- [ ] Run `deltaaegis paths` and confirm the default active database is `data/deltaaegis.db`.
- [ ] Confirm any ignored root-level `deltaaegis.db` is not selected automatically.
- [ ] Confirm the root-level database is not tracked by Git.
- [ ] Do not delete or migrate the root-level database as part of this release unless separately reviewed.

## Backup creation and manifests

- [ ] Create a backup from a disposable active database.
- [ ] Confirm the backup and `<backup>.manifest.json` are both created.
- [ ] Confirm an existing destination is not overwritten.
- [ ] Confirm the manifest records v0.41.0, SHA-256, size, SQLite metadata, and schema fingerprint.
- [ ] Confirm an invalid or empty source fails without publishing a partial bundle.

## Catalog and verification

- [ ] Run `backup-catalog` against a disposable directory containing valid, invalid, incomplete, and unrelated files.
- [ ] Confirm valid bundles report `VALID`.
- [ ] Confirm tampered bundles report `INVALID`.
- [ ] Confirm one-sided database or manifest entries report `INCOMPLETE`.
- [ ] Confirm unrelated files and nested historical directories are ignored.
- [ ] Run `backup-verify` for one valid and one tampered bundle.

## Restore rehearsal

- [ ] Rehearse a restore into a disposable non-active destination.
- [ ] Confirm the restored database matches integrity, schema, and logical fingerprints.
- [ ] Confirm the active database is unchanged.
- [ ] Confirm existing, symlink, active-database, and hard-link-alias destinations are rejected.

## Retention preview

- [ ] Build a disposable backup set with different ages.
- [ ] Confirm newest and young valid bundles are `KEEP`.
- [ ] Confirm old valid bundles outside the keep window are `ELIGIBLE`.
- [ ] Confirm invalid, incomplete, malformed, future-dated, and active-database aliases are `PROTECTED`.
- [ ] Confirm preview modifies no files.

## Retention execution

- [ ] Confirm any phrase other than `DELETE ELIGIBLE BACKUP BUNDLES` is rejected without changes.
- [ ] Execute retention against disposable bundles.
- [ ] Confirm only freshly verified `ELIGIBLE` bundles are deleted.
- [ ] Confirm `KEEP` and `PROTECTED` bundles remain.
- [ ] Confirm changed candidates are preserved and reported for review.
- [ ] Confirm no quarantine residue remains after successful execution.
- [ ] Review the structured receipt and plan digest.

## Active restore preview

- [ ] Generate a blocker-free preview using disposable active and restore databases.
- [ ] Confirm the plan reports `dry_run: true`, `destructive: false`, and `execution_supported: false`.
- [ ] Confirm the backup is `VALID` and a SHA-256 plan digest is present.
- [ ] Start a disposable DeltaAegis dashboard against the test database and confirm preview reports `DASHBOARD_PROCESS_ACTIVE`.
- [ ] Add a disposable `-wal`, `-shm`, or `-journal` file and confirm preview reports `SQLITE_SIDECARS_PRESENT`.
- [ ] Confirm active-database content inspection is skipped while a sidecar exists.
- [ ] Confirm preview leaves all test files byte-for-byte unchanged.

## Active restore execution and rollback

- [ ] Confirm an incorrect confirmation phrase is rejected without changes.
- [ ] Confirm an incorrect or stale plan digest is rejected without changes.
- [ ] Execute a disposable cutover with `RESTORE ACTIVE DELTAAEGIS DATABASE`.
- [ ] Confirm a fresh safety backup and manifest are retained.
- [ ] Confirm the active database contains the selected restore data.
- [ ] Confirm the original restore backup and manifest are unchanged.
- [ ] Confirm no temporary restore or rollback path remains after success.
- [ ] Trigger a controlled post-cutover verification failure only in a disposable test fixture.
- [ ] Confirm the original active database is automatically restored and verified.
- [ ] Confirm the receipt reports `ROLLED_BACK`, `rollback_attempted`, and `rollback_completed`.

## Regression and operator workflow

- [ ] Confirm the dashboard loads normally after restarting against the normal active database.
- [ ] Confirm authentication, RBAC, NetSniper orchestration, TrueAegis orchestration, investigation actions, and telemetry cleanup remain available.
- [ ] Confirm the dashboard release badge identifies v0.41 Data Durability & Recovery.
- [ ] Confirm `deltaaegis --help` identifies v0.41.0.

## Final local checks

- [ ] Run `./tools/validate_v0_41_release_gate.sh` from a clean tree.
- [ ] Run `python3 -W error::SyntaxWarning -m py_compile deltaaegis.py`.
- [ ] Run `git diff --check`.
- [ ] Confirm `git status --short` is empty.
- [ ] Review `README.md`, `CHANGELOG.md`, and `RELEASE_NOTES_v0.41.0.md`.
- [ ] Review the complete feature-branch diff against the v0.41 baseline.

## Approval and publication hold

- [ ] Parker approves the backup, retention, rehearsal, and restore behavior.
- [ ] Parker approves the release notes and manual verification results.
- [ ] Parker explicitly authorizes pushing the feature branch to GitHub.
- [ ] Only after explicit approval: push the feature branch.
- [ ] Only after explicit approval: merge into `main`.
- [ ] Run the clean release gate again on merged `main`.
- [ ] Only after the merged gate passes and Parker approves: create and push tag `v0.41.0`.
- [ ] Only after tag verification and Parker approves: publish the GitHub release.

## Publication Verification Record

**Recorded:** 2026-07-08T15:05:22Z
**Release candidate:** `2c136f5b93925cdb8f1858a8cf59c6140e1dcca4`
**Decision:** APPROVED FOR PUBLICATION

The following checks were completed manually before publication:

- Confirmed the release-candidate branch, commit, and clean working tree.
- Confirmed the configured active database remains
  `data/deltaaegis.db`.
- Confirmed the ignored legacy root database is untracked and has a
  different file identity from the active database.
- Confirmed all eight v0.41 durability and recovery commands are exposed
  through the CLI.
- Confirmed empty catalog and retention previews are non-destructive.
- Confirmed missing backups, incorrect confirmation phrases, symlinked
  backup roots, and blocked restore plans fail closed.
- Confirmed a matching restore plan digest and exact confirmation phrase
  cannot bypass backup verification or active-database blockers.
- Confirmed no database, backup, or manifest was created during the
  non-destructive boundary checks.
- Confirmed the localhost dashboard remained available at
  `127.0.0.1:8090`, displayed the v0.41 interface, preserved existing
  operational data, and showed no observed UI regression.

The positive backup, restore rehearsal, retention deletion, restore
cutover, and rollback paths were not repeated manually against the normal
active database. Those paths were exercised with isolated temporary
databases by the complete v0.41 automated release gate.
No production database restore was performed.

Parker explicitly approved publication of DeltaAegis v0.41.0 after these
manual checks.
