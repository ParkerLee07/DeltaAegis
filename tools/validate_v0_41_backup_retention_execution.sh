#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

expected_branch="feature/v0.41-data-durability-recovery"

echo "DeltaAegis v0.41 Backup Retention Execution Validator"
echo "======================================================"

if [ "$(git branch --show-current)" != "$expected_branch" ]; then
    echo "FAIL: expected branch $expected_branch"
    exit 1
fi

echo "[v0.41 checkpoint 6] source syntax"

python3 \
    -W error::SyntaxWarning \
    -m py_compile \
    deltaaegis.py

echo "PASS: source syntax"

echo "[v0.41 checkpoint 6] static execution contract"

python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = (
    '"deltaaegis-backup-retention-receipt-v1"',
    '"DELETE ELIGIBLE BACKUP BUNDLES"',
    "def _database_backup_retention_file_identity(",
    "os.lstat(",
    "def _database_backup_retention_plan_digest(",
    "def _database_backup_retention_prepare_candidate(",
    "_existing_paths_share_file_identity(",
    "def _database_backup_retention_unlink_if_identity_matches(",
    "def _database_backup_retention_restore_from_quarantine(",
    "tempfile.mkdtemp(",
    "os.link(",
    "follow_symlinks=False",
    "def execute_database_backup_retention(",
    '"deleted_paths"',
    '"skipped_paths"',
    '"changed_paths"',
    '"failed_paths"',
    '"restored_paths"',
    '"quarantine_paths"',
    "def command_backup_retention_execute(args) -> int:",
    '"backup-retention-execute"',
)

for marker in required:
    if marker not in text:
        raise SystemExit(
            f"missing retention execution marker: {marker}"
        )

start = text.index(
    "# v0.41 checkpoint 6: guarded backup retention execution"
)
end = text.index(
    "def build_parser() -> argparse.ArgumentParser:",
    start,
)
checkpoint = text[start:end]

for forbidden in (
    "shutil.rmtree(",
    "os.remove(",
    "os.replace(",
    "os.rename(",
    "subprocess.",
    "shell=True",
    "rglob(",
):
    if forbidden in checkpoint:
        raise SystemExit(
            f"forbidden retention execution behavior found: "
            f"{forbidden}"
        )

if checkpoint.count(".unlink()") != 2:
    raise SystemExit(
        "retention execution should contain exactly two "
        "controlled unlink call sites"
    )

if checkpoint.count(".rmdir()") != 1:
    raise SystemExit(
        "retention execution should contain exactly one "
        "quarantine-directory removal call site"
    )

print("static retention execution contract checks passed")
PY

echo "PASS: static execution contract"

echo "[v0.41 checkpoint 6] functional execution behavior"

python3 - <<'PY'
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import tempfile


module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v041_checkpoint6"

spec = importlib.util.spec_from_file_location(
    module_name,
    module_path,
)

if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module

try:
    spec.loader.exec_module(module)
finally:
    sys.modules.pop(module_name, None)


def create_database(path: Path, value: str) -> None:
    connection = sqlite3.connect(path)

    try:
        connection.execute(
            "CREATE TABLE retention_execution_records "
            "(id INTEGER PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO retention_execution_records(value) "
            "VALUES (?)",
            (value,),
        )
        connection.commit()
    finally:
        connection.close()


def set_created_at(backup: Path, created_at: str) -> None:
    manifest = module.database_backup_manifest_path(backup)
    payload = json.loads(
        manifest.read_text(encoding="utf-8")
    )
    payload["created_at"] = created_at
    manifest.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def create_bundle(
    root: Path,
    backups: Path,
    name: str,
    value: str,
    created_at: str,
) -> Path:
    source = root / f"source-{name}.db"
    backup = backups / f"{name}.db"
    create_database(source, value)
    module.create_sqlite_database_backup_bundle(
        source,
        backup,
    )
    set_created_at(backup, created_at)
    return backup


def timestamp(
    now: datetime,
    age_days: int,
) -> str:
    return (
        now - timedelta(days=age_days)
    ).replace(microsecond=0).isoformat().replace(
        "+00:00",
        "Z",
    )


with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v041-retention-execution-"
) as temporary_directory:
    root = Path(temporary_directory)
    active = root / "active.db"
    create_database(active, "active-record")
    active_hash_before = sha256(active)
    backups = root / "backups"
    backups.mkdir()
    now = datetime(2026, 7, 8, 12, 0, tzinfo=timezone.utc)

    backup_1 = create_bundle(
        root,
        backups,
        "backup-1",
        "one",
        timestamp(now, 1),
    )
    backup_2 = create_bundle(
        root,
        backups,
        "backup-2",
        "two",
        timestamp(now, 10),
    )
    backup_3 = create_bundle(
        root,
        backups,
        "backup-3",
        "three",
        timestamp(now, 40),
    )
    backup_4 = create_bundle(
        root,
        backups,
        "backup-4",
        "four",
        timestamp(now, 70),
    )
    backup_5 = create_bundle(
        root,
        backups,
        "backup-5",
        "five",
        timestamp(now, 100),
    )

    invalid = create_bundle(
        root,
        backups,
        "invalid",
        "invalid",
        timestamp(now, 120),
    )

    with invalid.open("ab") as handle:
        handle.write(b"tampered")

    incomplete = backups / "incomplete.db"
    incomplete.write_bytes(b"incomplete")

    all_paths_before_confirmation = sorted(
        str(path.relative_to(root))
        for path in root.rglob("*")
    )
    all_bytes_before_confirmation = {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }

    try:
        module.execute_database_backup_retention(
            active,
            backups,
            keep_newest=2,
            minimum_age_days=30,
            confirmation="DELETE BACKUPS",
            now=now,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "incorrect confirmation phrase was accepted"
        )

    if all_paths_before_confirmation != sorted(
        str(path.relative_to(root))
        for path in root.rglob("*")
    ):
        raise SystemExit(
            "incorrect confirmation changed filesystem paths"
        )

    if all_bytes_before_confirmation != {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }:
        raise SystemExit(
            "incorrect confirmation changed file contents"
        )

    receipt = module.execute_database_backup_retention(
        active,
        backups,
        keep_newest=2,
        minimum_age_days=30,
        confirmation=(
            module.DATABASE_BACKUP_RETENTION_EXECUTION_CONFIRMATION
        ),
        now=now,
    )

    if receipt["schema_version"] != (
        "deltaaegis-backup-retention-receipt-v1"
    ):
        raise SystemExit(
            "incorrect retention receipt schema"
        )

    if (
        receipt["dry_run"] is not False
        or receipt["destructive"] is not True
        or receipt["confirmation_matched"] is not True
    ):
        raise SystemExit(
            "execution receipt flags are incorrect"
        )

    summary = receipt["summary"]

    if summary["deleted_bundles"] != 3:
        raise SystemExit(
            f"expected 3 deleted bundles, found {summary}"
        )

    if summary["deleted_files"] != 6:
        raise SystemExit(
            f"expected 6 deleted files, found {summary}"
        )

    if summary["failed_bundles"] != 0:
        raise SystemExit(
            f"unexpected deletion failure: {summary}"
        )

    if summary["changed_bundles"] != 0:
        raise SystemExit(
            f"unexpected changed candidate: {summary}"
        )

    for backup in (backup_3, backup_4, backup_5):
        manifest = module.database_backup_manifest_path(
            backup
        )

        if os.path.lexists(backup):
            raise SystemExit(
                f"eligible backup was not deleted: {backup}"
            )

        if os.path.lexists(manifest):
            raise SystemExit(
                f"eligible manifest was not deleted: {manifest}"
            )

    for backup in (backup_1, backup_2):
        manifest = module.database_backup_manifest_path(
            backup
        )

        if not backup.is_file() or not manifest.is_file():
            raise SystemExit(
                f"protected newest bundle was removed: {backup}"
            )

    if not invalid.is_file():
        raise SystemExit(
            "invalid protected backup was removed"
        )

    if not module.database_backup_manifest_path(
        invalid
    ).is_file():
        raise SystemExit(
            "invalid protected manifest was removed"
        )

    if not incomplete.is_file():
        raise SystemExit(
            "incomplete protected backup was removed"
        )

    if sha256(active) != active_hash_before:
        raise SystemExit(
            "active database changed during retention execution"
        )

    quarantine_residue = [
        path
        for path in backups.iterdir()
        if path.name.startswith(".deltaaegis-retention-")
    ]

    if quarantine_residue:
        raise SystemExit(
            f"successful execution left quarantine residue: "
            f"{quarantine_residue}"
        )

    if not receipt["review_required"]:
        raise SystemExit(
            "protected invalid/incomplete bundles did not "
            "require review"
        )

    if len(receipt["plan_digest"]) != 64:
        raise SystemExit(
            "retention plan digest is not SHA-256"
        )

    race_root = root / "race"
    race_root.mkdir()
    race_backups = race_root / "backups"
    race_backups.mkdir()
    race_active = race_root / "active.db"
    create_database(race_active, "race-active")
    race_backup = create_bundle(
        race_root,
        race_backups,
        "race-old",
        "race-old",
        timestamp(now, 90),
    )
    create_bundle(
        race_root,
        race_backups,
        "race-new",
        "race-new",
        timestamp(now, 1),
    )
    race_plan = module.plan_database_backup_retention(
        race_backups,
        keep_newest=1,
        minimum_age_days=30,
        now=now,
    )
    race_entry = next(
        item
        for item in race_plan["entries"]
        if item["retention_action"] == "ELIGIBLE"
    )
    prepared = (
        module._database_backup_retention_prepare_candidate(
            race_entry,
            backups_root=race_backups,
            active_database_path=race_active,
        )
    )

    if prepared["outcome"] != "READY":
        raise SystemExit(
            f"race candidate was not prepared: {prepared}"
        )

    race_backup.unlink()
    race_backup.write_bytes(b"replacement-file")
    race_manifest = (
        module.database_backup_manifest_path(race_backup)
    )
    race_manifest_before = race_manifest.read_bytes()

    changed = (
        module._database_backup_retention_delete_prepared_candidate(
            prepared,
            backups_root=race_backups,
        )
    )

    if changed["outcome"] != "CHANGED":
        raise SystemExit(
            f"replaced candidate was not marked CHANGED: "
            f"{changed}"
        )

    if race_backup.read_bytes() != b"replacement-file":
        raise SystemExit(
            "replacement backup was deleted or modified"
        )

    if race_manifest.read_bytes() != race_manifest_before:
        raise SystemExit(
            "manifest changed during identity mismatch handling"
        )

    race_quarantine = [
        path
        for path in race_backups.iterdir()
        if path.name.startswith(".deltaaegis-retention-")
    ]

    if race_quarantine:
        raise SystemExit(
            "identity mismatch left quarantine residue"
        )

    alias_root = root / "active-alias"
    alias_root.mkdir()
    alias_backups = alias_root / "backups"
    alias_backups.mkdir()
    alias_active = alias_root / "active.db"
    create_database(alias_active, "alias-active")
    alias_hash_before = sha256(alias_active)
    alias_backup = alias_backups / "alias-old.db"

    module.create_sqlite_database_backup_bundle(
        alias_active,
        alias_backup,
    )
    set_created_at(
        alias_backup,
        timestamp(now, 90),
    )
    alias_backup.unlink()
    os.link(alias_active, alias_backup)

    alias_manifest = (
        module.database_backup_manifest_path(alias_backup)
    )
    alias_payload = json.loads(
        alias_manifest.read_text(encoding="utf-8")
    )
    alias_sqlite, alias_schema = (
        module._sqlite_backup_metadata(alias_backup)
    )
    alias_payload["backup"]["filename"] = (
        alias_backup.name
    )
    alias_payload["backup"]["path"] = str(
        alias_backup.resolve()
    )
    alias_payload["backup"]["size_bytes"] = (
        alias_backup.stat().st_size
    )
    alias_payload["backup"]["sha256"] = (
        module._database_backup_sha256(alias_backup)
    )
    alias_payload["sqlite"] = alias_sqlite
    alias_payload["schema"] = alias_schema
    alias_manifest.write_text(
        json.dumps(
            alias_payload,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    alias_catalog_entry = (
        module.inspect_database_backup_bundle(alias_backup)
    )

    if alias_catalog_entry["status"] != "VALID":
        raise SystemExit(
            "active hard-link alias fixture was not valid: "
            f"{alias_catalog_entry}"
        )

    create_bundle(
        alias_root,
        alias_backups,
        "alias-new",
        "alias-new",
        timestamp(now, 1),
    )

    alias_receipt = (
        module.execute_database_backup_retention(
            alias_active,
            alias_backups,
            keep_newest=1,
            minimum_age_days=30,
            confirmation=(
                module.DATABASE_BACKUP_RETENTION_EXECUTION_CONFIRMATION
            ),
            now=now,
        )
    )

    alias_result = next(
        result
        for result in alias_receipt["results"]
        if Path(result["backup_path"]).name
        == "alias-old.db"
    )

    if alias_result["outcome"] != "SKIPPED":
        raise SystemExit(
            f"active hard-link alias was not skipped: "
            f"{alias_result}"
        )

    if not alias_backup.is_file():
        raise SystemExit(
            "active hard-link alias path was deleted"
        )

    if not module.database_backup_manifest_path(
        alias_backup
    ).is_file():
        raise SystemExit(
            "active hard-link alias manifest was deleted"
        )

    if sha256(alias_active) != alias_hash_before:
        raise SystemExit(
            "active database changed through hard-link alias"
        )

    cli_root = root / "cli"
    cli_root.mkdir()
    cli_backups = cli_root / "backups"
    cli_backups.mkdir()
    cli_active = cli_root / "active.db"
    create_database(cli_active, "cli-active")
    cli_new = create_bundle(
        cli_root,
        cli_backups,
        "cli-new",
        "cli-new",
        timestamp(now, 1),
    )
    cli_old = create_bundle(
        cli_root,
        cli_backups,
        "cli-old",
        "cli-old",
        timestamp(now, 90),
    )

    cli = subprocess.run(
        [
            sys.executable,
            str(module_path),
            "--db",
            str(cli_active),
            "backup-retention-execute",
            "--backups-dir",
            str(cli_backups),
            "--keep-newest",
            "1",
            "--minimum-age-days",
            "30",
            "--confirmation",
            "DELETE ELIGIBLE BACKUP BUNDLES",
            "--json",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if cli.returncode != 0:
        raise SystemExit(
            "healthy CLI execution failed:\n"
            + cli.stdout
            + cli.stderr
        )

    cli_payload = json.loads(cli.stdout)

    if cli_payload["summary"]["deleted_bundles"] != 1:
        raise SystemExit(
            "CLI receipt deleted-bundle count is incorrect"
        )

    if not cli_new.is_file():
        raise SystemExit(
            "CLI deleted the newest protected backup"
        )

    if cli_old.exists():
        raise SystemExit(
            "CLI did not delete the eligible old backup"
        )

print("functional retention execution checks passed")
PY

echo "PASS: functional execution behavior"

echo "[v0.41 checkpoint 6] CLI help"

help_text="$(
    python3 deltaaegis.py backup-retention-execute --help
)"

printf '%s\n' "$help_text" |
    grep -F \
        "usage: deltaaegis.py backup-retention-execute" \
        >/dev/null

for flag in \
    "--backups-dir" \
    "--keep-newest" \
    "--minimum-age-days" \
    "--confirmation" \
    "--json"
do
    printf '%s\n' "$help_text" |
        grep -F -- "$flag" >/dev/null
done

printf '%s\n' "$help_text" |
    grep -F \
        "DELETE ELIGIBLE BACKUP BUNDLES" \
        >/dev/null

echo "PASS: CLI help"

echo "[v0.41 checkpoint 6] repository hygiene"

unexpected_paths="$(
    git status --short |
    grep -v -E \
        '^( M deltaaegis\.py|\?\? tools/validate_v0_41_backup_retention_execution\.sh)$' \
    || true
)"

if [ -n "$unexpected_paths" ]; then
    echo "FAIL: unexpected repository paths:"
    printf '%s\n' "$unexpected_paths"
    exit 1
fi

tracked_artifacts="$(
    git ls-files |
    grep -Ei \
        '(^|/)backups?/|\.db(\.|$)|\.sqlite3?(\.|$)|\.manifest\.json$|-(wal|shm|journal)$' \
    || true
)"

if [ -n "$tracked_artifacts" ]; then
    echo "FAIL: backup or database artifacts are tracked:"
    printf '%s\n' "$tracked_artifacts"
    exit 1
fi

echo "PASS: repository hygiene"
echo
echo "PASS: DeltaAegis v0.41 backup retention execution validator"
