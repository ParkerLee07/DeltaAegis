#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

expected_feature_branch="feature/v0.41-data-durability-recovery"
current_branch="$(git branch --show-current)"

echo "DeltaAegis v0.41 Backup Foundation Validator"
echo "=============================================="

if [ "$current_branch" != "$expected_feature_branch" ] && \
   [ "$current_branch" != "main" ]; then
    echo "FAIL: expected branch $expected_feature_branch or main, found $current_branch"
    exit 1
fi

echo "[v0.41 checkpoint 1] source syntax"

python3 \
    -W error::SyntaxWarning \
    -m py_compile \
    deltaaegis.py

echo "PASS: source syntax"

echo "[v0.41 checkpoint 1] static backup contract"

python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = (
    "DEFAULT_BACKUPS =",
    "def _normalize_new_backup_path(path: Path) -> Path:",
    "def resolve_database_backup_destination(",
    "def create_sqlite_database_backup(",
    "def command_backup(args) -> int:",
    "source_connection.backup(",
    '"PRAGMA quick_check"',
    "os.link(",
    "tempfile.mkstemp(",
    'if args.command == "backup":',
    '"--destination"',
    '"--backups-dir"',
)

for marker in required:
    if marker not in text:
        raise SystemExit(
            f"missing backup contract marker: {marker}"
        )

start = text.index(
    "# v0.41 checkpoint 1: SQLite-consistent backup foundation"
)
end = text.index(
    '# v0.41 checkpoint 2: backup metadata manifest and checksum',
    start,
)

checkpoint = text[start:end]

for forbidden in (
    "shutil.copy(",
    "shutil.copy2(",
    "shell=True",
    "os.replace(",
    "subprocess.run([\"cp\"",
    "connect(source_path)",
    "connect(resolved_source)",
):
    if forbidden in checkpoint:
        raise SystemExit(
            f"forbidden backup implementation marker: {forbidden}"
        )

print("static backup contract checks passed")
PY

echo "PASS: static backup contract"

echo "[v0.41 checkpoint 1] functional backup behavior"

python3 - <<'PY'
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import hashlib
import importlib.util
import os
import sqlite3
import subprocess
import sys
import tempfile


module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v041_checkpoint1"

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


def sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)

    return digest.hexdigest()


def quick_check(path: Path) -> list[str]:
    uri = path.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)

    try:
        return [
            str(row[0]).strip().lower()
            for row in connection.execute(
                "PRAGMA quick_check"
            ).fetchall()
        ]
    finally:
        connection.close()


def create_sample_database(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(path)

    try:
        connection.execute(
            """
            CREATE TABLE sample_records (
                id INTEGER PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        connection.executemany(
            "INSERT INTO sample_records(value) VALUES (?)",
            [
                ("alpha",),
                ("beta",),
                ("gamma",),
            ],
        )
        connection.commit()
    finally:
        connection.close()


with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v041-backup-"
) as temporary_directory:
    root = Path(temporary_directory)
    source = root / "source.db"
    create_sample_database(source)

    source_hash_before = sha256(source)

    destination = root / "backup.db"

    result = module.create_sqlite_database_backup(
        source,
        destination,
    )

    expected_keys = {
        "source_path",
        "backup_path",
        "size_bytes",
        "integrity_status",
    }

    if set(result) != expected_keys:
        raise SystemExit(
            f"unexpected backup result keys: {sorted(result)}"
        )

    if result["integrity_status"] != "ok":
        raise SystemExit("backup did not report integrity status ok")

    if not destination.is_file():
        raise SystemExit("backup destination was not created")

    if quick_check(destination) != ["ok"]:
        raise SystemExit("completed backup failed quick_check")

    source_connection = sqlite3.connect(source)
    backup_connection = sqlite3.connect(destination)

    try:
        source_rows = source_connection.execute(
            "SELECT id, value FROM sample_records ORDER BY id"
        ).fetchall()

        backup_rows = backup_connection.execute(
            "SELECT id, value FROM sample_records ORDER BY id"
        ).fetchall()
    finally:
        source_connection.close()
        backup_connection.close()

    if source_rows != backup_rows:
        raise SystemExit(
            "populated backup rows do not match the source"
        )

    if sha256(source) != source_hash_before:
        raise SystemExit(
            "backup operation modified the source database"
        )

    live_connection = sqlite3.connect(source)

    try:
        live_connection.execute(
            "SELECT COUNT(*) FROM sample_records"
        ).fetchone()

        live_destination = root / "live-source-backup.db"

        module.create_sqlite_database_backup(
            source,
            live_destination,
        )
    finally:
        live_connection.close()

    if quick_check(live_destination) != ["ok"]:
        raise SystemExit(
            "backup from an open source connection failed"
        )

    try:
        module.create_sqlite_database_backup(
            source,
            source,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "source-equals-destination was not rejected"
        )

    existing_destination = root / "existing.db"
    existing_destination.write_bytes(b"sentinel")
    existing_before = existing_destination.read_bytes()

    try:
        module.create_sqlite_database_backup(
            source,
            existing_destination,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "existing destination was not rejected"
        )

    if existing_destination.read_bytes() != existing_before:
        raise SystemExit(
            "existing destination bytes were modified"
        )

    broken_target = root / "missing-symlink-target.db"
    broken_destination = root / "broken-destination.db"
    broken_destination.symlink_to(broken_target)
    broken_link_value = os.readlink(broken_destination)

    try:
        module.resolve_database_backup_destination(
            source,
            destination=broken_destination,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "broken-symlink destination was not rejected by resolver"
        )

    try:
        module.create_sqlite_database_backup(
            source,
            broken_destination,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "broken-symlink destination was not rejected by backup helper"
        )

    if (
        not broken_destination.is_symlink()
        or os.readlink(broken_destination) != broken_link_value
    ):
        raise SystemExit(
            "broken-symlink destination was modified"
        )

    missing_source = root / "missing-parent" / "missing.db"
    missing_destination = root / "missing-backup.db"

    try:
        module.create_sqlite_database_backup(
            missing_source,
            missing_destination,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit("missing source was not rejected")

    if missing_source.parent.exists():
        raise SystemExit(
            "missing source parent was created unexpectedly"
        )

    corrupt_source = root / "corrupt.db"
    corrupt_source.write_bytes(b"not a sqlite database")
    corrupt_destination = root / "corrupt-backup.db"

    try:
        module.create_sqlite_database_backup(
            corrupt_source,
            corrupt_destination,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "invalid SQLite source was not rejected"
        )

    if corrupt_destination.exists():
        raise SystemExit(
            "invalid-source backup destination was retained"
        )

    empty_source = root / "empty.db"
    empty_source.touch()
    empty_destination = root / "empty-backup.db"

    try:
        module.create_sqlite_database_backup(
            empty_source,
            empty_destination,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit("empty source was not rejected")

    if empty_destination.exists():
        raise SystemExit(
            "empty-source backup destination was retained"
        )

    directory_source = root / "database-directory"
    directory_source.mkdir()
    directory_destination = root / "directory-backup.db"

    try:
        module.create_sqlite_database_backup(
            directory_source,
            directory_destination,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit("directory source was not rejected")

    missing_destination_parent = root / "missing-output-parent"

    try:
        module.resolve_database_backup_destination(
            source,
            destination=(
                missing_destination_parent / "backup.db"
            ),
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "missing explicit destination parent was accepted"
        )

    if missing_destination_parent.exists():
        raise SystemExit(
            "explicit destination parent was created unexpectedly"
        )

    try:
        module.resolve_database_backup_destination(
            source,
            destination=(root / "mutual.db"),
            backups_dir=(root / "mutual-directory"),
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "mutually exclusive destination options were accepted"
        )

    publication_destination = root / "publication-race.db"
    real_link = module.os.link

    def fail_publication(source_path, destination_path):
        raise FileExistsError("injected publication race")

    module.os.link = fail_publication

    try:
        try:
            module.create_sqlite_database_backup(
                source,
                publication_destination,
            )
        except module.DeltaAegisError:
            pass
        else:
            raise SystemExit(
                "injected publication failure was not surfaced"
            )
    finally:
        module.os.link = real_link

    if publication_destination.exists():
        raise SystemExit(
            "injected publication failure retained destination"
        )

    publication_leftovers = list(root.glob(".*.tmp"))

    if publication_leftovers:
        raise SystemExit(
            "injected publication failure did not remove "
            f"temporary backup: {publication_leftovers}"
        )

    leftovers = list(root.glob(".*.tmp"))

    if leftovers:
        raise SystemExit(
            f"temporary backup artifacts remain: {leftovers}"
        )

    cli_destination = root / "cli-explicit.db"

    cli_result = subprocess.run(
        [
            sys.executable,
            str(module_path),
            "--db",
            str(source),
            "backup",
            "--destination",
            str(cli_destination),
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if cli_result.returncode != 0:
        raise SystemExit(
            "explicit-destination CLI backup failed:\n"
            + cli_result.stdout
            + cli_result.stderr
        )

    for marker in (
        "DeltaAegis database backup completed.",
        "Source:",
        "Backup:",
        "Size:",
        "Integrity: ok",
    ):
        if marker not in cli_result.stdout:
            raise SystemExit(
                f"CLI output is missing marker: {marker}"
            )

    if quick_check(cli_destination) != ["ok"]:
        raise SystemExit(
            "explicit-destination CLI backup is invalid"
        )

    generated_directory = root / "generated-backups"

    args = SimpleNamespace(
        db=source,
        destination=None,
        backups_dir=generated_directory,
    )

    if module.command_backup(args) != 0:
        raise SystemExit(
            "command_backup returned a nonzero status"
        )

    generated_backups = list(
        generated_directory.glob(
            "deltaaegis-backup-*.db"
        )
    )

    if len(generated_backups) != 1:
        raise SystemExit(
            "backups-dir mode did not create exactly one backup"
        )

    temporary_home = root / "home"
    default_source = (
        temporary_home
        / "DeltaAegis"
        / "data"
        / "deltaaegis.db"
    )
    create_sample_database(default_source)

    environment = dict(os.environ)
    environment["HOME"] = str(temporary_home)

    default_result = subprocess.run(
        [
            sys.executable,
            str(module_path),
            "backup",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )

    if default_result.returncode != 0:
        raise SystemExit(
            "default CLI backup failed:\n"
            + default_result.stdout
            + default_result.stderr
        )

    default_backup_directory = (
        temporary_home
        / "DeltaAegis"
        / "backups"
    )

    default_backups = list(
        default_backup_directory.glob(
            "deltaaegis-backup-*.db"
        )
    )

    if len(default_backups) != 1:
        raise SystemExit(
            "default CLI did not create exactly one backup"
        )

    if quick_check(default_backups[0]) != ["ok"]:
        raise SystemExit("default CLI backup is invalid")

print("functional backup behavior checks passed")
PY

echo "PASS: functional backup behavior"

echo "[v0.41 checkpoint 1] CLI help"

help_output="$(
    python3 deltaaegis.py backup --help
)"

printf '%s\n' "$help_output"

grep -Fq -- "--destination" <<<"$help_output"
grep -Fq -- "--backups-dir" <<<"$help_output"

echo "PASS: CLI help"

echo "[v0.41 checkpoint 1] repository hygiene"

unexpected_paths="$(
    git status --short |
    grep -v -E \
        '^( M deltaaegis\.py|\?\? tools/validate_v0_41_backup_foundation\.sh)$' \
    || true
)"

if [ -n "$unexpected_paths" ]; then
    echo "FAIL: unexpected repository paths:"
    printf '%s\n' "$unexpected_paths"
    exit 1
fi

tracked_database_paths="$(
    git ls-files |
    grep -Ei \
        '\.(db|sqlite|sqlite3)($|\.)|-(wal|shm|journal)$' \
    || true
)"

if [ -n "$tracked_database_paths" ]; then
    echo "FAIL: database-like files are tracked:"
    printf '%s\n' "$tracked_database_paths"
    exit 1
fi

temporary_artifacts="$(
    find . \
        -path './.git' -prune -o \
        -type f \
        -name '.deltaaegis-backup-*.tmp' \
        -print
)"

if [ -n "$temporary_artifacts" ]; then
    echo "FAIL: temporary backup artifacts remain:"
    printf '%s\n' "$temporary_artifacts"
    exit 1
fi

echo "PASS: repository hygiene"
echo
echo "PASS: DeltaAegis v0.41 backup foundation validator"
