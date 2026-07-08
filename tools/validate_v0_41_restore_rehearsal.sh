#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

expected_branch="feature/v0.41-data-durability-recovery"

echo "DeltaAegis v0.41 Restore Rehearsal Validator"
echo "============================================="

if [ "$(git branch --show-current)" != "$expected_branch" ]; then
    echo "FAIL: expected branch $expected_branch"
    exit 1
fi

echo "[v0.41 checkpoint 3] source syntax"

python3 \
    -W error::SyntaxWarning \
    -m py_compile \
    deltaaegis.py

echo "PASS: source syntax"

echo "[v0.41 checkpoint 3] static restore contract"

python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = (
    "DEFAULT_RESTORE_REHEARSALS",
    "# v0.41 checkpoint 3: verified restore rehearsal",
    "def _existing_paths_share_file_identity(",
    "def resolve_database_restore_rehearsal_paths(",
    "def _read_database_backup_manifest(",
    "def _sqlite_database_integrity_check(",
    "def _sqlite_database_logical_fingerprint(",
    "def verify_database_backup_bundle(",
    "def _unlink_if_inode_matches(",
    "def create_database_restore_rehearsal(",
    "def command_restore_rehearsal(args) -> int:",
    "PRAGMA integrity_check",
    "connection.iterdump()",
    "source_connection.backup(",
    "os.link(",
    "os.lstat(",
    "os.path.lexists(",
    "os.path.samefile(",
    '"restore-rehearsal"',
    '"--manifest"',
    '"--destination"',
    '"--restore-dir"',
    "Active database was not modified.",
)

for marker in required:
    if marker not in text:
        raise SystemExit(
            f"missing restore contract marker: {marker}"
        )

start = text.index(
    "# v0.41 checkpoint 3: verified restore rehearsal"
)
end = text.index(
    '# v0.41 checkpoint 4: backup catalog and verification CLI',
    start,
)
checkpoint = text[start:end]

for forbidden in (
    "shutil.copy(",
    "shutil.copy2(",
    "shell=True",
    "os.replace(",
    "VACUUM INTO",
    "ATTACH DATABASE",
):
    if forbidden in checkpoint:
        raise SystemExit(
            f"forbidden restore implementation marker: {forbidden}"
        )

print("static restore contract checks passed")
PY

echo "PASS: static restore contract"

echo "[v0.41 checkpoint 3] functional restore behavior"

python3 - <<'PY'

from __future__ import annotations

from pathlib import Path
import hashlib
import importlib.util
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile


module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v041_checkpoint3"

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
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def create_database(
    path: Path,
    values: tuple[str, ...],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)

    try:
        connection.execute("PRAGMA user_version = 41")
        connection.execute("PRAGMA application_id = 1145128263")
        connection.execute(
            "CREATE TABLE records "
            "(id INTEGER PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE INDEX records_value_idx ON records(value)"
        )
        connection.executemany(
            "INSERT INTO records(value) VALUES (?)",
            [(value,) for value in values],
        )
        connection.commit()
    finally:
        connection.close()


def read_values(path: Path) -> list[str]:
    connection = sqlite3.connect(
        path.resolve().as_uri() + "?mode=ro",
        uri=True,
    )

    try:
        return [
            str(row[0])
            for row in connection.execute(
                "SELECT value FROM records ORDER BY id"
            ).fetchall()
        ]
    finally:
        connection.close()


def integrity(path: Path) -> list[str]:
    connection = sqlite3.connect(
        path.resolve().as_uri() + "?mode=ro",
        uri=True,
    )

    try:
        return [
            str(row[0]).strip().lower()
            for row in connection.execute(
                "PRAGMA integrity_check"
            ).fetchall()
        ]
    finally:
        connection.close()


with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v041-restore-"
) as temporary_directory:
    root = Path(temporary_directory)
    active = root / "active.db"
    source = root / "source.db"
    backup = root / "backup.db"
    restore = root / "restore.db"

    create_database(active, ("active-only",))
    create_database(
        source,
        ("alpha", "beta", "gamma"),
    )

    bundle = module.create_sqlite_database_backup_bundle(
        source,
        backup,
    )
    manifest = Path(bundle["manifest_path"])

    active_hash_before = sha256(active)
    backup_hash_before = sha256(backup)
    manifest_hash_before = sha256(manifest)

    result = module.create_database_restore_rehearsal(
        active,
        backup,
        manifest,
        restore,
    )

    expected_keys = {
        "backup_path",
        "manifest_path",
        "size_bytes",
        "backup_sha256",
        "schema_fingerprint",
        "logical_fingerprint",
        "integrity_status",
        "active_database_path",
        "restored_path",
        "restored_size_bytes",
        "restored_integrity_status",
        "restored_logical_fingerprint",
    }

    if set(result) != expected_keys:
        raise SystemExit(
            f"unexpected restore result keys: {sorted(result)}"
        )

    if not restore.is_file():
        raise SystemExit("restore rehearsal did not create destination")

    if integrity(restore) != ["ok"]:
        raise SystemExit("restored database failed integrity_check")

    if read_values(restore) != ["alpha", "beta", "gamma"]:
        raise SystemExit("restored database rows do not match")

    if (
        result["logical_fingerprint"]
        != result["restored_logical_fingerprint"]
    ):
        raise SystemExit("logical fingerprints do not match")

    if sha256(active) != active_hash_before:
        raise SystemExit("active database was modified")

    if sha256(backup) != backup_hash_before:
        raise SystemExit("backup database was modified")

    if sha256(manifest) != manifest_hash_before:
        raise SystemExit("backup manifest was modified")

    if read_values(active) != ["active-only"]:
        raise SystemExit("active database content changed")

    restore_mode = stat.S_IMODE(restore.stat().st_mode)

    if restore_mode & 0o077:
        raise SystemExit(
            f"restore destination permissions are too broad: "
            f"{oct(restore_mode)}"
        )

    occupied = root / "occupied.db"
    occupied.write_bytes(b"sentinel")
    occupied_before = occupied.read_bytes()

    try:
        module.create_database_restore_rehearsal(
            active,
            backup,
            manifest,
            occupied,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit("existing destination was not rejected")

    if occupied.read_bytes() != occupied_before:
        raise SystemExit("existing destination was modified")

    broken = root / "broken-destination.db"
    broken_target = root / "missing-target.db"
    broken.symlink_to(broken_target)
    broken_value = os.readlink(broken)

    try:
        module.create_database_restore_rehearsal(
            active,
            backup,
            manifest,
            broken,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit("broken destination symlink was not rejected")

    if not broken.is_symlink() or os.readlink(broken) != broken_value:
        raise SystemExit("broken destination symlink was modified")

    for prohibited in (active, backup, manifest):
        try:
            module.create_database_restore_rehearsal(
                active,
                backup,
                manifest,
                prohibited,
            )
        except module.DeltaAegisError:
            pass
        else:
            raise SystemExit(
                f"prohibited destination was accepted: {prohibited}"
            )

    active_manifest = module.database_backup_manifest_path(active)
    active_manifest.write_text(
        manifest.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    try:
        module.resolve_database_restore_rehearsal_paths(
            active,
            active,
            manifest_path=active_manifest,
            destination=(root / "active-source-restore.db"),
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit("active database was accepted as backup")

    active_hardlink_backup = root / "active-hardlink-backup.db"
    os.link(active, active_hardlink_backup)

    try:
        module.resolve_database_restore_rehearsal_paths(
            active,
            active_hardlink_backup,
            manifest_path=manifest,
            destination=(
                root / "active-hardlink-resolver-restore.db"
            ),
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "active database hard-link alias was accepted as backup "
            "by resolver"
        )

    try:
        module.create_database_restore_rehearsal(
            active,
            active_hardlink_backup,
            manifest,
            root / "active-hardlink-helper-restore.db",
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "active database hard-link alias was accepted as backup "
            "by restore helper"
        )

    if sha256(active) != active_hash_before:
        raise SystemExit(
            "active database changed during hard-link identity tests"
        )

    symlink_backup = root / "backup-link.db"
    symlink_backup.symlink_to(backup)

    try:
        module.resolve_database_restore_rehearsal_paths(
            active,
            symlink_backup,
            manifest_path=manifest,
            destination=(root / "symlink-backup-restore.db"),
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit("backup symlink was accepted")

    symlink_manifest = root / "manifest-link.json"
    symlink_manifest.symlink_to(manifest)

    try:
        module.resolve_database_restore_rehearsal_paths(
            active,
            backup,
            manifest_path=symlink_manifest,
            destination=(root / "symlink-manifest-restore.db"),
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit("manifest symlink was accepted")

    missing_parent = root / "missing-parent"
    missing_destination = missing_parent / "restore.db"

    try:
        module.resolve_database_restore_rehearsal_paths(
            active,
            backup,
            manifest_path=manifest,
            destination=missing_destination,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit("missing destination parent was accepted")

    if missing_parent.exists():
        raise SystemExit("explicit destination parent was created")

    tampered_backup = root / "tampered.db"
    tampered_manifest = module.database_backup_manifest_path(
        tampered_backup
    )
    tampered_backup.write_bytes(backup.read_bytes())
    tampered_payload = json.loads(
        manifest.read_text(encoding="utf-8")
    )

    with tampered_backup.open("ab") as handle:
        handle.write(b"tamper")

    tampered_payload["backup"]["filename"] = (
        tampered_backup.name
    )
    tampered_payload["backup"]["size_bytes"] = (
        tampered_backup.stat().st_size
    )
    tampered_manifest.write_text(
        json.dumps(
            tampered_payload,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    tampered_destination = root / "tampered-restore.db"

    try:
        module.create_database_restore_rehearsal(
            active,
            tampered_backup,
            tampered_manifest,
            tampered_destination,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit("tampered backup was accepted")

    if tampered_destination.exists():
        raise SystemExit("tampered backup created a destination")

    wrong_schema_backup = root / "wrong-schema.db"
    wrong_schema_manifest = (
        module.database_backup_manifest_path(
            wrong_schema_backup
        )
    )
    wrong_schema_backup.write_bytes(backup.read_bytes())
    wrong_schema_payload = json.loads(
        manifest.read_text(encoding="utf-8")
    )
    wrong_schema_payload["backup"]["filename"] = (
        wrong_schema_backup.name
    )
    wrong_schema_payload["schema"]["fingerprint"] = "0" * 64
    wrong_schema_manifest.write_text(
        json.dumps(
            wrong_schema_payload,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    wrong_schema_destination = root / "wrong-schema-restore.db"

    try:
        module.create_database_restore_rehearsal(
            active,
            wrong_schema_backup,
            wrong_schema_manifest,
            wrong_schema_destination,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "incorrect manifest schema fingerprint was accepted"
        )

    if wrong_schema_destination.exists():
        raise SystemExit(
            "wrong schema fingerprint created a destination"
        )

    race_destination = root / "race-restore.db"
    real_link = module.os.link

    def fail_publication(source_path, destination_path):
        raise FileExistsError("injected restore publication race")

    module.os.link = fail_publication

    try:
        try:
            module.create_database_restore_rehearsal(
                active,
                backup,
                manifest,
                race_destination,
            )
        except module.DeltaAegisError:
            pass
        else:
            raise SystemExit(
                "restore publication failure was not surfaced"
            )
    finally:
        module.os.link = real_link

    if race_destination.exists():
        raise SystemExit(
            "restore publication failure retained destination"
        )

    race_leftovers = list(
        root.glob(f".{race_destination.name}.*.tmp")
    )

    if race_leftovers:
        raise SystemExit(
            f"restore publication left temporary files: "
            f"{race_leftovers}"
        )

    explicit_cli_destination = root / "cli-restore.db"

    cli_result = subprocess.run(
        [
            sys.executable,
            str(module_path),
            "--db",
            str(active),
            "restore-rehearsal",
            str(backup),
            "--manifest",
            str(manifest),
            "--destination",
            str(explicit_cli_destination),
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if cli_result.returncode != 0:
        raise SystemExit(
            "explicit restore-rehearsal CLI failed:\n"
            + cli_result.stdout
            + cli_result.stderr
        )

    for marker in (
        "DeltaAegis restore rehearsal completed.",
        "Restored copy:",
        "Backup SHA-256 verified:",
        "Schema fingerprint verified:",
        "Logical fingerprint verified:",
        "Integrity: ok",
        "Active database was not modified.",
    ):
        if marker not in cli_result.stdout:
            raise SystemExit(
                f"restore CLI output is missing: {marker}"
            )

    if read_values(explicit_cli_destination) != [
        "alpha",
        "beta",
        "gamma",
    ]:
        raise SystemExit("explicit CLI restore data is incorrect")

    isolated_home = root / "isolated-home"
    isolated_home.mkdir()
    default_env = dict(os.environ)
    default_env["HOME"] = str(isolated_home)

    default_result = subprocess.run(
        [
            sys.executable,
            str(module_path),
            "--db",
            str(active),
            "restore-rehearsal",
            str(backup),
            "--manifest",
            str(manifest),
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=default_env,
    )

    if default_result.returncode != 0:
        raise SystemExit(
            "default restore-rehearsal CLI failed:\n"
            + default_result.stdout
            + default_result.stderr
        )

    default_restore_root = (
        isolated_home
        / "DeltaAegis"
        / "restore-rehearsals"
    )
    default_restores = list(
        default_restore_root.glob(
            "deltaaegis-restore-rehearsal-*.db"
        )
    )

    if len(default_restores) != 1:
        raise SystemExit(
            "default restore-rehearsal CLI did not create "
            f"exactly one destination: {default_restores}"
        )

    if read_values(default_restores[0]) != [
        "alpha",
        "beta",
        "gamma",
    ]:
        raise SystemExit("default CLI restore data is incorrect")

    if sha256(active) != active_hash_before:
        raise SystemExit(
            "active database changed during CLI tests"
        )

print("functional restore rehearsal checks passed")

PY

echo "PASS: functional restore behavior"

echo "[v0.41 checkpoint 3] CLI help"

python3 deltaaegis.py restore-rehearsal --help |
    grep -F -- "--manifest" >/dev/null
python3 deltaaegis.py restore-rehearsal --help |
    grep -F -- "--destination" >/dev/null
python3 deltaaegis.py restore-rehearsal --help |
    grep -F -- "--restore-dir" >/dev/null

echo "PASS: CLI help"

echo "[v0.41 checkpoint 3] restore artifact ignore coverage"

for path in \
    "restore-rehearsals/audit.db" \
    "restore-rehearsals/audit.db-wal" \
    "restore-rehearsals/audit.db-shm" \
    "restore-rehearsals/audit.db-journal" \
    "nested/audit.sqlite-wal" \
    "nested/audit.sqlite3-shm"
do
    if ! git check-ignore -q --no-index -- "$path"; then
        echo "FAIL: restore artifact is not ignored: $path"
        exit 1
    fi
done

echo "PASS: restore artifact ignore coverage"

echo "[v0.41 checkpoint 3] repository hygiene"

unexpected_paths="$(
    git status --short |
    grep -v -E \
        '^( M \.gitignore| M deltaaegis\.py|\?\? tools/validate_v0_41_restore_rehearsal\.sh)$' \
    || true
)"

if [ -n "$unexpected_paths" ]; then
    echo "FAIL: unexpected repository paths:"
    printf '%s\n' "$unexpected_paths"
    exit 1
fi

tracked_runtime_artifacts="$(
    git ls-files |
    grep -Ei \
        '(^|/)restore-rehearsals?/|\.db($|\.)|\.sqlite3?($|\.)|-(wal|shm|journal)$|\.manifest\.json$' \
    || true
)"

if [ -n "$tracked_runtime_artifacts" ]; then
    echo "FAIL: runtime database artifacts are tracked:"
    printf '%s\n' "$tracked_runtime_artifacts"
    exit 1
fi

temporary_artifacts="$(
    find . \
        -path './.git' -prune -o \
        -type f \
        \( \
            -name '.*.tmp' \
            -o -path '*/restore-rehearsals/*' \
        \) \
        -print
)"

if [ -n "$temporary_artifacts" ]; then
    echo "FAIL: restore rehearsal artifacts remain in repository:"
    printf '%s\n' "$temporary_artifacts"
    exit 1
fi

echo "PASS: repository hygiene"
echo
echo "PASS: DeltaAegis v0.41 restore rehearsal validator"
