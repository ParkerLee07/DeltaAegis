#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

expected_feature_branch="feature/v0.41-data-durability-recovery"
current_branch="$(git branch --show-current)"

echo "DeltaAegis v0.41 Backup Manifest Validator"
echo "==========================================="

if [ "$current_branch" != "$expected_feature_branch" ] && \
   [ "$current_branch" != "main" ]; then
    echo "FAIL: expected branch $expected_feature_branch or main, found $current_branch"
    exit 1
fi

echo "[v0.41 checkpoint 2] source syntax"

python3 \
    -W error::SyntaxWarning \
    -m py_compile \
    deltaaegis.py

echo "PASS: source syntax"

echo "[v0.41 checkpoint 2] static manifest contract"

python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = (
    'DELTAAEGIS_VERSION = "0.41.0"',
    '"deltaaegis-backup-manifest-v1"',
    "def database_backup_manifest_path(",
    "def _database_backup_sha256(",
    "def _sqlite_backup_metadata(",
    "def _publish_database_backup_manifest(",
    "def create_sqlite_database_backup_bundle(",
    "hashlib.sha256(",
    "os.fsync(",
    "os.link(",
    "os.path.lexists(",
    '"PRAGMA {pragma_name}"',
    "FROM sqlite_master",
    'Manifest:',
    'SHA-256:',
    'Schema fingerprint:',
)

for marker in required:
    if marker not in text:
        raise SystemExit(
            f"missing manifest contract marker: {marker}"
        )

start = text.index(
    "# v0.41 checkpoint 2: backup metadata manifest and checksum"
)
end = text.index(
    '# v0.41 checkpoint 3: verified restore rehearsal',
    start,
)

checkpoint = text[start:end]

for forbidden in (
    "shutil.copy(",
    "shutil.copy2(",
    "shell=True",
    "os.replace(",
    "source_sha256",
):
    if forbidden in checkpoint:
        raise SystemExit(
            f"forbidden manifest implementation marker: {forbidden}"
        )

print("static manifest contract checks passed")
PY

echo "PASS: static manifest contract"

echo "[v0.41 checkpoint 2] functional manifest behavior"

python3 - <<'PY'
from __future__ import annotations

from datetime import datetime
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
module_name = "deltaaegis_v041_checkpoint2"

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


def create_sample_database(
    path: Path,
    *,
    values: tuple[str, ...],
    extra_schema: bool = False,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)

    try:
        connection.execute("PRAGMA user_version = 17")
        connection.execute("PRAGMA application_id = 1145128263")
        connection.execute(
            "CREATE TABLE sample_records "
            "(id INTEGER PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE INDEX sample_value_index "
            "ON sample_records(value)"
        )
        connection.execute(
            "CREATE VIEW sample_record_view AS "
            "SELECT id, value FROM sample_records"
        )
        connection.executemany(
            "INSERT INTO sample_records(value) VALUES (?)",
            [(value,) for value in values],
        )

        if extra_schema:
            connection.execute(
                "CREATE TABLE extra_records "
                "(id INTEGER PRIMARY KEY, note TEXT)"
            )

        connection.commit()
    finally:
        connection.close()


def load_manifest(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v041-manifest-"
) as temporary_directory:
    root = Path(temporary_directory)
    source = root / "source.db"
    destination = root / "backup.db"

    create_sample_database(
        source,
        values=("alpha-secret-row", "beta-secret-row"),
    )

    result = module.create_sqlite_database_backup_bundle(
        source,
        destination,
    )

    expected_result_keys = {
        "source_path",
        "backup_path",
        "size_bytes",
        "integrity_status",
        "manifest_path",
        "backup_sha256",
        "schema_fingerprint",
    }

    if set(result) != expected_result_keys:
        raise SystemExit(
            f"unexpected bundle result keys: {sorted(result)}"
        )

    manifest_path = Path(result["manifest_path"])

    if manifest_path != Path(
        str(destination.resolve()) + ".manifest.json"
    ):
        raise SystemExit(
            f"unexpected manifest path: {manifest_path}"
        )

    if not destination.is_file() or not manifest_path.is_file():
        raise SystemExit(
            "backup bundle did not create both required files"
        )

    manifest = load_manifest(manifest_path)

    expected_top_level = {
        "schema_version",
        "application",
        "created_at",
        "source",
        "backup",
        "sqlite",
        "schema",
    }

    if set(manifest) != expected_top_level:
        raise SystemExit(
            f"unexpected manifest keys: {sorted(manifest)}"
        )

    if (
        manifest["schema_version"]
        != "deltaaegis-backup-manifest-v1"
    ):
        raise SystemExit("incorrect manifest schema version")

    if manifest["application"] != {
        "name": "DeltaAegis",
        "version": "0.41.0",
    }:
        raise SystemExit(
            f"unexpected application metadata: "
            f"{manifest['application']}"
        )

    created_at = str(manifest["created_at"])

    if not created_at.endswith("Z"):
        raise SystemExit("manifest timestamp is not UTC Z format")

    datetime.fromisoformat(created_at.replace("Z", "+00:00"))

    if manifest["source"]["path"] != str(source.resolve()):
        raise SystemExit("manifest source path is incorrect")

    if int(manifest["source"]["size_bytes"]) <= 0:
        raise SystemExit("manifest source size is invalid")

    backup_metadata = manifest["backup"]

    if backup_metadata["filename"] != destination.name:
        raise SystemExit("manifest backup filename is incorrect")

    if backup_metadata["path"] != str(destination.resolve()):
        raise SystemExit("manifest backup path is incorrect")

    if backup_metadata["integrity_status"] != "ok":
        raise SystemExit("manifest integrity status is not ok")

    if int(backup_metadata["size_bytes"]) != destination.stat().st_size:
        raise SystemExit("manifest backup size is incorrect")

    actual_sha256 = sha256(destination)

    if backup_metadata["sha256"] != actual_sha256:
        raise SystemExit("manifest backup checksum is incorrect")

    if result["backup_sha256"] != actual_sha256:
        raise SystemExit("bundle result checksum is incorrect")

    sqlite_metadata = manifest["sqlite"]

    if int(sqlite_metadata["user_version"]) != 17:
        raise SystemExit("manifest user_version is incorrect")

    if int(sqlite_metadata["application_id"]) != 1145128263:
        raise SystemExit("manifest application_id is incorrect")

    for integer_key in (
        "schema_version",
        "page_size",
        "page_count",
    ):
        if int(sqlite_metadata[integer_key]) <= 0:
            raise SystemExit(
                f"manifest SQLite {integer_key} is invalid"
            )

    if not str(sqlite_metadata["library_version"]):
        raise SystemExit("manifest SQLite library version is empty")

    if not str(sqlite_metadata["journal_mode"]):
        raise SystemExit("manifest journal mode is empty")

    schema_metadata = manifest["schema"]

    if schema_metadata["fingerprint_algorithm"] != "sha256":
        raise SystemExit("schema fingerprint algorithm is incorrect")

    if len(str(schema_metadata["fingerprint"])) != 64:
        raise SystemExit("schema fingerprint length is incorrect")

    if int(schema_metadata["object_count"]) != 3:
        raise SystemExit(
            f"unexpected schema object count: "
            f"{schema_metadata['object_count']}"
        )

    if (
        result["schema_fingerprint"]
        != schema_metadata["fingerprint"]
    ):
        raise SystemExit(
            "bundle result schema fingerprint is incorrect"
        )

    manifest_text = manifest_path.read_text(encoding="utf-8")

    for forbidden_value in (
        "alpha-secret-row",
        "beta-secret-row",
    ):
        if forbidden_value in manifest_text:
            raise SystemExit(
                "manifest leaked database row content"
            )

    for protected_path in (destination, manifest_path):
        mode = stat.S_IMODE(protected_path.stat().st_mode)

        if mode & 0o077:
            raise SystemExit(
                f"backup artifact is too broadly readable: "
                f"{protected_path} mode={oct(mode)}"
            )

    same_schema_source = root / "same-schema.db"
    same_schema_destination = root / "same-schema-backup.db"

    create_sample_database(
        same_schema_source,
        values=("different-data",),
    )

    same_schema_result = (
        module.create_sqlite_database_backup_bundle(
            same_schema_source,
            same_schema_destination,
        )
    )

    if (
        same_schema_result["schema_fingerprint"]
        != result["schema_fingerprint"]
    ):
        raise SystemExit(
            "identical schemas produced different fingerprints"
        )

    changed_schema_source = root / "changed-schema.db"
    changed_schema_destination = (
        root / "changed-schema-backup.db"
    )

    create_sample_database(
        changed_schema_source,
        values=("different-data",),
        extra_schema=True,
    )

    changed_schema_result = (
        module.create_sqlite_database_backup_bundle(
            changed_schema_source,
            changed_schema_destination,
        )
    )

    if (
        changed_schema_result["schema_fingerprint"]
        == result["schema_fingerprint"]
    ):
        raise SystemExit(
            "changed schema did not change the fingerprint"
        )

    occupied_destination = root / "occupied-backup.db"
    occupied_manifest = module.database_backup_manifest_path(
        occupied_destination
    )
    occupied_manifest.write_text(
        "sentinel-manifest",
        encoding="utf-8",
    )

    try:
        module.create_sqlite_database_backup_bundle(
            source,
            occupied_destination,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "existing manifest was not rejected"
        )

    if occupied_destination.exists():
        raise SystemExit(
            "backup was created despite existing manifest"
        )

    if (
        occupied_manifest.read_text(encoding="utf-8")
        != "sentinel-manifest"
    ):
        raise SystemExit("existing manifest was modified")

    broken_destination = root / "broken-manifest-backup.db"
    broken_manifest = module.database_backup_manifest_path(
        broken_destination
    )
    missing_manifest_target = root / "missing-manifest-target"
    broken_manifest.symlink_to(missing_manifest_target)
    broken_link_value = os.readlink(broken_manifest)

    try:
        module.create_sqlite_database_backup_bundle(
            source,
            broken_destination,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "broken-symlink manifest was not rejected"
        )

    if broken_destination.exists():
        raise SystemExit(
            "backup was created despite broken manifest symlink"
        )

    if (
        not broken_manifest.is_symlink()
        or os.readlink(broken_manifest) != broken_link_value
    ):
        raise SystemExit(
            "broken manifest symlink was modified"
        )

    race_destination = root / "manifest-race-backup.db"
    race_manifest = module.database_backup_manifest_path(
        race_destination
    )
    real_link = module.os.link
    link_calls = 0

    def controlled_link(source_path, destination_path):
        global link_calls
        link_calls += 1

        if link_calls == 2:
            raise FileExistsError(
                "injected manifest publication race"
            )

        return real_link(source_path, destination_path)

    module.os.link = controlled_link

    try:
        try:
            module.create_sqlite_database_backup_bundle(
                source,
                race_destination,
            )
        except module.DeltaAegisError:
            pass
        else:
            raise SystemExit(
                "manifest publication failure was not surfaced"
            )
    finally:
        module.os.link = real_link

    if race_destination.exists():
        raise SystemExit(
            "failed manifest publication retained backup"
        )

    if os.path.lexists(race_manifest):
        raise SystemExit(
            "failed manifest publication retained manifest"
        )

    race_leftovers = list(
        root.glob(f".{race_destination.name}.*.tmp")
    ) + list(
        root.glob(f".{race_manifest.name}.*.tmp")
    )

    if race_leftovers:
        raise SystemExit(
            f"manifest publication left temporary files: "
            f"{race_leftovers}"
        )

    cli_destination = root / "cli-backup.db"

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
            "Checkpoint 2 CLI backup failed:\n"
            + cli_result.stdout
            + cli_result.stderr
        )

    for marker in (
        "DeltaAegis database backup completed.",
        "Manifest:",
        "Integrity: ok",
        "SHA-256:",
        "Schema fingerprint:",
    ):
        if marker not in cli_result.stdout:
            raise SystemExit(
                f"Checkpoint 2 CLI output is missing: {marker}"
            )

    cli_manifest = module.database_backup_manifest_path(
        cli_destination
    )

    if not cli_destination.is_file() or not cli_manifest.is_file():
        raise SystemExit(
            "Checkpoint 2 CLI did not create complete bundle"
        )

print("functional manifest behavior checks passed")
PY

echo "PASS: functional manifest behavior"

echo "[v0.41 checkpoint 2] backup sidecar ignore coverage"

for path in \
    "backups/deltaaegis-audit.db.manifest.json" \
    "backups/.deltaaegis-audit.db.manifest.json.tmp"
do
    if ! git check-ignore -q --no-index -- "$path"; then
        echo "FAIL: backup sidecar is not ignored: $path"
        exit 1
    fi
done

echo "PASS: backup sidecar ignore coverage"

echo "[v0.41 checkpoint 2] repository hygiene"

unexpected_paths="$(
    git status --short |
    grep -v -E \
        '^( M deltaaegis\.py|\?\? tools/validate_v0_41_backup_manifest\.sh)$' \
    || true
)"

if [ -n "$unexpected_paths" ]; then
    echo "FAIL: unexpected repository paths:"
    printf '%s\n' "$unexpected_paths"
    exit 1
fi

tracked_backup_artifacts="$(
    git ls-files |
    grep -Ei \
        '(^|/)backups?/|\.db(\.|$)|\.sqlite3?(\.|$)|\.manifest\.json$' \
    || true
)"

if [ -n "$tracked_backup_artifacts" ]; then
    echo "FAIL: backup or database artifacts are tracked:"
    printf '%s\n' "$tracked_backup_artifacts"
    exit 1
fi

temporary_artifacts="$(
    find . \
        -path './.git' -prune -o \
        -type f \
        \( \
            -name '.*.tmp' \
            -o -name '*.manifest.json' \
        \) \
        -print
)"

if [ -n "$temporary_artifacts" ]; then
    echo "FAIL: backup manifest artifacts remain in repository:"
    printf '%s\n' "$temporary_artifacts"
    exit 1
fi

echo "PASS: repository hygiene"
echo
echo "PASS: DeltaAegis v0.41 backup manifest validator"
