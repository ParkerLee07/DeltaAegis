#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

expected_feature_branch="feature/v0.41-data-durability-recovery"
current_branch="$(git branch --show-current)"

echo "DeltaAegis v0.41 Backup Catalog Validator"
echo "=========================================="

if [ "$current_branch" != "$expected_feature_branch" ] && \
   [ "$current_branch" != "main" ]; then
    echo "FAIL: expected branch $expected_feature_branch or main, found $current_branch"
    exit 1
fi

echo "[v0.41 checkpoint 4] source syntax"

python3 \
    -W error::SyntaxWarning \
    -m py_compile \
    deltaaegis.py

echo "PASS: source syntax"

echo "[v0.41 checkpoint 4] static catalog contract"

python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = (
    '"deltaaegis-backup-catalog-v1"',
    "def _database_backup_catalog_root(",
    "def _database_backup_catalog_entry(",
    "def catalog_database_backups(",
    "def inspect_database_backup_bundle(",
    "def command_backup_catalog(args) -> int:",
    "def command_backup_verify(args) -> int:",
    "verify_database_backup_bundle(",
    "root.iterdir()",
    '"VALID"',
    '"INVALID"',
    '"INCOMPLETE"',
    '"backup-catalog"',
    '"backup-verify"',
)

for marker in required:
    if marker not in text:
        raise SystemExit(
            f"missing catalog contract marker: {marker}"
        )

start = text.index(
    "# v0.41 checkpoint 4: backup catalog and verification CLI"
)
end = text.index(
    '# v0.41 checkpoint 5: backup retention planning and preview',
    start,
)
checkpoint = text[start:end]

for forbidden in (
    "unlink(",
    "rmdir(",
    "shutil.rmtree(",
    "os.remove(",
    "os.replace(",
    "os.rename(",
    "root.rglob(",
):
    if forbidden in checkpoint:
        raise SystemExit(
            f"forbidden catalog behavior found: {forbidden}"
        )

print("static catalog contract checks passed")
PY

echo "PASS: static catalog contract"

echo "[v0.41 checkpoint 4] functional catalog behavior"

python3 - <<'PY'
from __future__ import annotations

from pathlib import Path
import importlib.util
import json
import sqlite3
import subprocess
import sys
import tempfile


module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v041_checkpoint4"

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
            "CREATE TABLE catalog_records "
            "(id INTEGER PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO catalog_records(value) VALUES (?)",
            (value,),
        )
        connection.commit()
    finally:
        connection.close()


with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v041-catalog-"
) as temporary_directory:
    root = Path(temporary_directory)

    empty = module.catalog_database_backups(
        root / "missing-directory"
    )

    if empty["summary"] != {
        "total": 0,
        "valid": 0,
        "invalid": 0,
        "incomplete": 0,
    }:
        raise SystemExit(
            f"unexpected missing-directory summary: "
            f"{empty['summary']}"
        )

    if empty["directory_exists"]:
        raise SystemExit(
            "missing catalog directory was reported as existing"
        )

    backups = root / "backups"
    backups.mkdir()

    source_valid = root / "source-valid.db"
    create_database(source_valid, "valid-row")
    valid_backup = backups / "valid.db"

    module.create_sqlite_database_backup_bundle(
        source_valid,
        valid_backup,
    )

    source_invalid = root / "source-invalid.db"
    create_database(source_invalid, "invalid-row")
    invalid_backup = backups / "invalid.db"

    module.create_sqlite_database_backup_bundle(
        source_invalid,
        invalid_backup,
    )

    with invalid_backup.open("ab") as handle:
        handle.write(b"tampered")

    incomplete_backup = backups / "incomplete.db"
    incomplete_backup.write_bytes(b"not-a-complete-bundle")

    orphan_manifest = backups / "orphan.db.manifest.json"
    orphan_manifest.write_text(
        json.dumps({"schema_version": "orphan"}),
        encoding="utf-8",
    )

    historical = backups / "v035-historical-patch-backups"
    historical.mkdir()
    (historical / "deltaaegis.py.bak").write_text(
        "historical backup",
        encoding="utf-8",
    )
    (backups / "README.bak").write_text(
        "unrelated backup artifact",
        encoding="utf-8",
    )

    catalog = module.catalog_database_backups(backups)

    if catalog["schema_version"] != (
        "deltaaegis-backup-catalog-v1"
    ):
        raise SystemExit("incorrect catalog schema version")

    if catalog["summary"] != {
        "total": 4,
        "valid": 1,
        "invalid": 1,
        "incomplete": 2,
    }:
        raise SystemExit(
            f"unexpected catalog summary: {catalog['summary']}"
        )

    statuses = {
        Path(item["backup_path"]).name: item["status"]
        for item in catalog["entries"]
    }

    if statuses != {
        "valid.db": "VALID",
        "invalid.db": "INVALID",
        "incomplete.db": "INCOMPLETE",
        "orphan.db": "INCOMPLETE",
    }:
        raise SystemExit(
            f"unexpected catalog statuses: {statuses}"
        )

    catalog_paths = " ".join(
        str(item["backup_path"])
        for item in catalog["entries"]
    )

    if "v035-historical-patch-backups" in catalog_paths:
        raise SystemExit(
            "catalog descended into historical backup directories"
        )

    if "README.bak" in catalog_paths:
        raise SystemExit(
            "catalog included unrelated .bak files"
        )

    valid_entry = module.inspect_database_backup_bundle(
        valid_backup
    )

    if valid_entry["status"] != "VALID":
        raise SystemExit(
            f"valid bundle did not verify: {valid_entry}"
        )

    invalid_entry = module.inspect_database_backup_bundle(
        invalid_backup
    )

    if invalid_entry["status"] != "INVALID":
        raise SystemExit(
            f"tampered bundle was not invalid: {invalid_entry}"
        )

    incomplete_entry = module.inspect_database_backup_bundle(
        incomplete_backup
    )

    if incomplete_entry["status"] != "INCOMPLETE":
        raise SystemExit(
            "missing manifest was not classified INCOMPLETE"
        )

    before_paths = sorted(
        str(path.relative_to(root))
        for path in root.rglob("*")
    )
    before_bytes = {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }

    catalog_again = module.catalog_database_backups(backups)

    after_paths = sorted(
        str(path.relative_to(root))
        for path in root.rglob("*")
    )
    after_bytes = {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }

    if catalog_again["summary"] != catalog["summary"]:
        raise SystemExit(
            "repeat catalog produced a different summary"
        )

    if before_paths != after_paths or before_bytes != after_bytes:
        raise SystemExit(
            "catalog operation modified backup artifacts"
        )

    catalog_json = subprocess.run(
        [
            sys.executable,
            str(module_path),
            "backup-catalog",
            "--backups-dir",
            str(backups),
            "--json",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if catalog_json.returncode != 1:
        raise SystemExit(
            "catalog CLI did not return 1 for unhealthy catalog:\n"
            + catalog_json.stdout
            + catalog_json.stderr
        )

    catalog_payload = json.loads(catalog_json.stdout)

    if catalog_payload["summary"] != catalog["summary"]:
        raise SystemExit(
            "catalog CLI JSON summary is incorrect"
        )

    verify_valid = subprocess.run(
        [
            sys.executable,
            str(module_path),
            "backup-verify",
            str(valid_backup),
            "--json",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if verify_valid.returncode != 0:
        raise SystemExit(
            "valid backup-verify CLI failed:\n"
            + verify_valid.stdout
            + verify_valid.stderr
        )

    valid_payload = json.loads(verify_valid.stdout)

    if valid_payload["entry"]["status"] != "VALID":
        raise SystemExit(
            "valid backup-verify JSON status is incorrect"
        )

    verify_invalid = subprocess.run(
        [
            sys.executable,
            str(module_path),
            "backup-verify",
            str(invalid_backup),
            "--json",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if verify_invalid.returncode != 1:
        raise SystemExit(
            "invalid backup-verify CLI did not return 1"
        )

    invalid_payload = json.loads(verify_invalid.stdout)

    if invalid_payload["entry"]["status"] != "INVALID":
        raise SystemExit(
            "invalid backup-verify JSON status is incorrect"
        )

print("functional catalog behavior checks passed")
PY

echo "PASS: functional catalog behavior"

echo "[v0.41 checkpoint 4] CLI help"

catalog_help="$(
    python3 deltaaegis.py backup-catalog --help
)"

printf '%s\n' "$catalog_help" |
    grep -F "usage: deltaaegis.py backup-catalog" >/dev/null

printf '%s\n' "$catalog_help" |
    grep -F -- "--backups-dir" >/dev/null

printf '%s\n' "$catalog_help" |
    grep -F -- "--json" >/dev/null

verify_help="$(
    python3 deltaaegis.py backup-verify --help
)"

printf '%s\n' "$verify_help" |
    grep -F "usage: deltaaegis.py backup-verify" >/dev/null

printf '%s\n' "$verify_help" |
    grep -F -- "--manifest" >/dev/null

printf '%s\n' "$verify_help" |
    grep -F -- "--json" >/dev/null

echo "PASS: CLI help"

echo "[v0.41 checkpoint 4] repository hygiene"

unexpected_paths="$(
    git status --short |
    grep -v -E \
        '^( M deltaaegis\.py|\?\? tools/validate_v0_41_backup_catalog\.sh)$' \
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
echo "PASS: DeltaAegis v0.41 backup catalog validator"
