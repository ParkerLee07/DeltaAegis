#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

expected_branch="feature/v0.41-data-durability-recovery"

echo "DeltaAegis v0.41 Backup Retention Preview Validator"
echo "===================================================="

if [ "$(git branch --show-current)" != "$expected_branch" ]; then
    echo "FAIL: expected branch $expected_branch"
    exit 1
fi

echo "[v0.41 checkpoint 5] source syntax"

python3 \
    -W error::SyntaxWarning \
    -m py_compile \
    deltaaegis.py

echo "PASS: source syntax"

echo "[v0.41 checkpoint 5] static retention contract"

python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = (
    '"deltaaegis-backup-retention-plan-v1"',
    "def _database_backup_retention_timestamp(",
    "def plan_database_backup_retention(",
    "catalog_database_backups(",
    '"dry_run": True',
    '"destructive": False',
    '"execution_supported": False',
    '"KEEP"',
    '"ELIGIBLE"',
    '"PROTECTED"',
    "def command_backup_retention_preview(args) -> int:",
    '"backup-retention-preview"',
)

for marker in required:
    if marker not in text:
        raise SystemExit(
            f"missing retention contract marker: {marker}"
        )

start = text.index(
    "# v0.41 checkpoint 5: backup retention planning and preview"
)
end = text.index(
    '# v0.41 checkpoint 6: guarded backup retention execution',
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
    "subprocess.",
    "shell=True",
):
    if forbidden in checkpoint:
        raise SystemExit(
            f"forbidden retention-preview behavior found: "
            f"{forbidden}"
        )

print("static retention contract checks passed")
PY

echo "PASS: static retention contract"

echo "[v0.41 checkpoint 5] functional retention behavior"

python3 - <<'PY'
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import importlib.util
import json
import sqlite3
import subprocess
import sys
import tempfile


module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v041_checkpoint5"

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
            "CREATE TABLE retention_records "
            "(id INTEGER PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO retention_records(value) VALUES (?)",
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


with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v041-retention-"
) as temporary_directory:
    root = Path(temporary_directory)
    backups = root / "backups"
    backups.mkdir()
    now = datetime(2026, 7, 8, 12, 0, tzinfo=timezone.utc)

    normal_ages = (1, 8, 18, 40, 70, 100)
    normal_backups: list[Path] = []

    for index, age_days in enumerate(normal_ages, start=1):
        source = root / f"source-{index}.db"
        backup = backups / f"backup-{index}.db"
        create_database(source, f"row-{index}")

        module.create_sqlite_database_backup_bundle(
            source,
            backup,
        )

        created_at = (
            now - timedelta(days=age_days)
        ).replace(microsecond=0).isoformat().replace(
            "+00:00",
            "Z",
        )
        set_created_at(backup, created_at)
        normal_backups.append(backup)

    malformed_source = root / "source-malformed.db"
    malformed_backup = backups / "malformed.db"
    create_database(malformed_source, "malformed-time")
    module.create_sqlite_database_backup_bundle(
        malformed_source,
        malformed_backup,
    )
    set_created_at(malformed_backup, "not-a-timestamp")

    invalid_source = root / "source-invalid.db"
    invalid_backup = backups / "invalid.db"
    create_database(invalid_source, "invalid-row")
    module.create_sqlite_database_backup_bundle(
        invalid_source,
        invalid_backup,
    )

    with invalid_backup.open("ab") as handle:
        handle.write(b"tampered")

    incomplete_backup = backups / "incomplete.db"
    incomplete_backup.write_bytes(b"incomplete")

    before_paths = sorted(
        str(path.relative_to(root))
        for path in root.rglob("*")
    )
    before_bytes = {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }

    plan = module.plan_database_backup_retention(
        backups,
        keep_newest=2,
        minimum_age_days=30,
        now=now,
    )

    if plan["schema_version"] != (
        "deltaaegis-backup-retention-plan-v1"
    ):
        raise SystemExit("incorrect retention schema version")

    if (
        plan["dry_run"] is not True
        or plan["destructive"] is not False
        or plan["execution_supported"] is not False
    ):
        raise SystemExit(
            "retention preview is not explicitly non-destructive"
        )

    if plan["summary"] != {
        "total": 9,
        "keep": 3,
        "eligible": 3,
        "protected": 3,
        "eligible_bytes": sum(
            backup.stat().st_size
            for backup in normal_backups[3:]
        ),
    }:
        raise SystemExit(
            f"unexpected retention summary: {plan['summary']}"
        )

    actions = {
        Path(item["backup_path"]).name: (
            item["retention_action"]
        )
        for item in plan["entries"]
    }

    expected_actions = {
        "backup-1.db": "KEEP",
        "backup-2.db": "KEEP",
        "backup-3.db": "KEEP",
        "backup-4.db": "ELIGIBLE",
        "backup-5.db": "ELIGIBLE",
        "backup-6.db": "ELIGIBLE",
        "malformed.db": "PROTECTED",
        "invalid.db": "PROTECTED",
        "incomplete.db": "PROTECTED",
    }

    if actions != expected_actions:
        raise SystemExit(
            f"unexpected retention actions: {actions}"
        )

    for item in plan["entries"]:
        if item["retention_action"] == "ELIGIBLE":
            if item["status"] != "VALID":
                raise SystemExit(
                    "non-valid bundle was marked ELIGIBLE"
                )

            if item["valid_rank"] <= 2:
                raise SystemExit(
                    "newest protected backup was marked ELIGIBLE"
                )

            if item["age_days"] < 30:
                raise SystemExit(
                    "too-young backup was marked ELIGIBLE"
                )

    malformed_item = next(
        item
        for item in plan["entries"]
        if Path(item["backup_path"]).name == "malformed.db"
    )

    if "timestamp" not in malformed_item["retention_reason"]:
        raise SystemExit(
            "timestamp anomaly did not explain protection"
        )

    after_paths = sorted(
        str(path.relative_to(root))
        for path in root.rglob("*")
    )
    after_bytes = {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }

    if before_paths != after_paths or before_bytes != after_bytes:
        raise SystemExit(
            "retention preview modified backup artifacts"
        )

    try:
        module.plan_database_backup_retention(
            backups,
            keep_newest=0,
            minimum_age_days=30,
            now=now,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "zero keep-newest policy was accepted"
        )

    try:
        module.plan_database_backup_retention(
            backups,
            keep_newest=2,
            minimum_age_days=-1,
            now=now,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "negative minimum age was accepted"
        )

    cli = subprocess.run(
        [
            sys.executable,
            str(module_path),
            "backup-retention-preview",
            "--backups-dir",
            str(backups),
            "--keep-newest",
            "2",
            "--minimum-age-days",
            "30",
            "--json",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if cli.returncode != 1:
        raise SystemExit(
            "retention preview CLI did not return 1 when "
            "protected entries require review:\n"
            + cli.stdout
            + cli.stderr
        )

    payload = json.loads(cli.stdout)

    if payload["summary"]["protected"] != 3:
        raise SystemExit(
            "retention preview CLI protected count is incorrect"
        )

    if (
        payload["dry_run"] is not True
        or payload["execution_supported"] is not False
    ):
        raise SystemExit(
            "retention preview CLI is not explicitly preview-only"
        )

    invalid_cli = subprocess.run(
        [
            sys.executable,
            str(module_path),
            "backup-retention-preview",
            "--keep-newest",
            "0",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if invalid_cli.returncode == 0:
        raise SystemExit(
            "CLI accepted --keep-newest 0"
        )

print("functional retention behavior checks passed")
PY

echo "PASS: functional retention behavior"

echo "[v0.41 checkpoint 5] CLI help"

help_text="$(
    python3 deltaaegis.py backup-retention-preview --help
)"

printf '%s\n' "$help_text" |
    grep -F \
        "usage: deltaaegis.py backup-retention-preview" \
        >/dev/null

for flag in \
    "--backups-dir" \
    "--keep-newest" \
    "--minimum-age-days" \
    "--json"
do
    printf '%s\n' "$help_text" |
        grep -F -- "$flag" >/dev/null
done

echo "PASS: CLI help"

echo "[v0.41 checkpoint 5] repository hygiene"

unexpected_paths="$(
    git status --short |
    grep -v -E \
        '^( M deltaaegis\.py|\?\? tools/validate_v0_41_backup_retention_preview\.sh)$' \
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
echo "PASS: DeltaAegis v0.41 backup retention preview validator"
