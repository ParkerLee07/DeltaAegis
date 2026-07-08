#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

expected_branch="feature/v0.41-data-durability-recovery"

echo "DeltaAegis v0.41 Restore Cutover Preview Validator"
echo "==================================================="

if [ "$(git branch --show-current)" != "$expected_branch" ]; then
    echo "FAIL: expected branch $expected_branch"
    exit 1
fi

echo "[v0.41 checkpoint 7] source syntax"

python3 \
    -W error::SyntaxWarning \
    -m py_compile \
    deltaaegis.py

echo "PASS: source syntax"

echo "[v0.41 checkpoint 7] static preview contract"

python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = (
    '"deltaaegis-restore-cutover-plan-v1"',
    "def _database_restore_cutover_absolute_path(",
    "def _database_restore_cutover_file_identity(",
    "def _database_restore_cutover_sidecars(",
    "def _database_restore_cutover_dashboard_processes(",
    "def _database_restore_cutover_active_state(",
    '"inspection_skipped_reason"',
    "inspect_database=not bool(sidecars)",
    "def _database_restore_cutover_safety_backup_state(",
    "def _database_restore_cutover_plan_digest(",
    "def plan_database_restore_cutover(",
    "verify_database_backup_bundle(",
    '"dry_run": True',
    '"destructive": False',
    '"execution_supported": False',
    '"cutover_ready"',
    '"DASHBOARD_PROCESS_ACTIVE"',
    '"SQLITE_SIDECARS_PRESENT"',
    '"SAFETY_BACKUP_DIRECTORY_MISSING"',
    "def command_restore_cutover_preview(args) -> int:",
    '"restore-cutover-preview"',
)

for marker in required:
    if marker not in text:
        raise SystemExit(
            f"missing restore cutover preview marker: {marker}"
        )

start = text.index(
    "# v0.41 checkpoint 7: active restore cutover preview"
)
end = text.index(
    '# v0.41 checkpoint 8: guarded active restore cutover execution',
    start,
)
checkpoint = text[start:end]

for forbidden in (
    ".mkdir(",
    ".unlink(",
    ".rmdir(",
    "tempfile.",
    "os.link(",
    "os.remove(",
    "os.replace(",
    "os.rename(",
    "shutil.rmtree(",
    "subprocess.",
    "shell=True",
):
    if forbidden in checkpoint:
        raise SystemExit(
            f"forbidden restore preview behavior found: "
            f"{forbidden}"
        )

print("static restore cutover preview checks passed")
PY

echo "PASS: static preview contract"

echo "[v0.41 checkpoint 7] functional preview behavior"

python3 - <<'PY'
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import tempfile


module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v041_checkpoint7"

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
            "CREATE TABLE restore_cutover_records "
            "(id INTEGER PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO restore_cutover_records(value) "
            "VALUES (?)",
            (value,),
        )
        connection.commit()
    finally:
        connection.close()


def snapshot(root: Path) -> tuple[list[str], dict[str, bytes]]:
    paths = sorted(
        str(path.relative_to(root))
        for path in root.rglob("*")
    )
    contents = {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }
    return paths, contents


def write_fake_cmdline(
    process_root: Path,
    pid: int,
    argv: list[str],
) -> None:
    process_directory = process_root / str(pid)
    process_directory.mkdir()
    (process_directory / "cmdline").write_bytes(
        b"\0".join(
            argument.encode("utf-8")
            for argument in argv
        )
        + b"\0"
    )


with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v041-cutover-preview-"
) as temporary_directory:
    root = Path(temporary_directory)
    data = root / "data"
    backups = root / "backups"
    process_root = root / "proc"
    data.mkdir()
    backups.mkdir()
    process_root.mkdir()
    active = data / "deltaaegis.db"
    source = root / "backup-source.db"
    backup = backups / "restore.db"
    create_database(active, "active")
    create_database(source, "restore")
    module.create_sqlite_database_backup_bundle(
        source,
        backup,
    )
    now = datetime(2026, 7, 8, 12, 0, tzinfo=timezone.utc)
    before = snapshot(root)

    plan = module.plan_database_restore_cutover(
        active,
        backup,
        safety_backups_dir=backups,
        now=now,
        process_root=process_root,
        current_pid=99999,
    )

    if plan["schema_version"] != (
        "deltaaegis-restore-cutover-plan-v1"
    ):
        raise SystemExit(
            "incorrect restore cutover plan schema"
        )

    if (
        plan["dry_run"] is not True
        or plan["destructive"] is not False
        or plan["execution_supported"] is not False
    ):
        raise SystemExit(
            "restore cutover preview is not explicitly "
            "non-destructive"
        )

    if not plan["cutover_ready"]:
        raise SystemExit(
            f"healthy cutover preview was blocked: "
            f"{plan['blockers']}"
        )

    if plan["blockers"]:
        raise SystemExit(
            f"healthy cutover preview has blockers: "
            f"{plan['blockers']}"
        )

    if plan["backup"]["status"] != "VALID":
        raise SystemExit(
            "verified restore backup was not marked VALID"
        )

    if len(plan["plan_digest"]) != 64:
        raise SystemExit(
            "restore cutover plan digest is not SHA-256"
        )

    if not plan["safety_backup"]["required"]:
        raise SystemExit(
            "fresh safety backup was not required"
        )

    if not plan["required_steps"]:
        raise SystemExit(
            "restore cutover plan has no execution sequence"
        )

    after = snapshot(root)

    if before != after:
        raise SystemExit(
            "healthy cutover preview modified filesystem state"
        )

    wal_path = Path(str(active) + "-wal")
    wal_path.write_bytes(b"wal-present")
    wal_before = snapshot(root)

    wal_plan = module.plan_database_restore_cutover(
        active,
        backup,
        safety_backups_dir=backups,
        now=now,
        process_root=process_root,
        current_pid=99999,
    )

    wal_codes = {
        blocker["code"]
        for blocker in wal_plan["blockers"]
    }

    if "SQLITE_SIDECARS_PRESENT" not in wal_codes:
        raise SystemExit(
            "SQLite WAL sidecar was not a cutover blocker"
        )

    if (
        wal_plan["active_database"].get(
            "inspection_skipped_reason"
        )
        is None
    ):
        raise SystemExit(
            "active database inspection was not skipped "
            "while a SQLite sidecar was present"
        )

    if (
        wal_plan["active_database"].get("sha256")
        is not None
        or wal_plan["active_database"].get(
            "logical_fingerprint"
        )
        is not None
    ):
        raise SystemExit(
            "sidecar-blocked preview still opened the active "
            "database for content inspection"
        )

    if wal_plan["cutover_ready"]:
        raise SystemExit(
            "cutover with SQLite sidecar was marked ready"
        )

    if wal_before != snapshot(root):
        raise SystemExit(
            "sidecar preview modified filesystem state"
        )

    wal_path.unlink()

    write_fake_cmdline(
        process_root,
        4242,
        [
            sys.executable,
            str(module_path),
            "--db",
            str(active),
            "dashboard",
        ],
    )
    process_before = snapshot(root)

    process_plan = module.plan_database_restore_cutover(
        active,
        backup,
        safety_backups_dir=backups,
        now=now,
        process_root=process_root,
        current_pid=99999,
    )

    process_codes = {
        blocker["code"]
        for blocker in process_plan["blockers"]
    }

    if "DASHBOARD_PROCESS_ACTIVE" not in process_codes:
        raise SystemExit(
            "active dashboard process was not a blocker"
        )

    if process_plan["cutover_ready"]:
        raise SystemExit(
            "cutover with active dashboard was marked ready"
        )

    if process_before != snapshot(root):
        raise SystemExit(
            "process-blocked preview modified filesystem state"
        )

    (process_root / "4242" / "cmdline").unlink()
    (process_root / "4242").rmdir()

    invalid_backup = backups / "invalid.db"
    invalid_source = root / "invalid-source.db"
    create_database(invalid_source, "invalid")
    module.create_sqlite_database_backup_bundle(
        invalid_source,
        invalid_backup,
    )

    with invalid_backup.open("ab") as handle:
        handle.write(b"tampered")

    invalid_before = snapshot(root)

    invalid_plan = module.plan_database_restore_cutover(
        active,
        invalid_backup,
        safety_backups_dir=backups,
        now=now,
        process_root=process_root,
        current_pid=99999,
    )

    invalid_codes = {
        blocker["code"]
        for blocker in invalid_plan["blockers"]
    }

    if "BACKUP_NOT_VERIFIED" not in invalid_codes:
        raise SystemExit(
            "invalid backup was not blocked"
        )

    if invalid_before != snapshot(root):
        raise SystemExit(
            "invalid-backup preview modified filesystem state"
        )

    missing_process_plan = (
        module.plan_database_restore_cutover(
            active,
            backup,
            safety_backups_dir=backups,
            now=now,
            process_root=root / "missing-proc",
            current_pid=99999,
        )
    )

    missing_process_codes = {
        blocker["code"]
        for blocker in missing_process_plan["blockers"]
    }

    if "PROCESS_PROBE_UNAVAILABLE" not in (
        missing_process_codes
    ):
        raise SystemExit(
            "unavailable process probe was not blocked"
        )

    alias_root = root / "alias"
    alias_data = alias_root / "data"
    alias_backups = alias_root / "backups"
    alias_proc = alias_root / "proc"
    alias_data.mkdir(parents=True)
    alias_backups.mkdir()
    alias_proc.mkdir()
    alias_active = alias_data / "deltaaegis.db"
    create_database(alias_active, "alias-active")
    alias_backup = alias_backups / "alias.db"
    os.link(alias_active, alias_backup)
    alias_manifest = module.database_backup_manifest_path(
        alias_backup
    )
    alias_manifest.write_text(
        "{}\n",
        encoding="utf-8",
    )

    alias_plan = module.plan_database_restore_cutover(
        alias_active,
        alias_backup,
        manifest_path=alias_manifest,
        safety_backups_dir=alias_backups,
        now=now,
        process_root=alias_proc,
        current_pid=99999,
    )

    alias_codes = {
        blocker["code"]
        for blocker in alias_plan["blockers"]
    }

    if "BACKUP_NOT_VERIFIED" not in alias_codes:
        raise SystemExit(
            "active database hard-link alias was not blocked"
        )

    cli_root = root / "cli"
    cli_data = cli_root / "data"
    cli_backups = cli_root / "backups"
    cli_data.mkdir(parents=True)
    cli_backups.mkdir()
    cli_active = cli_data / "deltaaegis.db"
    cli_source = cli_root / "source.db"
    cli_backup = cli_backups / "restore.db"
    create_database(cli_active, "cli-active")
    create_database(cli_source, "cli-restore")
    module.create_sqlite_database_backup_bundle(
        cli_source,
        cli_backup,
    )

    cli = subprocess.run(
        [
            sys.executable,
            str(module_path),
            "--db",
            str(cli_active),
            "restore-cutover-preview",
            str(cli_backup),
            "--safety-backups-dir",
            str(cli_backups),
            "--json",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if cli.returncode != 0:
        raise SystemExit(
            "healthy restore cutover preview CLI failed:\n"
            + cli.stdout
            + cli.stderr
        )

    cli_payload = json.loads(cli.stdout)

    if not cli_payload["cutover_ready"]:
        raise SystemExit(
            "healthy CLI cutover preview was not ready"
        )

    if cli_payload["execution_supported"] is not False:
        raise SystemExit(
            "CLI preview incorrectly supports execution"
        )

print("functional restore cutover preview checks passed")
PY

echo "PASS: functional preview behavior"

echo "[v0.41 checkpoint 7] CLI help"

help_text="$(
    python3 deltaaegis.py restore-cutover-preview --help
)"

printf '%s\n' "$help_text" |
    grep -F \
        "usage: deltaaegis.py restore-cutover-preview" \
        >/dev/null

for flag in \
    "--manifest" \
    "--safety-backups-dir" \
    "--json"
do
    printf '%s\n' "$help_text" |
        grep -F -- "$flag" >/dev/null
done

echo "PASS: CLI help"

echo "[v0.41 checkpoint 7] repository hygiene"

unexpected_paths="$(
    git status --short |
    grep -v -E \
        '^( M deltaaegis\.py|\?\? tools/validate_v0_41_restore_cutover_preview\.sh)$' \
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
        '(^|/)(data|backups?|restore-rehearsals?)/|\.db(\.|$)|\.sqlite3?(\.|$)|\.manifest\.json$|-(wal|shm|journal)$' \
    || true
)"

if [ -n "$tracked_artifacts" ]; then
    echo "FAIL: database or restore artifacts are tracked:"
    printf '%s\n' "$tracked_artifacts"
    exit 1
fi

echo "PASS: repository hygiene"
echo
echo "PASS: DeltaAegis v0.41 restore cutover preview validator"
