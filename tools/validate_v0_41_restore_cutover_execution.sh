#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

expected_branch="feature/v0.41-data-durability-recovery"

echo "DeltaAegis v0.41 Restore Cutover Execution Validator"
echo "====================================================="

if [ "$(git branch --show-current)" != "$expected_branch" ]; then
    echo "FAIL: expected branch $expected_branch"
    exit 1
fi

echo "[v0.41 checkpoint 8] source syntax"

python3 \
    -W error::SyntaxWarning \
    -m py_compile \
    deltaaegis.py

echo "PASS: source syntax"

echo "[v0.41 checkpoint 8] static execution contract"

python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = (
    '"deltaaegis-restore-cutover-receipt-v1"',
    '"RESTORE ACTIVE DELTAAEGIS DATABASE"',
    "def _database_restore_cutover_unique_path(",
    "def _database_restore_cutover_verify_expected(",
    "def _database_restore_cutover_recheck_inputs(",
    "def _database_restore_cutover_remove_identity_path(",
    "def execute_database_restore_cutover(",
    "expected_plan_digest",
    "create_sqlite_database_backup_bundle(",
    "verify_database_backup_bundle(",
    "create_database_restore_rehearsal(",
    "os.link(",
    "follow_symlinks=False",
    "os.replace(",
    "_database_backup_retention_fsync_directory(",
    '"COMPLETED"',
    '"ROLLED_BACK"',
    '"FAILED"',
    '"rollback_attempted"',
    '"rollback_completed"',
    "def command_restore_cutover_execute(args) -> int:",
    '"restore-cutover-execute"',
)

for marker in required:
    if marker not in text:
        raise SystemExit(
            f"missing restore cutover execution marker: "
            f"{marker}"
        )

start = text.index(
    "# v0.41 checkpoint 8: guarded active restore cutover execution"
)
end = text.index(
    "def build_parser() -> argparse.ArgumentParser:",
    start,
)
checkpoint = text[start:end]

for forbidden in (
    "shutil.rmtree(",
    "os.remove(",
    "subprocess.",
    "shell=True",
    "rglob(",
):
    if forbidden in checkpoint:
        raise SystemExit(
            f"forbidden restore cutover operation found: "
            f"{forbidden}"
        )

if checkpoint.count("os.replace(") != 2:
    raise SystemExit(
        "restore cutover should contain exactly two atomic "
        "replace call sites"
    )

if checkpoint.count("os.link(") != 1:
    raise SystemExit(
        "restore cutover should contain exactly one rollback "
        "hard-link call site"
    )

print("static restore cutover execution checks passed")
PY

echo "PASS: static execution contract"

echo "[v0.41 checkpoint 8] functional execution behavior"

python3 - <<'PY'
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import tempfile


module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v041_checkpoint8"

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
            "CREATE TABLE restore_execution_records "
            "(id INTEGER PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO restore_execution_records(value) "
            "VALUES (?)",
            (value,),
        )
        connection.commit()
    finally:
        connection.close()


def database_value(path: Path) -> str:
    connection = sqlite3.connect(
        path.as_uri() + "?mode=ro",
        uri=True,
    )

    try:
        row = connection.execute(
            "SELECT value FROM restore_execution_records "
            "ORDER BY id LIMIT 1"
        ).fetchone()
    finally:
        connection.close()

    return str(row[0])


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


def create_fixture(
    root: Path,
    name: str,
) -> tuple[Path, Path, Path, Path]:
    fixture = root / name
    data = fixture / "data"
    backups = fixture / "backups"
    process_root = fixture / "proc"
    data.mkdir(parents=True)
    backups.mkdir()
    process_root.mkdir()
    active = data / "deltaaegis.db"
    source = fixture / "restore-source.db"
    backup = backups / "restore.db"
    create_database(active, f"{name}-active")
    create_database(source, f"{name}-restore")
    module.create_sqlite_database_backup_bundle(
        source,
        backup,
    )
    return active, backup, backups, process_root


def plan_for(
    active: Path,
    backup: Path,
    backups: Path,
    process_root: Path,
    now: datetime,
) -> dict:
    return module.plan_database_restore_cutover(
        active,
        backup,
        safety_backups_dir=backups,
        now=now,
        process_root=process_root,
        current_pid=99999,
    )


def cutover_residue(data_directory: Path) -> list[Path]:
    return [
        path
        for path in data_directory.iterdir()
        if path.name.startswith(
            ".deltaaegis-restore-"
        )
    ]


with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v041-cutover-execution-"
) as temporary_directory:
    root = Path(temporary_directory)
    now = datetime(2026, 7, 8, 12, 0, tzinfo=timezone.utc)

    active, backup, backups, process_root = (
        create_fixture(root, "confirmation")
    )
    plan = plan_for(
        active,
        backup,
        backups,
        process_root,
        now,
    )
    before = snapshot(root / "confirmation")

    try:
        module.execute_database_restore_cutover(
            active,
            backup,
            safety_backups_dir=backups,
            expected_plan_digest=plan["plan_digest"],
            confirmation="RESTORE DATABASE",
            now=now,
            process_root=process_root,
            current_pid=99999,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "incorrect cutover confirmation was accepted"
        )

    if before != snapshot(root / "confirmation"):
        raise SystemExit(
            "incorrect confirmation modified filesystem state"
        )

    try:
        module.execute_database_restore_cutover(
            active,
            backup,
            safety_backups_dir=backups,
            expected_plan_digest="0" * 64,
            confirmation=(
                module.DATABASE_RESTORE_CUTOVER_EXECUTION_CONFIRMATION
            ),
            now=now,
            process_root=process_root,
            current_pid=99999,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "stale cutover plan digest was accepted"
        )

    if before != snapshot(root / "confirmation"):
        raise SystemExit(
            "stale plan digest modified filesystem state"
        )

    stable_plan_later = plan_for(
        active,
        backup,
        backups,
        process_root,
        now + timedelta(minutes=5),
    )

    if stable_plan_later["plan_digest"] != plan["plan_digest"]:
        raise SystemExit(
            "cutover plan digest changed only because time advanced"
        )

    healthy_active, healthy_backup, healthy_backups, healthy_proc = (
        create_fixture(root, "healthy")
    )
    healthy_old_value = database_value(healthy_active)
    healthy_restore_value = database_value(healthy_backup)
    healthy_backup_before = healthy_backup.read_bytes()
    healthy_manifest = (
        module.database_backup_manifest_path(
            healthy_backup
        )
    )
    healthy_manifest_before = (
        healthy_manifest.read_bytes()
    )
    healthy_plan = plan_for(
        healthy_active,
        healthy_backup,
        healthy_backups,
        healthy_proc,
        now,
    )
    healthy_receipt = (
        module.execute_database_restore_cutover(
            healthy_active,
            healthy_backup,
            safety_backups_dir=healthy_backups,
            expected_plan_digest=(
                healthy_plan["plan_digest"]
            ),
            confirmation=(
                module.DATABASE_RESTORE_CUTOVER_EXECUTION_CONFIRMATION
            ),
            now=now,
            process_root=healthy_proc,
            current_pid=99999,
        )
    )

    if healthy_receipt["status"] != "COMPLETED":
        raise SystemExit(
            f"healthy cutover did not complete: "
            f"{healthy_receipt}"
        )

    if healthy_receipt["review_required"]:
        raise SystemExit(
            "healthy cutover unexpectedly requires review"
        )

    if database_value(healthy_active) != healthy_restore_value:
        raise SystemExit(
            "active database does not contain restored data"
        )

    if database_value(healthy_active) == healthy_old_value:
        raise SystemExit(
            "active database still contains original data"
        )

    safety_path = Path(
        healthy_receipt["safety_backup_path"]
    )
    safety_manifest = Path(
        healthy_receipt["safety_manifest_path"]
    )

    if not safety_path.is_file():
        raise SystemExit(
            "fresh safety backup was not retained"
        )

    if not safety_manifest.is_file():
        raise SystemExit(
            "fresh safety manifest was not retained"
        )

    if database_value(safety_path) != healthy_old_value:
        raise SystemExit(
            "fresh safety backup does not contain original data"
        )

    if healthy_backup.read_bytes() != healthy_backup_before:
        raise SystemExit(
            "restore backup changed during cutover"
        )

    if healthy_manifest.read_bytes() != healthy_manifest_before:
        raise SystemExit(
            "restore manifest changed during cutover"
        )

    if cutover_residue(healthy_active.parent):
        raise SystemExit(
            "successful cutover left temporary data-directory residue"
        )

    for suffix in ("-wal", "-shm", "-journal"):
        if os.path.lexists(
            Path(str(healthy_active) + suffix)
        ):
            raise SystemExit(
                "successful cutover left SQLite sidecar residue"
            )

    side_active, side_backup, side_backups, side_proc = (
        create_fixture(root, "sidecar")
    )
    side_plan = plan_for(
        side_active,
        side_backup,
        side_backups,
        side_proc,
        now,
    )
    sidecar = Path(str(side_active) + "-wal")
    sidecar.write_bytes(b"present")
    side_before = snapshot(root / "sidecar")

    try:
        module.execute_database_restore_cutover(
            side_active,
            side_backup,
            safety_backups_dir=side_backups,
            expected_plan_digest=side_plan["plan_digest"],
            confirmation=(
                module.DATABASE_RESTORE_CUTOVER_EXECUTION_CONFIRMATION
            ),
            now=now,
            process_root=side_proc,
            current_pid=99999,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "sidecar appearing after preview was accepted"
        )

    if side_before != snapshot(root / "sidecar"):
        raise SystemExit(
            "sidecar-blocked execution modified filesystem state"
        )

    rollback_active, rollback_backup, rollback_backups, rollback_proc = (
        create_fixture(root, "rollback")
    )
    rollback_old_value = database_value(
        rollback_active
    )
    rollback_plan = plan_for(
        rollback_active,
        rollback_backup,
        rollback_backups,
        rollback_proc,
        now,
    )
    original_verifier = (
        module._database_restore_cutover_verify_expected
    )

    def injected_verifier(
        database_path: Path,
        *,
        expected_logical_fingerprint: str,
        expected_schema_fingerprint: str,
        verification_context: str,
    ):
        if verification_context == "restored active":
            raise module.DeltaAegisError(
                "injected post-cutover verification failure"
            )

        return original_verifier(
            database_path,
            expected_logical_fingerprint=(
                expected_logical_fingerprint
            ),
            expected_schema_fingerprint=(
                expected_schema_fingerprint
            ),
            verification_context=verification_context,
        )

    module._database_restore_cutover_verify_expected = (
        injected_verifier
    )

    try:
        rollback_receipt = (
            module.execute_database_restore_cutover(
                rollback_active,
                rollback_backup,
                safety_backups_dir=rollback_backups,
                expected_plan_digest=(
                    rollback_plan["plan_digest"]
                ),
                confirmation=(
                    module.DATABASE_RESTORE_CUTOVER_EXECUTION_CONFIRMATION
                ),
                now=now,
                process_root=rollback_proc,
                current_pid=99999,
            )
        )
    finally:
        module._database_restore_cutover_verify_expected = (
            original_verifier
        )

    if rollback_receipt["status"] != "ROLLED_BACK":
        raise SystemExit(
            f"injected failure did not roll back: "
            f"{rollback_receipt}"
        )

    if not rollback_receipt["rollback_completed"]:
        raise SystemExit(
            "rollback receipt did not record completion"
        )

    if database_value(rollback_active) != rollback_old_value:
        raise SystemExit(
            "rolled-back active database does not contain "
            "the original data"
        )

    if not Path(
        rollback_receipt["safety_backup_path"]
    ).is_file():
        raise SystemExit(
            "rollback path did not retain the safety backup"
        )

    if cutover_residue(rollback_active.parent):
        raise SystemExit(
            "rolled-back cutover left temporary residue"
        )

    process_active, process_backup, process_backups, process_proc = (
        create_fixture(root, "process")
    )
    process_plan = plan_for(
        process_active,
        process_backup,
        process_backups,
        process_proc,
        now,
    )
    process_directory = process_proc / "4242"
    process_directory.mkdir()
    (process_directory / "cmdline").write_bytes(
        b"\0".join(
            argument.encode("utf-8")
            for argument in (
                sys.executable,
                str(module_path),
                "--db",
                str(process_active),
                "dashboard",
            )
        )
        + b"\0"
    )
    process_before = snapshot(root / "process")

    try:
        module.execute_database_restore_cutover(
            process_active,
            process_backup,
            safety_backups_dir=process_backups,
            expected_plan_digest=(
                process_plan["plan_digest"]
            ),
            confirmation=(
                module.DATABASE_RESTORE_CUTOVER_EXECUTION_CONFIRMATION
            ),
            now=now,
            process_root=process_proc,
            current_pid=99999,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise SystemExit(
            "dashboard appearing after preview was accepted"
        )

    if process_before != snapshot(root / "process"):
        raise SystemExit(
            "process-blocked execution modified filesystem state"
        )

    cli_root = root / "cli"
    cli_active, cli_backup, cli_backups, _cli_proc = (
        create_fixture(root, "cli")
    )
    cli_plan = module.plan_database_restore_cutover(
        cli_active,
        cli_backup,
        safety_backups_dir=cli_backups,
        now=now,
        process_root=Path("/proc"),
        current_pid=os.getpid(),
    )

    if not cli_plan["cutover_ready"]:
        raise SystemExit(
            f"CLI fixture unexpectedly blocked: "
            f"{cli_plan['blockers']}"
        )

    cli = subprocess.run(
        [
            sys.executable,
            str(module_path),
            "--db",
            str(cli_active),
            "restore-cutover-execute",
            str(cli_backup),
            "--safety-backups-dir",
            str(cli_backups),
            "--plan-digest",
            cli_plan["plan_digest"],
            "--confirmation",
            "RESTORE ACTIVE DELTAAEGIS DATABASE",
            "--json",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if cli.returncode != 0:
        raise SystemExit(
            "healthy restore cutover CLI failed:\n"
            + cli.stdout
            + cli.stderr
        )

    cli_payload = json.loads(cli.stdout)

    if cli_payload["status"] != "COMPLETED":
        raise SystemExit(
            "CLI cutover receipt did not report COMPLETED"
        )

print("functional restore cutover execution checks passed")
PY

echo "PASS: functional execution behavior"

echo "[v0.41 checkpoint 8] CLI help"

help_text="$(
    python3 deltaaegis.py restore-cutover-execute --help
)"

HELP_TEXT="$help_text" python3 - <<'PY'
import os

help_text = os.environ["HELP_TEXT"]
normalized = " ".join(help_text.split())

required_markers = (
    "usage: deltaaegis.py restore-cutover-execute",
    "--manifest",
    "--safety-backups-dir",
    "--plan-digest",
    "--confirmation",
    "--json",
    "RESTORE ACTIVE DELTAAEGIS DATABASE",
)

for marker in required_markers:
    if marker not in normalized:
        raise SystemExit(
            f"restore-cutover-execute help is missing: {marker}"
        )

print("restore cutover execution CLI help checks passed")
PY

echo "PASS: CLI help"

echo "[v0.41 checkpoint 8] repository hygiene"

unexpected_paths="$(
    git status --short |
    grep -v -E \
        '^( M deltaaegis\.py|\?\? tools/validate_v0_41_restore_cutover_execution\.sh)$' \
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
echo "PASS: DeltaAegis v0.41 restore cutover execution validator"
