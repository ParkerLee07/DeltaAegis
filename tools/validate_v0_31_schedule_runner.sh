#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

grep -Fq 'def run_due_scan_schedules(' deltaaegis.py \
    || fail "missing run_due_scan_schedules helper"

grep -Fq 'def query_due_scan_schedules(' deltaaegis.py \
    || fail "missing query_due_scan_schedules helper"

grep -Fq 'def active_scan_job_exists(' deltaaegis.py \
    || fail "missing active scan job guard"

grep -Fq 'sub.add_parser("schedule-run-due"' deltaaegis.py \
    || fail "missing schedule-run-due CLI command"

grep -Fq 'if args.command == "schedule-run-due": return command_schedule_run_due(args)' deltaaegis.py \
    || fail "missing schedule-run-due dispatch"

python3 - <<'PYTEST'
from pathlib import Path
import importlib.util
import sys
import tempfile

spec = importlib.util.spec_from_file_location("deltaaegis", "deltaaegis.py")
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = module
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory() as tmp:
    tmp_path = Path(tmp)
    connection = module.connect(tmp_path / "deltaaegis.db")

    def fake_execute_scan_job(
        connection,
        job_id,
        target,
        netsniper_path,
        runs_dir,
        logs_dir,
        events_path,
        auto_ingest=False,
        scan_profile="balanced",
    ):
        module.update_scan_job(
            connection,
            job_id,
            status="COMPLETED",
            finished_at=module.utc_now_text(),
            exit_code=0,
            bundle_path=str(tmp_path / "fake-bundle"),
            status_json={"status": "COMPLETE"},
            message=f"fake scheduled scan completed profile={scan_profile}",
        )
        connection.commit()
        row = connection.execute(
            "SELECT * FROM scan_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        return module.scan_job_to_dict(row)

    module.execute_scan_job = fake_execute_scan_job

    schedule = module.create_scan_schedule(
        connection,
        name="Hourly Balanced Monitoring",
        target="192.168.5.0/24",
        scan_profile="balanced",
        cadence_minutes=60,
        enabled=True,
        auto_ingest=False,
    )
    connection.commit()

    due = module.query_due_scan_schedules(connection, limit=10)
    assert len(due) == 1

    results = module.run_due_scan_schedules(
        connection,
        netsniper_path=tmp_path / "netsniper.sh",
        runs_dir=tmp_path / "runs",
        logs_dir=tmp_path / "logs",
        events_path=tmp_path / "events.jsonl",
        max_runs=1,
    )

    assert len(results) == 1
    assert results[0]["action"] == "ran"
    assert results[0]["job"]["status"] == "COMPLETED"
    assert results[0]["job"]["scan_profile"] == "balanced"
    assert results[0]["schedule"]["last_job_id"] == results[0]["job"]["job_id"]
    assert results[0]["schedule"]["last_status"] == "COMPLETED"
    assert results[0]["schedule"]["next_run_at"]
    assert results[0]["schedule"]["failure_count"] == 0
    assert len(module.query_due_scan_schedules(connection, limit=10)) == 0

    module.create_scan_job(
        connection,
        "192.168.5.0/24",
        tmp_path / "netsniper.sh",
        tmp_path / "runs",
        auto_ingest=False,
        scan_profile="quick",
    )
    connection.commit()

    module.create_scan_schedule(
        connection,
        name="Quick Active Guard",
        target="192.168.5.0/24",
        scan_profile="quick",
        cadence_minutes=60,
        enabled=True,
        auto_ingest=False,
    )
    connection.commit()

    skipped = module.run_due_scan_schedules(
        connection,
        netsniper_path=tmp_path / "netsniper.sh",
        runs_dir=tmp_path / "runs",
        logs_dir=tmp_path / "logs",
        events_path=tmp_path / "events.jsonl",
        max_runs=1,
    )

    assert len(skipped) == 1
    assert skipped[0]["action"] == "skipped"
    assert skipped[0]["schedule"]["skip_count"] == 1
    assert skipped[0]["schedule"]["last_status"] == "SKIPPED"

print("[PASS] v0.31 schedule runner python checks passed")
PYTEST

pass "DeltaAegis v0.31 schedule runner validation passed"
