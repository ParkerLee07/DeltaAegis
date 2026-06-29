#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

ok() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

grep -Fq 'failure_message = str(exc)' deltaaegis.py \
    || fail "scheduled scan failure handler does not preserve failure message"

grep -Fq 'status="FAILED"' deltaaegis.py \
    || fail "scheduled scan failure handler does not persist FAILED scan job status"

grep -Fq 'scan_job_to_dict(failed_row)' deltaaegis.py \
    || fail "scheduled scan failure handler does not return persisted failed job row"

python3 - <<'DELTA_31_5B_PYTEST'
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

    module.create_scan_schedule(
        connection,
        name="Failure Persistence Test",
        target="192.168.5.0/24",
        scan_profile="balanced",
        cadence_minutes=60,
        enabled=True,
        auto_ingest=True,
    )
    connection.commit()

    def fake_execute_scan_job(*args, **kwargs):
        raise module.DeltaAegisError("simulated scheduled scan execution failure")

    module.execute_scan_job = fake_execute_scan_job

    results = module.run_due_scan_schedules(
        connection,
        netsniper_path=tmp_path / "netsniper.sh",
        runs_dir=tmp_path / "runs",
        logs_dir=tmp_path / "logs",
        events_path=tmp_path / "events.jsonl",
        max_runs=1,
    )

    assert len(results) == 1
    assert results[0]["action"] == "failed"
    assert results[0]["job"]["status"] == "FAILED"
    assert results[0]["job"]["finished_at"]
    assert "simulated scheduled scan execution failure" in results[0]["job"]["message"]

    job_id = results[0]["job"]["job_id"]
    row = connection.execute(
        "SELECT * FROM scan_jobs WHERE job_id = ?",
        (job_id,),
    ).fetchone()

    assert row is not None
    persisted = module.scan_job_to_dict(row)
    assert persisted["status"] == "FAILED"
    assert persisted["finished_at"]
    assert "simulated scheduled scan execution failure" in persisted["message"]

    schedule = results[0]["schedule"]
    assert schedule["last_status"] == "FAILED"
    assert schedule["failure_count"] == 1
    assert schedule["last_job_id"] == job_id

print("[PASS] v0.31 scheduled scan failure persistence python checks passed")
DELTA_31_5B_PYTEST

ok "DeltaAegis v0.31 scheduled scan failure persistence validation passed"
