#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[v0.38 checkpoint 6] checkpoint 5 dependency"
tools/validate_v0_38_trueaegis_ingest_provenance.sh

echo "[v0.38 checkpoint 6] syntax check"
python3 -m py_compile deltaaegis.py

echo "[v0.38 checkpoint 6] static execution-mode checks"
python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = [
    "deltaaegis-trueaegis-followup-execution-v2",
    'execution_mode: str = "asynchronous"',
    'safe_execution_mode not in {"asynchronous", "synchronous"}',
    'if safe_execution_mode == "synchronous":',
    "final_job = execute_trueaegis_job(",
    'trueaegis_execution_mode: str = "asynchronous"',
    "execution_mode=trueaegis_execution_mode",
    'trueaegis_execution_mode="synchronous"',
    'trueaegis_execution_mode="asynchronous"',
    "trueaegis_failed = any(",
]

for needle in required:
    if needle not in text:
        raise SystemExit(f"missing checkpoint 6 marker: {needle}")

command_start = text.find("def command_schedule_run_due(")
command_end = text.find("\ndef set_scan_schedule_enabled(", command_start)
if command_start < 0 or command_end < 0:
    raise SystemExit("could not isolate command_schedule_run_due")
command_block = text[command_start:command_end]

if command_block.count('trueaegis_execution_mode="synchronous"') != 1:
    raise SystemExit("CLI schedule-run-due must select synchronous execution exactly once")

dashboard_api_start = text.find("def dashboard_netsniper_schedule_run_due_payload(")
dashboard_api_end = text.find("\nHOURLY_BALANCED_MONITORING_NAME", dashboard_api_start)
dashboard_tick_start = text.find("def dashboard_run_due_schedule_tick(")
dashboard_tick_end = text.find("\ndef dashboard_schedule_worker_loop(", dashboard_tick_start)

for label, start, end in (
    ("dashboard API run-due", dashboard_api_start, dashboard_api_end),
    ("dashboard schedule tick", dashboard_tick_start, dashboard_tick_end),
):
    if start < 0 or end < 0:
        raise SystemExit(f"could not isolate {label}")
    block = text[start:end]
    if 'trueaegis_execution_mode="asynchronous"' not in block:
        raise SystemExit(f"{label} must explicitly use asynchronous execution")

print("static execution-mode checks passed")
PY

echo "[v0.38 checkpoint 6] synchronous execution smoke test"
python3 - <<'PY'
from pathlib import Path
import tempfile
import deltaaegis

original_execute = deltaaegis.execute_trueaegis_job
original_thread = deltaaegis.dashboard_start_trueaegis_job_thread

try:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        conn = deltaaegis.connect(root / "sync.db")
        manifest = root / "manifest.json"
        manifest.write_text("{}", encoding="utf-8")
        trueaegis_path = root / "trueaegis.py"
        trueaegis_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

        job = deltaaegis.create_trueaegis_job(
            conn,
            scan_id="scan-sync",
            network_scope="192.168.44.0/24",
            manifest_path=manifest,
            trueaegis_path=trueaegis_path,
            scan_job_id="scan-job-sync",
            schedule_id="schedule-sync",
            trigger_source="scheduled_followup",
        )
        conn.commit()

        queue_result = {
            "queued": True,
            "outcome": "queued",
            "trueaegis_job_id": job["job_id"],
            "job": job,
        }
        captured = {}

        def fake_execute(connection, **kwargs):
            captured.update(kwargs)
            deltaaegis.update_trueaegis_job(
                connection,
                kwargs["job_id"],
                status="COMPLETED",
                completed_at=deltaaegis.utc_now_text(),
                imported_observations=4,
                correlation_count=3,
                exit_code=0,
                message="synthetic completion",
            )
            connection.commit()
            row = connection.execute(
                "SELECT * FROM trueaegis_jobs WHERE job_id = ?",
                (kwargs["job_id"],),
            ).fetchone()
            return deltaaegis.trueaegis_job_to_dict(row)

        def forbidden_thread(**kwargs):
            raise AssertionError("synchronous mode must not start a daemon thread")

        deltaaegis.execute_trueaegis_job = fake_execute
        deltaaegis.dashboard_start_trueaegis_job_thread = forbidden_thread

        result = deltaaegis.trueaegis_start_queued_followup_for_schedule(
            conn,
            queue_result,
            execution_mode="synchronous",
        )

        assert result["execution_mode"] == "synchronous", result
        assert result["started"] is True, result
        assert result["completed"] is True, result
        assert result["outcome"] == "completed", result
        assert result["job"]["status"] == "COMPLETED", result
        assert captured["job_id"] == job["job_id"], captured
        conn.close()
finally:
    deltaaegis.execute_trueaegis_job = original_execute
    deltaaegis.dashboard_start_trueaegis_job_thread = original_thread

print("synchronous execution smoke test passed")
PY

echo "[v0.38 checkpoint 6] synchronous failure recovery smoke test"
python3 - <<'PY'
from pathlib import Path
import tempfile
import deltaaegis

original_execute = deltaaegis.execute_trueaegis_job

try:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        conn = deltaaegis.connect(root / "sync-failure.db")
        manifest = root / "manifest.json"
        manifest.write_text("{}", encoding="utf-8")
        trueaegis_path = root / "trueaegis.py"
        trueaegis_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

        job = deltaaegis.create_trueaegis_job(
            conn,
            scan_id="scan-sync-failure",
            network_scope="192.168.44.0/24",
            manifest_path=manifest,
            trueaegis_path=trueaegis_path,
            trigger_source="scheduled_followup",
        )
        conn.commit()

        queue_result = {
            "queued": True,
            "outcome": "queued",
            "trueaegis_job_id": job["job_id"],
            "job": job,
        }

        def fail_execute(*args, **kwargs):
            raise RuntimeError("synthetic synchronous failure")

        deltaaegis.execute_trueaegis_job = fail_execute

        result = deltaaegis.trueaegis_start_queued_followup_for_schedule(
            conn,
            queue_result,
            execution_mode="synchronous",
        )

        assert result["started"] is True, result
        assert result["completed"] is True, result
        assert result["outcome"] == "execution_failed", result
        assert result["job"]["status"] == "FAILED", result
        assert not deltaaegis.active_trueaegis_job_exists(conn)
        conn.close()
finally:
    deltaaegis.execute_trueaegis_job = original_execute

print("synchronous failure recovery smoke test passed")
PY

echo "[v0.38 checkpoint 6] asynchronous execution smoke test"
python3 - <<'PY'
from pathlib import Path
import tempfile
import deltaaegis

original_thread = deltaaegis.dashboard_start_trueaegis_job_thread
original_execute = deltaaegis.execute_trueaegis_job

try:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        conn = deltaaegis.connect(root / "async.db")
        manifest = root / "manifest.json"
        manifest.write_text("{}", encoding="utf-8")
        trueaegis_path = root / "trueaegis.py"
        trueaegis_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

        job = deltaaegis.create_trueaegis_job(
            conn,
            scan_id="scan-async",
            network_scope="192.168.44.0/24",
            manifest_path=manifest,
            trueaegis_path=trueaegis_path,
            trigger_source="scheduled_followup",
        )
        conn.commit()

        queue_result = {
            "queued": True,
            "outcome": "queued",
            "trueaegis_job_id": job["job_id"],
            "job": job,
        }
        captured = {}

        class FakeThread:
            name = "fake-async-trueaegis"

        def fake_thread(**kwargs):
            captured.update(kwargs)
            return FakeThread()

        def forbidden_execute(*args, **kwargs):
            raise AssertionError("asynchronous mode must not execute synchronously")

        deltaaegis.dashboard_start_trueaegis_job_thread = fake_thread
        deltaaegis.execute_trueaegis_job = forbidden_execute

        result = deltaaegis.trueaegis_start_queued_followup_for_schedule(
            conn,
            queue_result,
            execution_mode="asynchronous",
        )

        assert result["execution_mode"] == "asynchronous", result
        assert result["started"] is True, result
        assert result["completed"] is False, result
        assert result["outcome"] == "started", result
        assert result["thread_name"] == "fake-async-trueaegis", result
        assert captured["job_id"] == job["job_id"], captured
        conn.close()
finally:
    deltaaegis.dashboard_start_trueaegis_job_thread = original_thread
    deltaaegis.execute_trueaegis_job = original_execute

print("asynchronous execution smoke test passed")
PY

echo "[v0.38 checkpoint 6] run_due mode routing smoke test"
python3 - <<'PY'
from pathlib import Path
import sqlite3
import tempfile
import deltaaegis

originals = {
    "query_due_scan_schedules": deltaaegis.query_due_scan_schedules,
    "active_scan_job_row": deltaaegis.active_scan_job_row,
    "create_scan_job": deltaaegis.create_scan_job,
    "execute_scan_job": deltaaegis.execute_scan_job,
    "update_scan_schedule_after_job": deltaaegis.update_scan_schedule_after_job,
    "trueaegis_followup_plan_for_schedule": deltaaegis.trueaegis_followup_plan_for_schedule,
    "trueaegis_queue_followup_for_schedule": deltaaegis.trueaegis_queue_followup_for_schedule,
    "trueaegis_start_queued_followup_for_schedule": deltaaegis.trueaegis_start_queued_followup_for_schedule,
}

try:
    with tempfile.TemporaryDirectory() as tmp:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row

        schedule = {
            "schedule_id": "schedule-mode",
            "name": "mode routing",
            "target": "192.168.44.0/24",
            "network_scope": "192.168.44.0/24",
            "scan_profile": "balanced",
            "cadence_minutes": 60,
            "auto_ingest": True,
            "run_trueaegis_after_ingest": True,
            "enabled": True,
            "failure_count": 0,
            "skip_count": 0,
        }
        final_job = {
            "job_id": "scan-mode",
            "status": "COMPLETED",
            "auto_ingest": True,
            "network_scope": "192.168.44.0/24",
            "message": "done",
        }
        captured = {}

        deltaaegis.query_due_scan_schedules = lambda connection, limit=1: [schedule]
        deltaaegis.active_scan_job_row = lambda connection: None
        deltaaegis.create_scan_job = lambda *args, **kwargs: {"job_id": "scan-mode"}
        deltaaegis.execute_scan_job = lambda *args, **kwargs: final_job
        deltaaegis.update_scan_schedule_after_job = lambda *args, **kwargs: schedule
        deltaaegis.trueaegis_followup_plan_for_schedule = lambda *args, **kwargs: {
            "eligible": True,
            "outcome": "eligible",
        }
        deltaaegis.trueaegis_queue_followup_for_schedule = lambda *args, **kwargs: {
            "queued": True,
            "outcome": "queued",
            "trueaegis_job_id": "trueaegis-mode",
        }

        def fake_execution(*args, **kwargs):
            captured.update(kwargs)
            return {
                "execution_mode": kwargs.get("execution_mode"),
                "started": True,
                "completed": True,
                "outcome": "completed",
            }

        deltaaegis.trueaegis_start_queued_followup_for_schedule = fake_execution

        results = deltaaegis.run_due_scan_schedules(
            conn,
            netsniper_path=Path("/tmp/netsniper.sh"),
            runs_dir=Path(tmp),
            logs_dir=Path(tmp),
            events_path=Path(tmp) / "events.jsonl",
            max_runs=1,
            trueaegis_execution_mode="synchronous",
        )

        assert captured["execution_mode"] == "synchronous", captured
        assert results[0]["trueaegis_followup_execution"]["outcome"] == "completed", results
finally:
    for name, value in originals.items():
        setattr(deltaaegis, name, value)

print("run_due mode routing smoke test passed")
PY

echo "[v0.38 checkpoint 6] PASS"
