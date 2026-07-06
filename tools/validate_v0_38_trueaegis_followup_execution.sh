#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[v0.38 checkpoint 4] checkpoint 3 dependency"
tools/validate_v0_38_trueaegis_followup_queue.sh

echo "[v0.38 checkpoint 4] syntax check"
python3 -m py_compile deltaaegis.py

echo "[v0.38 checkpoint 4] static execution checks"
python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = [
    "def sqlite_connection_database_path(",
    'connection.execute("PRAGMA database_list")',
    "def trueaegis_start_queued_followup_for_schedule(",
    "deltaaegis-trueaegis-followup-execution-v2",
    '"database_path_unavailable"',
    '"thread_start_failed"',
    "dashboard_start_trueaegis_job_thread(",
    "trueaegis_followup_execution = trueaegis_start_queued_followup_for_schedule(",
    '"trueaegis_followup_execution": trueaegis_followup_execution',
]

for needle in required:
    if needle not in text:
        raise SystemExit(f"missing v0.38 execution marker: {needle}")

start = text.find("def run_due_scan_schedules(")
end = text.find("\ndef set_scan_schedule_enabled(", start)
if start < 0 or end < 0:
    raise SystemExit("could not isolate run_due_scan_schedules")

run_due_block = text[start:end]

if run_due_block.count(
    "trueaegis_followup_execution = trueaegis_start_queued_followup_for_schedule("
) < 2:
    raise SystemExit("run_due_scan_schedules should start-plan both result paths")

if run_due_block.count(
    '"trueaegis_followup_execution": trueaegis_followup_execution'
) < 2:
    raise SystemExit("run_due_scan_schedules should expose execution payload twice")

for forbidden in ("execute_trueaegis_job(", "create_trueaegis_job("):
    if forbidden in run_due_block:
        raise SystemExit(f"run_due_scan_schedules should not directly call {forbidden}")

helper_start = text.find("def trueaegis_start_queued_followup_for_schedule(")
helper_end = text.find("\ndef latest_trueaegis_validation_results_path(", helper_start)
if helper_start < 0 or helper_end < 0:
    raise SystemExit("could not isolate execution helper")

helper = text[helper_start:helper_end]

if "create_trueaegis_job(" in helper:
    raise SystemExit("execution helper must not create a second job")

if "dashboard_start_trueaegis_job_thread(" not in helper:
    raise SystemExit("execution helper must retain the guarded asynchronous worker")

if (
    "execute_trueaegis_job(" in helper
    and 'if safe_execution_mode == "synchronous":' not in helper
):
    raise SystemExit(
        "direct TrueAegis execution is only allowed in guarded synchronous mode"
    )

print("static execution checks passed")
PY

echo "[v0.38 checkpoint 4] database path resolution smoke test"
python3 - <<'PY'
from pathlib import Path
import tempfile
import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "path-resolution.db"
    conn = deltaaegis.connect(db)
    resolved = deltaaegis.sqlite_connection_database_path(conn)

    if resolved is None or resolved.resolve() != db.resolve():
        raise SystemExit(f"unexpected database path: {resolved} != {db}")

    conn.close()

print("database path resolution smoke test passed")
PY

echo "[v0.38 checkpoint 4] execution start smoke test"
python3 - <<'PY'
from pathlib import Path
import tempfile
import deltaaegis

original_start = deltaaegis.dashboard_start_trueaegis_job_thread

try:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        db = root / "execution.db"
        conn = deltaaegis.connect(db)

        bundle = root / "bundle"
        bundle.mkdir()
        manifest = bundle / "manifest.json"
        manifest.write_text("{}", encoding="utf-8")

        class PlannerSnapshotCursor:
            def __init__(self, row):
                self.row = row

            def fetchone(self):
                return self.row

        class PlannerConnection:
            def __init__(self, inner, manifest_path):
                self.inner = inner
                self.manifest_path = manifest_path

            def execute(self, sql, params=()):
                if "FROM snapshots" in sql:
                    scan_id = str(params[0] if params else "scan-test")

                    return PlannerSnapshotCursor(
                        {
                            "scan_id": scan_id,
                            "quality_status": "ACCEPTED",
                            "manifest_path": str(self.manifest_path),
                        }
                    )

                return self.inner.execute(sql, params)

        planner_conn = PlannerConnection(conn, manifest)

        trueaegis_dir = root / "TrueAegis"
        trueaegis_dir.mkdir()
        trueaegis_path = trueaegis_dir / "trueaegis.py"
        trueaegis_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

        schedule = {
            "schedule_id": "sched-execution",
            "target": "192.168.44.0/24",
            "network_scope": "192.168.44.0/24",
            "auto_ingest": True,
            "run_trueaegis_after_ingest": True,
        }
        job = {
            "job_id": "scan-execution",
            "scan_id": "scan-execution",
            "status": "COMPLETED",
            "network_scope": "192.168.44.0/24",
            "auto_ingest": True,
            "bundle_path": str(bundle),
            "status_json": {
            "auto_ingest": {
                "performed": True,
                "accepted": True,
                "quality_status": "ACCEPTED",
                "scan_id": "scan-test",
            }
        },
        }

        plan = deltaaegis.trueaegis_followup_plan_for_schedule(
            planner_conn,
            schedule,
            job,
            trueaegis_path=trueaegis_path,
        )
        queue_result = deltaaegis.trueaegis_queue_followup_for_schedule(
            conn,
            schedule,
            job,
            plan,
        )

        captured = {}

        class FakeThread:
            name = "fake-trueaegis-thread"

        def fake_start(**kwargs):
            captured.update(kwargs)
            return FakeThread()

        deltaaegis.dashboard_start_trueaegis_job_thread = fake_start

        execution = deltaaegis.trueaegis_start_queued_followup_for_schedule(
            conn,
            queue_result,
        )

        if execution.get("started") is not True:
            raise SystemExit(f"expected started result, got {execution}")

        if captured.get("job_id") != queue_result.get("trueaegis_job_id"):
            raise SystemExit(f"unexpected worker arguments: {captured}")

        if Path(captured["db_path"]).resolve() != db.resolve():
            raise SystemExit(f"unexpected worker database path: {captured}")

        conn.close()
finally:
    deltaaegis.dashboard_start_trueaegis_job_thread = original_start

print("execution start smoke test passed")
PY

echo "[v0.38 checkpoint 4] startup failure recovery smoke test"
python3 - <<'PY'
from pathlib import Path
import tempfile
import deltaaegis

original_start = deltaaegis.dashboard_start_trueaegis_job_thread

try:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        db = root / "failure.db"
        conn = deltaaegis.connect(db)

        manifest = root / "manifest.json"
        manifest.write_text("{}", encoding="utf-8")

        trueaegis_path = root / "trueaegis.py"
        trueaegis_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

        queued_job = deltaaegis.create_trueaegis_job(
            conn,
            scan_id="scan-failure",
            network_scope="192.168.44.0/24",
            manifest_path=manifest,
            trueaegis_path=trueaegis_path,
        )
        conn.commit()

        queue_result = {
            "queued": True,
            "outcome": "queued",
            "trueaegis_job_id": queued_job["job_id"],
            "job": queued_job,
        }

        def fail_start(**kwargs):
            raise RuntimeError("simulated thread startup failure")

        deltaaegis.dashboard_start_trueaegis_job_thread = fail_start

        execution = deltaaegis.trueaegis_start_queued_followup_for_schedule(
            conn,
            queue_result,
        )

        if execution.get("outcome") != "thread_start_failed":
            raise SystemExit(f"unexpected failure outcome: {execution}")

        row = conn.execute(
            "SELECT * FROM trueaegis_jobs WHERE job_id = ?",
            (queued_job["job_id"],),
        ).fetchone()
        stored = deltaaegis.trueaegis_job_to_dict(row)

        if stored.get("status") != "FAILED":
            raise SystemExit(f"startup failure did not mark job FAILED: {stored}")

        if deltaaegis.active_trueaegis_job_exists(conn):
            raise SystemExit("failed startup job remained active")

        conn.close()
finally:
    deltaaegis.dashboard_start_trueaegis_job_thread = original_start

print("startup failure recovery smoke test passed")
PY

echo "[v0.38 checkpoint 4] run_due integration smoke test"
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
            "schedule_id": "sched-run-due-execution",
            "name": "run due execution",
            "target": "192.168.44.0/24",
            "network_scope": "192.168.44.0/24",
            "scan_profile": "balanced",
            "cadence_minutes": 120,
            "auto_ingest": True,
            "run_trueaegis_after_ingest": True,
            "enabled": True,
            "last_run_at": None,
            "next_run_at": None,
            "last_job_id": None,
            "last_status": None,
            "failure_count": 0,
            "skip_count": 0,
            "created_at": "now",
            "updated_at": "now",
            "message": "test",
        }
        final_job = {
            "job_id": "scan-run-due-execution",
            "status": "COMPLETED",
            "network_scope": "192.168.44.0/24",
            "auto_ingest": True,
            "message": "done",
        }
        plan = {"eligible": True, "outcome": "eligible"}
        queue_result = {
            "queued": True,
            "outcome": "queued",
            "trueaegis_job_id": "trueaegis-run-due",
        }
        execution_result = {
            "started": True,
            "outcome": "started",
            "trueaegis_job_id": "trueaegis-run-due",
        }

        deltaaegis.query_due_scan_schedules = lambda connection, limit=1: [schedule]
        deltaaegis.active_scan_job_row = lambda connection: None
        deltaaegis.create_scan_job = lambda *args, **kwargs: {"job_id": "scan-run-due-execution"}
        deltaaegis.execute_scan_job = lambda *args, **kwargs: final_job
        deltaaegis.update_scan_schedule_after_job = lambda *args, **kwargs: schedule
        deltaaegis.trueaegis_followup_plan_for_schedule = lambda *args, **kwargs: plan
        deltaaegis.trueaegis_queue_followup_for_schedule = lambda *args, **kwargs: queue_result
        deltaaegis.trueaegis_start_queued_followup_for_schedule = lambda *args, **kwargs: execution_result

        result = deltaaegis.run_due_scan_schedules(
            conn,
            netsniper_path=Path("/tmp/netsniper.sh"),
            runs_dir=Path(tmp),
            logs_dir=Path(tmp),
            events_path=Path(tmp) / "events.jsonl",
            max_runs=1,
        )

        if result[0].get("trueaegis_followup_execution") != execution_result:
            raise SystemExit(f"missing execution payload: {result}")
finally:
    for name, value in originals.items():
        setattr(deltaaegis, name, value)

print("run_due integration smoke test passed")
PY

echo "[v0.38 checkpoint 4] PASS"
