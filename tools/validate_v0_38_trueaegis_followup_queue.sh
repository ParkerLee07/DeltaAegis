#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[v0.38 checkpoint 3] checkpoint 2 dependency"
tools/validate_v0_38_trueaegis_followup_planner.sh

echo "[v0.38 checkpoint 3] syntax check"
python3 -m py_compile deltaaegis.py

echo "[v0.38 checkpoint 3] static queue checks"
python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = [
    "def trueaegis_queue_followup_for_schedule(",
    "deltaaegis-trueaegis-followup-queue-v1",
    '"queued": False',
    '"outcome": "queued"',
    "create_trueaegis_job(",
    "TrueAegis follow-up job queued; execution is deferred",
    "trueaegis_followup_queue = trueaegis_queue_followup_for_schedule(",
    '"trueaegis_followup_queue": trueaegis_followup_queue',
]

for needle in required:
    if needle not in text:
        raise SystemExit(f"missing v0.38 queue marker: {needle}")

start = text.find("def run_due_scan_schedules(")
if start < 0:
    raise SystemExit("could not locate run_due_scan_schedules")
end = text.find("\ndef set_scan_schedule_enabled(", start)
if end < 0:
    end = text.find("\ndef ", start + 1)
if end < 0:
    raise SystemExit("could not locate end of run_due_scan_schedules")
run_due_block = text[start:end]

if run_due_block.count("trueaegis_followup_queue = trueaegis_queue_followup_for_schedule(") < 2:
    raise SystemExit("run_due_scan_schedules should queue-plan both failed and successful scheduled scan results")

if run_due_block.count('"trueaegis_followup_queue": trueaegis_followup_queue') < 2:
    raise SystemExit("run_due_scan_schedules should include queue result in both failed and successful result payloads")

for forbidden in [
    "execute_trueaegis_job(",
    "dashboard_start_trueaegis_job_thread",
    "dashboard_trueaegis_validation_start_payload",
]:
    if forbidden in run_due_block:
        raise SystemExit(f"checkpoint 3 must not execute TrueAegis from schedules yet: {forbidden}")

queue_start = text.find("def trueaegis_queue_followup_for_schedule(")

queue_end_candidates = [
    text.find("\ndef sqlite_connection_database_path(", queue_start),
    text.find("\ndef latest_trueaegis_validation_results_path(", queue_start),
]
queue_end_candidates = [
    candidate
    for candidate in queue_end_candidates
    if candidate >= 0
]

if queue_start < 0 or not queue_end_candidates:
    raise SystemExit("could not isolate queue helper")

queue_end = min(queue_end_candidates)
queue_block = text[queue_start:queue_end]

for forbidden in [
    "execute_trueaegis_job(",
    "dashboard_start_trueaegis_job_thread",
    "threading.Thread",
    ".start()",
]:
    if forbidden in queue_block:
        raise SystemExit(f"queue helper must not start or execute TrueAegis yet: {forbidden}")

print("static queue checks passed")
PY

echo "[v0.38 checkpoint 3] functional queue smoke test"
python3 - <<'PY'
from pathlib import Path
import tempfile
import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    db = root / "queue.db"
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
        "schedule_id": "sched-queue",
        "name": "queue test",
        "target": "192.168.44.0/24",
        "network_scope": "192.168.44.0/24",
        "auto_ingest": True,
        "run_trueaegis_after_ingest": True,
    }
    job = {
        "job_id": "scan-queue",
        "scan_id": "scan-queue",
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

    disabled_plan = {
        "eligible": False,
        "outcome": "disabled_by_schedule",
        "message": "disabled",
    }

    disabled_result = deltaaegis.trueaegis_queue_followup_for_schedule(
        conn,
        schedule,
        job,
        disabled_plan,
    )

    if disabled_result.get("queued") is not False:
        raise SystemExit("disabled plan should not queue a job")

    plan = deltaaegis.trueaegis_followup_plan_for_schedule(
        planner_conn,
        schedule,
        job,
        trueaegis_path=trueaegis_path,
    )

    if plan.get("outcome") != "eligible":
        raise SystemExit(f"expected eligible planner result before queueing, got {plan}")

    queued = deltaaegis.trueaegis_queue_followup_for_schedule(
        conn,
        schedule,
        job,
        plan,
    )

    if queued.get("queued") is not True:
        raise SystemExit(f"expected queue helper to queue job, got {queued}")

    if queued.get("outcome") != "queued":
        raise SystemExit(f"expected queued outcome, got {queued}")

    trueaegis_job_id = queued.get("trueaegis_job_id")
    if not trueaegis_job_id:
        raise SystemExit("queued result did not include trueaegis_job_id")

    row = conn.execute(
        "SELECT * FROM trueaegis_jobs WHERE job_id = ?",
        (trueaegis_job_id,),
    ).fetchone()

    if row is None:
        raise SystemExit("queued TrueAegis job was not persisted")

    stored = deltaaegis.trueaegis_job_to_dict(row)

    if stored.get("status") != "QUEUED":
        raise SystemExit(f"queued TrueAegis job should remain QUEUED, got {stored}")

    if stored.get("started_at"):
        raise SystemExit("checkpoint 3 must not start TrueAegis jobs")

    second = deltaaegis.trueaegis_queue_followup_for_schedule(
        conn,
        schedule,
        job,
        plan,
    )

    if second.get("outcome") != "active_trueaegis_job_exists":
        raise SystemExit(f"expected active job guard, got {second}")

    conn.close()

print("functional queue smoke test passed")
PY

echo "[v0.38 checkpoint 3] run_due queue integration smoke test"
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
}

try:
    with tempfile.TemporaryDirectory() as tmp:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row

        schedule = {
            "schedule_id": "sched-run-due-queue",
            "name": "run due queue",
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
            "job_id": "scan-run-due-queue",
            "status": "COMPLETED",
            "network_scope": "192.168.44.0/24",
            "auto_ingest": True,
            "message": "done",
        }

        plan = {
            "schema_version": "deltaaegis-trueaegis-followup-plan-v1",
            "eligible": True,
            "outcome": "eligible",
            "message": "eligible",
        }

        queue_result = {
            "schema_version": "deltaaegis-trueaegis-followup-queue-v1",
            "queued": True,
            "outcome": "queued",
            "trueaegis_job_id": "trueaegis-test",
        }

        deltaaegis.query_due_scan_schedules = lambda connection, limit=1: [schedule]
        deltaaegis.active_scan_job_row = lambda connection: None
        deltaaegis.create_scan_job = lambda *args, **kwargs: {"job_id": "scan-run-due-queue"}
        deltaaegis.execute_scan_job = lambda *args, **kwargs: final_job
        deltaaegis.update_scan_schedule_after_job = lambda *args, **kwargs: schedule
        deltaaegis.trueaegis_followup_plan_for_schedule = lambda *args, **kwargs: plan
        deltaaegis.trueaegis_queue_followup_for_schedule = lambda *args, **kwargs: queue_result

        result = deltaaegis.run_due_scan_schedules(
            conn,
            netsniper_path=Path("/tmp/netsniper.sh"),
            runs_dir=Path(tmp),
            logs_dir=Path(tmp),
            events_path=Path(tmp) / "events.jsonl",
            max_runs=1,
        )

        if len(result) != 1:
            raise SystemExit(f"expected one run_due result, got {result}")

        item = result[0]

        if item.get("trueaegis_followup") != plan:
            raise SystemExit(f"run_due result did not include expected planner payload: {item}")

        if item.get("trueaegis_followup_queue") != queue_result:
            raise SystemExit(f"run_due result did not include expected queue payload: {item}")

finally:
    for name, value in originals.items():
        setattr(deltaaegis, name, value)

print("run_due queue integration smoke test passed")
PY

echo "[v0.38 checkpoint 3] PASS"
