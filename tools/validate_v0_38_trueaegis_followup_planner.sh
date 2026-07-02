#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[v0.38 checkpoint 2] checkpoint 1 dependency"
tools/validate_v0_38_trueaegis_followup_intent.sh

echo "[v0.38 checkpoint 2] syntax check"
python3 -m py_compile deltaaegis.py

echo "[v0.38 checkpoint 2] static planner checks"
python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = [
    "def trueaegis_followup_plan_for_schedule(",
    "deltaaegis-trueaegis-followup-plan-v1",
    '"outcome": ""',
    '"disabled_by_schedule"',
    '"auto_ingest_disabled"',
    '"scan_not_completed"',
    '"ingest_not_accepted"',
    '"missing_manifest"',
    '"trueaegis_not_ready"',
    '"active_trueaegis_job_exists"',
    '"eligible"',
    '"trueaegis_followup": trueaegis_followup_plan',
]

for needle in required:
    if needle not in text:
        raise SystemExit(f"missing v0.38 planner marker: {needle}")

start = text.find("def run_due_scan_schedules(")
if start < 0:
    raise SystemExit("could not locate run_due_scan_schedules")

end = text.find("\ndef ", start + 1)
if end < 0:
    raise SystemExit("could not locate end of run_due_scan_schedules")

run_due_block = text[start:end]

if run_due_block.count("plan_trueaegis_followup_for_schedule") != 0:
    raise SystemExit("unexpected old planner function name in run_due_scan_schedules")

if run_due_block.count("trueaegis_followup_plan = trueaegis_followup_plan_for_schedule(") < 2:
    raise SystemExit("run_due_scan_schedules should plan follow-up for failed and successful scheduled scans")

for forbidden in [
    "dashboard_trueaegis_validation_start_payload",
    "create_trueaegis_job(",
    "execute_trueaegis_job(",
    "dashboard_start_trueaegis_job_thread",
]:
    if forbidden in run_due_block:
        raise SystemExit(f"checkpoint 2 must not execute or queue TrueAegis from schedules yet: {forbidden}")

print("static planner checks passed")
PY

echo "[v0.38 checkpoint 2] functional planner smoke test"
python3 - <<'PY'
from pathlib import Path
import tempfile
import deltaaegis

def require_outcome(plan, expected):
    actual = plan.get("outcome")
    if actual != expected:
        raise SystemExit(f"expected outcome {expected}, got {actual}: {plan}")

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    db = root / "planner.db"
    conn = deltaaegis.connect(db)

    schedule = {
        "schedule_id": "sched-test",
        "name": "planner test",
        "target": "192.168.44.0/24",
        "network_scope": "192.168.44.0/24",
        "auto_ingest": True,
        "run_trueaegis_after_ingest": True,
    }
    job = {
        "job_id": "scan-test",
        "status": "COMPLETED",
        "network_scope": "192.168.44.0/24",
        "auto_ingest": True,
        "status_json": {},
    }

    disabled = dict(schedule)
    disabled["run_trueaegis_after_ingest"] = False
    require_outcome(
        deltaaegis.trueaegis_followup_plan_for_schedule(conn, disabled, job),
        "disabled_by_schedule",
    )

    no_ingest = dict(schedule)
    no_ingest["auto_ingest"] = False
    require_outcome(
        deltaaegis.trueaegis_followup_plan_for_schedule(conn, no_ingest, job),
        "auto_ingest_disabled",
    )

    failed_job = dict(job)
    failed_job["status"] = "FAILED"
    require_outcome(
        deltaaegis.trueaegis_followup_plan_for_schedule(conn, schedule, failed_job),
        "scan_not_completed",
    )

    rejected_job = dict(job)
    rejected_job["status_json"] = {"quality_status": "SKIPPED"}
    require_outcome(
        deltaaegis.trueaegis_followup_plan_for_schedule(conn, schedule, rejected_job),
        "ingest_not_accepted",
    )

    require_outcome(
        deltaaegis.trueaegis_followup_plan_for_schedule(conn, schedule, job),
        "missing_manifest",
    )

    bundle = root / "bundle"
    bundle.mkdir()
    manifest = bundle / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")

    with_manifest = dict(job)
    with_manifest["bundle_path"] = str(bundle)

    require_outcome(
        deltaaegis.trueaegis_followup_plan_for_schedule(
            conn,
            schedule,
            with_manifest,
            trueaegis_path=root / "missing" / "trueaegis.py",
        ),
        "trueaegis_not_ready",
    )

    trueaegis_dir = root / "TrueAegis"
    trueaegis_dir.mkdir()
    trueaegis_path = trueaegis_dir / "trueaegis.py"
    trueaegis_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    eligible = deltaaegis.trueaegis_followup_plan_for_schedule(
        conn,
        schedule,
        with_manifest,
        trueaegis_path=trueaegis_path,
    )
    require_outcome(eligible, "eligible")

    if eligible.get("eligible") is not True:
        raise SystemExit("eligible plan did not set eligible=True")

    if eligible.get("execution_enabled") is not False:
        raise SystemExit("checkpoint 2 planner must not enable execution")

    active = deltaaegis.create_trueaegis_job(
        conn,
        scan_id="scan-test",
        network_scope="192.168.44.0/24",
        manifest_path=manifest,
        trueaegis_path=trueaegis_path,
    )
    conn.commit()

    require_outcome(
        deltaaegis.trueaegis_followup_plan_for_schedule(
            conn,
            schedule,
            with_manifest,
            trueaegis_path=trueaegis_path,
        ),
        "active_trueaegis_job_exists",
    )

    conn.close()

print("functional planner smoke test passed")
PY

echo "[v0.38 checkpoint 2] run_due integration smoke test"
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
}

try:
    with tempfile.TemporaryDirectory() as tmp:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row

        schedule = {
            "schedule_id": "sched-run-due",
            "name": "run due planner",
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
            "job_id": "scan-run-due",
            "status": "COMPLETED",
            "network_scope": "192.168.44.0/24",
            "auto_ingest": True,
            "message": "done",
        }

        deltaaegis.query_due_scan_schedules = lambda connection, limit=1: [schedule]
        deltaaegis.active_scan_job_row = lambda connection: None
        deltaaegis.create_scan_job = lambda *args, **kwargs: {"job_id": "scan-run-due"}
        deltaaegis.execute_scan_job = lambda *args, **kwargs: final_job
        deltaaegis.update_scan_schedule_after_job = lambda *args, **kwargs: schedule

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

        if "trueaegis_followup" not in item:
            raise SystemExit(f"run_due result is missing trueaegis_followup: {item}")

        if item["trueaegis_followup"].get("outcome") != "missing_manifest":
            raise SystemExit(f"unexpected follow-up plan: {item['trueaegis_followup']}")

finally:
    for name, value in originals.items():
        setattr(deltaaegis, name, value)

print("run_due integration smoke test passed")
PY

echo "[v0.38 checkpoint 2] PASS"
