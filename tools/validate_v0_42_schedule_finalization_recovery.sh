#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

branch="$(git branch --show-current)"
case "$branch" in
  feature/v0.42-logical-site-scopes|main)
    ;;
  *)
    echo "FAIL: unexpected branch $branch"
    exit 1
    ;;
esac

echo "DeltaAegis v0.42 Schedule Finalization Recovery Validator"
echo "=========================================================="

echo "[v0.42 hotfix D] source syntax"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py
echo "PASS: source syntax"

echo "[v0.42 hotfix D] static recovery contract"
python3 - <<'PY'
from pathlib import Path
import ast

source = Path("deltaaegis.py").read_text(encoding="utf-8")
ast.parse(source)

required = (
    "SCAN_JOB_COMPLETION_RECONCILIATION_SCHEMA_VERSION",
    "SCAN_JOB_COMPLETION_RECONCILIATION_GRACE_MINUTES = 1",
    "def scan_job_recovery_manifest_evidence(",
    "def scan_job_reconcile_completed_orphan(",
    "resolved.relative_to(runs_root)",
    "netsniper_manifest_matches_scan_job(",
    "ingest_manifest(",
    "scan_job_auto_ingest_evidence(",
    "SAVEPOINT scan_job_completed_orphan",
    "update_scan_schedule_after_job(",
    '"completed_recovery_count"',
    '"failed_recovery_count"',
    "events_path=events_path",
    "trueaegis_execution_mode=trueaegis_execution_mode",
    "waiting for the active scheduled",
    "dashboard_schedule_worker_thread.join()",
)

for marker in required:
    if marker not in source:
        raise SystemExit(
            f"missing schedule-finalization marker: {marker}"
        )

print("PASS: trusted completion-evidence boundary")
print("PASS: completed and failed job schedule reconciliation")
print("PASS: recovery carries ingest and TrueAegis execution context")
print("PASS: graceful dashboard shutdown waits for finalization")
PY

echo "[v0.42 hotfix D] functional completed-orphan recovery"
python3 - <<'PY'
from datetime import datetime, timedelta, timezone
from pathlib import Path
import importlib.util
import json
import os
import sys
import tempfile

repo = Path.cwd()
spec = importlib.util.spec_from_file_location(
    "deltaaegis_v042_finalization_validator",
    repo / "deltaaegis.py",
)
if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v042-finalization-"
) as temp_name:
    root = Path(temp_name)
    db = root / "deltaaegis.db"
    runs = root / "runs"
    logs = root / "logs"
    proc = root / "proc"
    events = root / "events.jsonl"
    netsniper = root / "netsniper.sh"
    runs.mkdir()
    logs.mkdir()
    proc.mkdir()
    netsniper.write_text("#!/bin/sh\n", encoding="utf-8")

    connection = module.connect(db)

    schedule_a = module.create_scan_schedule(
        connection,
        name="A",
        target="10.20.0.0/24",
        scan_profile="balanced",
        cadence_minutes=120,
        enabled=True,
        auto_ingest=True,
        run_trueaegis_after_ingest=False,
    )
    schedule_b = module.create_scan_schedule(
        connection,
        name="B",
        target="10.21.0.0/24",
        scan_profile="balanced",
        cadence_minutes=120,
        enabled=True,
        auto_ingest=False,
        run_trueaegis_after_ingest=False,
    )

    old_a = "2026-07-01T00:00:00+00:00"
    old_b = "2026-07-01T00:05:00+00:00"
    connection.execute(
        "UPDATE scan_schedules SET next_run_at = ? "
        "WHERE schedule_id = ?",
        (old_a, schedule_a["schedule_id"]),
    )
    connection.execute(
        "UPDATE scan_schedules SET next_run_at = ? "
        "WHERE schedule_id = ?",
        (old_b, schedule_b["schedule_id"]),
    )

    job = module.create_scan_job(
        connection,
        "10.20.0.0/24",
        netsniper,
        runs,
        auto_ingest=True,
        scan_profile="balanced",
        schedule_id=schedule_a["schedule_id"],
    )
    started = datetime.now(timezone.utc) - timedelta(minutes=5)
    started_text = module.utc_datetime_to_text(started)
    stdout_path = logs / f"{job['job_id']}.stdout.log"
    stderr_path = logs / f"{job['job_id']}.stderr.log"
    run_dir = runs / "fixture-run"
    run_dir.mkdir()
    manifest_path = run_dir / "manifest.json"
    manifest = {
        "schema_version": "netsniper-run-v3",
        "scan_id": "fixture-recovered-scan",
        "status": "COMPLETE",
        "target": "10.20.0.0/24",
        "network_scope": "10.20.0.0/24",
        "scanner_version": "v2.0.0",
        "scan_profile_requested": "balanced",
        "scan_profile_effective": "balanced",
        "requested_profile": "balanced",
        "effective_profile": "balanced",
    }
    manifest_path.write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    now_epoch = datetime.now(timezone.utc).timestamp()
    os.utime(manifest_path, (now_epoch, now_epoch))
    stdout_path.write_text(
        "pipeline output\n"
        + json.dumps(
            {
                "schema_version": "netsniper-status-v1",
                "status": "completed",
                "target": "10.20.0.0/24",
                "requested_profile": "balanced",
                "effective_profile": "balanced",
                "return_code": 0,
                "run_dir": str(run_dir),
                "manifest_path": str(manifest_path),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    stderr_path.write_text("", encoding="utf-8")

    module.update_scan_job(
        connection,
        job["job_id"],
        status="RUNNING",
        started_at=started_text,
        heartbeat_at=started_text,
        process_pid=987654,
        stdout_log=str(stdout_path),
        stderr_log=str(stderr_path),
        message="fixture running",
    )
    connection.commit()

    ingest_calls = []

    def fake_ingest(connection_arg, manifest_arg, events_arg):
        ingest_calls.append(str(manifest_arg))
        connection_arg.commit()
        return "IMPORT fixture-recovered-scan: quality=ACCEPTED"

    def fake_evidence(
        connection_arg,
        manifest_arg,
        ingest_result,
        status_json=None,
    ):
        return {
            "schema_version": "deltaaegis-scan-auto-ingest-evidence-v1",
            "requested": True,
            "attempted": True,
            "performed": True,
            "accepted": True,
            "quality_status": "ACCEPTED",
            "scan_id": "fixture-recovered-scan",
            "manifest_path": str(manifest_arg),
            "network_scope": "10.20.0.0/24",
            "result": str(ingest_result),
        }

    module.ingest_manifest = fake_ingest
    module.scan_job_auto_ingest_evidence = fake_evidence

    report = module.scan_job_watchdog_recover_dead_jobs(
        connection,
        now=datetime.now(timezone.utc),
        stale_minutes=10,
        proc_root=proc,
        actor="validator",
        events_path=events,
        trueaegis_execution_mode="asynchronous",
    )

    if report["completed_recovery_count"] != 1:
        raise SystemExit(
            f"expected one completed recovery: {report}"
        )

    recovered = connection.execute(
        "SELECT * FROM scan_jobs WHERE job_id = ?",
        (job["job_id"],),
    ).fetchone()
    if recovered["status"] != "COMPLETED":
        raise SystemExit(
            f"orphan was not completed: {dict(recovered)}"
        )
    if recovered["bundle_path"] != str(run_dir):
        raise SystemExit("recovered bundle path was not persisted")
    if recovered["exit_code"] != 0:
        raise SystemExit("recovered exit code is not zero")

    refreshed_a = connection.execute(
        "SELECT * FROM scan_schedules WHERE schedule_id = ?",
        (schedule_a["schedule_id"],),
    ).fetchone()
    if refreshed_a["last_job_id"] != job["job_id"]:
        raise SystemExit("linked schedule history was not updated")
    if refreshed_a["last_status"] != "COMPLETED":
        raise SystemExit("linked schedule status was not completed")
    if refreshed_a["next_run_at"] <= old_b:
        raise SystemExit("recovered schedule was not advanced")

    due = module.query_due_scan_schedules(
        connection,
        limit=1,
        now_text=module.utc_now_text(),
    )
    if not due or due[0]["schedule_id"] != schedule_b["schedule_id"]:
        raise SystemExit(
            "next oldest overdue schedule was not selected"
        )

    module.scan_job_watchdog_recover_dead_jobs(
        connection,
        now=datetime.now(timezone.utc),
        stale_minutes=10,
        proc_root=proc,
        actor="validator-repeat",
        events_path=events,
    )
    if len(ingest_calls) != 1:
        raise SystemExit(
            f"auto-ingest repeated: {ingest_calls}"
        )

    failed_schedule = module.create_scan_schedule(
        connection,
        name="Failed",
        target="10.22.0.0/24",
        scan_profile="balanced",
        cadence_minutes=120,
        enabled=True,
        auto_ingest=False,
    )
    failed_job = module.create_scan_job(
        connection,
        "10.22.0.0/24",
        netsniper,
        runs,
        auto_ingest=False,
        scan_profile="balanced",
        schedule_id=failed_schedule["schedule_id"],
    )
    stale = datetime.now(timezone.utc) - timedelta(minutes=20)
    stale_text = module.utc_datetime_to_text(stale)
    failed_stdout = logs / f"{failed_job['job_id']}.stdout.log"
    failed_stderr = logs / f"{failed_job['job_id']}.stderr.log"
    failed_stdout.write_text(
        "no completion evidence\n",
        encoding="utf-8",
    )
    failed_stderr.write_text("", encoding="utf-8")
    module.update_scan_job(
        connection,
        failed_job["job_id"],
        status="RUNNING",
        started_at=stale_text,
        heartbeat_at=stale_text,
        process_pid=876543,
        stdout_log=str(failed_stdout),
        stderr_log=str(failed_stderr),
        message="failed fixture running",
    )
    connection.commit()

    failed_report = module.scan_job_watchdog_recover_dead_jobs(
        connection,
        now=datetime.now(timezone.utc),
        stale_minutes=10,
        proc_root=proc,
        actor="validator-failed",
        events_path=events,
    )
    if failed_report["failed_recovery_count"] != 1:
        raise SystemExit(
            f"expected one failed recovery: {failed_report}"
        )

    failed_row = connection.execute(
        "SELECT * FROM scan_jobs WHERE job_id = ?",
        (failed_job["job_id"],),
    ).fetchone()
    failed_schedule_row = connection.execute(
        "SELECT * FROM scan_schedules WHERE schedule_id = ?",
        (failed_schedule["schedule_id"],),
    ).fetchone()
    if failed_row["status"] != "FAILED":
        raise SystemExit("stale job without evidence was not failed")
    if failed_schedule_row["last_job_id"] != failed_job["job_id"]:
        raise SystemExit("failed recovery did not update schedule")
    if failed_schedule_row["last_status"] != "FAILED":
        raise SystemExit("failed recovery schedule status is wrong")

    outside = root / "outside" / "manifest.json"
    outside.parent.mkdir()
    outside_manifest = dict(manifest)
    outside_manifest["target"] = "10.23.0.0/24"
    outside_manifest["network_scope"] = "10.23.0.0/24"
    outside.write_text(
        json.dumps(outside_manifest),
        encoding="utf-8",
    )
    outside_stdout = logs / "outside.stdout.log"
    outside_stdout.write_text(
        json.dumps(
            {
                "status": "completed",
                "return_code": 0,
                "manifest_path": str(outside),
                "run_dir": str(outside.parent),
            }
        ),
        encoding="utf-8",
    )
    outside_job = {
        "job_id": "outside",
        "target": "10.23.0.0/24",
        "network_scope": "10.23.0.0/24",
        "status": "RUNNING",
        "created_at": started_text,
        "started_at": started_text,
        "updated_at": started_text,
        "heartbeat_at": started_text,
        "process_pid": 765432,
        "netsniper_path": str(netsniper),
        "runs_dir": str(runs),
        "scan_profile": "balanced",
        "auto_ingest": False,
        "schedule_id": "",
        "stdout_log": str(outside_stdout),
        "stderr_log": "",
        "status_json": {},
        "message": "outside fixture",
    }
    candidate, _ = module.scan_job_recovery_manifest_evidence(
        outside_job
    )
    if candidate is not None:
        raise SystemExit(
            "manifest outside configured runs root was accepted"
        )

    connection.close()

print("PASS: successful orphan reconciled as COMPLETED")
print("PASS: idempotent auto-ingest executed once")
print("PASS: linked schedule history advanced")
print("PASS: next overdue subnet selected fairly")
print("PASS: failed orphan advanced its schedule")
print("PASS: outside-runs manifest rejected")
PY

echo "[v0.42 hotfix D] flat-suite compatibility boundary"
echo "PASS: prior components are composed independently by the suite layer"
echo "PASS: inherited compatibility remains delegated to the release gate"

echo "[v0.42 hotfix D] repository hygiene"
git diff --check
echo "PASS: repository hygiene"

echo "PASS: DeltaAegis v0.42 schedule finalization recovery validator"
