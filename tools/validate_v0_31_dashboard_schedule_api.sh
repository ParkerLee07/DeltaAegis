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

grep -Fq '"/api/netsniper/schedules"' deltaaegis.py \
    || fail "missing GET schedules API route policy"

grep -Fq '"/api/netsniper/schedule-create"' deltaaegis.py \
    || fail "missing schedule-create API route"

grep -Fq '"/api/netsniper/schedule-enable"' deltaaegis.py \
    || fail "missing schedule-enable API route"

grep -Fq '"/api/netsniper/schedule-disable"' deltaaegis.py \
    || fail "missing schedule-disable API route"

grep -Fq '"/api/netsniper/schedule-delete"' deltaaegis.py \
    || fail "missing schedule-delete API route"

grep -Fq '"/api/netsniper/schedule-run-due"' deltaaegis.py \
    || fail "missing schedule-run-due API route"

grep -Fq 'def dashboard_scan_schedules_payload(' deltaaegis.py \
    || fail "missing dashboard scan schedules payload helper"

grep -Fq 'def dashboard_netsniper_schedule_action_payload(' deltaaegis.py \
    || fail "missing dashboard schedule action helper"

grep -Fq 'if not self.require_permission("scan.start")' deltaaegis.py \
    || fail "dashboard schedule mutation routes are not ADMIN gated through scan.start"

python3 - <<'DELTA_31_3A_PYTEST'
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

    created = module.dashboard_netsniper_schedule_action_payload(
        connection,
        "/api/netsniper/schedule-create",
        {
            "name": "Hourly Balanced Monitoring",
            "target": "192.168.5.0/24",
            "scan_profile": "balanced",
            "cadence_minutes": 60,
            "enabled": True,
            "auto_ingest": False,
        },
        tmp_path / "events.jsonl",
    )
    connection.commit()

    assert created["ok"] is True
    assert created["schedule"]["scan_profile"] == "balanced"
    assert created["schedule"]["cadence_minutes"] == 60
    assert created["schedule"]["auto_ingest"] is False
    schedule_id = created["schedule"]["schedule_id"]

    listed = module.dashboard_scan_schedules_payload(connection)
    assert len(listed) == 1

    disabled = module.dashboard_netsniper_schedule_action_payload(
        connection,
        "/api/netsniper/schedule-disable",
        {"schedule_id": schedule_id},
        tmp_path / "events.jsonl",
    )
    connection.commit()
    assert disabled["schedule"]["enabled"] is False

    enabled = module.dashboard_netsniper_schedule_action_payload(
        connection,
        "/api/netsniper/schedule-enable",
        {"schedule_id": schedule_id},
        tmp_path / "events.jsonl",
    )
    connection.commit()
    assert enabled["schedule"]["enabled"] is True

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
            message=f"fake dashboard scheduled scan completed profile={scan_profile}",
        )
        connection.commit()
        row = connection.execute(
            "SELECT * FROM scan_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        return module.scan_job_to_dict(row)

    module.execute_scan_job = fake_execute_scan_job

    run_due = module.dashboard_netsniper_schedule_action_payload(
        connection,
        "/api/netsniper/schedule-run-due",
        {"max_runs": 1},
        tmp_path / "events.jsonl",
    )
    connection.commit()

    assert run_due["ok"] is True
    assert len(run_due["results"]) == 1
    assert run_due["results"][0]["action"] == "ran"
    assert run_due["results"][0]["job"]["status"] == "COMPLETED"

    deleted = module.dashboard_netsniper_schedule_action_payload(
        connection,
        "/api/netsniper/schedule-delete",
        {"schedule_id": schedule_id},
        tmp_path / "events.jsonl",
    )
    connection.commit()

    assert deleted["ok"] is True
    assert deleted["schedule_id"] == schedule_id
    assert module.dashboard_scan_schedules_payload(connection) == []

    try:
        module.dashboard_netsniper_schedule_action_payload(
            connection,
            "/api/netsniper/schedule-create",
            {
                "name": "Bad Public Target",
                "target": "8.8.8.0/24",
                "scan_profile": "balanced",
                "cadence_minutes": 60,
            },
            tmp_path / "events.jsonl",
        )
    except module.DeltaAegisError:
        pass
    else:
        raise AssertionError("public target schedule was accepted by dashboard API helper")

print("[PASS] v0.31 dashboard schedule API python checks passed")
DELTA_31_3A_PYTEST

ok "DeltaAegis v0.31 dashboard schedule API validation passed"
