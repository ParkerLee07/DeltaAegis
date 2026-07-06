#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

printf '%s\n' \
  "DeltaAegis v0.39 Schedule Deletion Semantics Validator" \
  "======================================================="

python3 -m py_compile deltaaegis.py

python3 - <<'PY'
from __future__ import annotations

from pathlib import Path
import inspect
import json
import tempfile

import deltaaegis


EXPECTED_TOMBSTONE_COLUMNS = {
    "schedule_id",
    "name",
    "target",
    "network_scope",
    "scan_profile",
    "cadence_minutes",
    "enabled",
    "auto_ingest",
    "run_trueaegis_after_ingest",
    "last_run_at",
    "next_run_at",
    "last_job_id",
    "last_status",
    "failure_count",
    "skip_count",
    "created_at",
    "updated_at",
    "message",
    "deleted_at",
    "linked_job_count",
    "linked_active_job_count",
    "linked_job_status_counts_json",
}


def table_columns(connection, table):
    return {
        row[1]
        for row in connection.execute(
            f"PRAGMA table_info({table})"
        )
    }


def job_dict(connection, job_id):
    row = connection.execute(
        "SELECT * FROM scan_jobs WHERE job_id = ?",
        (job_id,),
    ).fetchone()
    assert row is not None
    return deltaaegis.scan_job_to_dict(row)


source = Path("deltaaegis.py").read_text(encoding="utf-8")
delete_source = inspect.getsource(deltaaegis.delete_scan_schedule)
update_source = inspect.getsource(deltaaegis.update_scan_schedule_after_job)

assert "CREATE TABLE IF NOT EXISTS scan_schedule_deletions" in source
assert "WITH schedule_sources AS" in source
assert "SCAN_SCHEDULE_DELETE_CONFIRMATION_PREFIX" in source
assert "INSERT OR REPLACE INTO scan_schedule_deletions" in delete_source
assert "UPDATE scan_schedule_deletions" in update_source

for forbidden in (
    "DELETE FROM scan_jobs",
    "UPDATE scan_jobs",
    "request_scan_job_cancellation",
    "os.kill",
    "killpg",
    "SIGTERM",
    "SIGKILL",
):
    assert forbidden not in delete_source, forbidden

with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v039-schedule-delete-"
) as temp_dir:
    temp = Path(temp_dir)
    db_path = temp / "deltaaegis.db"
    runs_dir = temp / "runs"
    scanner = temp / "netsniper.sh"
    runs_dir.mkdir()
    scanner.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    scanner.chmod(0o755)

    connection = deltaaegis.connect(db_path)

    missing = EXPECTED_TOMBSTONE_COLUMNS - table_columns(
        connection,
        "scan_schedule_deletions",
    )
    assert not missing, sorted(missing)

    schedule = deltaaegis.create_scan_schedule(
        connection,
        name="Deletion Semantics",
        target="192.168.94.0/24",
        scan_profile="balanced",
        cadence_minutes=60,
        enabled=True,
        auto_ingest=True,
        run_trueaegis_after_ingest=True,
    )

    unrelated_schedule = deltaaegis.create_scan_schedule(
        connection,
        name="Unrelated Schedule",
        target="192.168.95.0/24",
        scan_profile="quick",
        cadence_minutes=120,
        enabled=True,
    )

    statuses = [
        "QUEUED",
        "RUNNING",
        "COMPLETED",
        "FAILED",
        "CANCELLED",
    ]
    linked_jobs = []

    for index, status in enumerate(statuses):
        job = deltaaegis.create_scan_job(
            connection,
            f"192.168.{100 + index}.0/24",
            scanner,
            runs_dir,
            scan_profile="balanced",
            schedule_id=schedule["schedule_id"],
        )

        if status != "QUEUED":
            fields = {
                "status": status,
                "message": f"validator {status.lower()}",
            }

            if status == "RUNNING":
                fields.update(
                    started_at=deltaaegis.utc_now_text(),
                    heartbeat_at=deltaaegis.utc_now_text(),
                    process_pid=999999,
                )
            else:
                fields.update(
                    finished_at=deltaaegis.utc_now_text(),
                    exit_code=(0 if status == "COMPLETED" else 1),
                )

            if status == "CANCELLED":
                fields.update(
                    cancel_requested_at=deltaaegis.utc_now_text(),
                    cancel_requested_by="validator",
                    cancel_reason="fixture cancellation",
                    cancelled_at=deltaaegis.utc_now_text(),
                    exit_code=130,
                )

            deltaaegis.update_scan_job(
                connection,
                job["job_id"],
                **fields,
            )

        linked_jobs.append(job["job_id"])

    unrelated_job = deltaaegis.create_scan_job(
        connection,
        "192.168.120.0/24",
        scanner,
        runs_dir,
        schedule_id=unrelated_schedule["schedule_id"],
    )
    connection.commit()

    snapshots = {
        job_id: job_dict(connection, job_id)
        for job_id in linked_jobs
    }
    unrelated_snapshot = job_dict(
        connection,
        unrelated_job["job_id"],
    )

    confirmation = deltaaegis.scan_schedule_delete_confirmation(
        schedule["schedule_id"]
    )
    assert confirmation == f"DELETE SCHEDULE {schedule['schedule_id']}"

    for bad_payload in (
        {"schedule_id": schedule["schedule_id"]},
        {
            "schedule_id": schedule["schedule_id"],
            "confirmation": "DELETE SCHEDULE wrong-id",
        },
    ):
        try:
            deltaaegis.dashboard_netsniper_schedule_delete_payload(
                connection,
                bad_payload,
            )
        except deltaaegis.DashboardAdminUserActionError as exc:
            assert exc.status_code == 400
            assert "confirmation" in str(exc).lower()
        else:
            raise AssertionError(
                "schedule deletion accepted invalid confirmation"
            )

    result = deltaaegis.dashboard_netsniper_schedule_delete_payload(
        connection,
        {
            "schedule_id": schedule["schedule_id"],
            "confirmation": confirmation,
        },
    )
    connection.commit()

    assert result["ok"] is True
    assert result["linked_job_count"] == 5
    assert result["linked_active_job_count"] == 2
    assert result["linked_jobs_preserved"] is True
    assert result["active_jobs_cancelled"] is False
    assert result["cancellation_required_for_active_jobs"] is True
    assert result["linked_job_status_counts"] == {
        "CANCELLED": 1,
        "COMPLETED": 1,
        "FAILED": 1,
        "QUEUED": 1,
        "RUNNING": 1,
    }

    schedule_row = connection.execute(
        "SELECT * FROM scan_schedules WHERE schedule_id = ?",
        (schedule["schedule_id"],),
    ).fetchone()
    assert schedule_row is None

    tombstone = connection.execute(
        "SELECT * FROM scan_schedule_deletions WHERE schedule_id = ?",
        (schedule["schedule_id"],),
    ).fetchone()
    assert tombstone is not None
    tombstone_dict = deltaaegis.scan_schedule_deletion_to_dict(
        tombstone
    )
    assert tombstone_dict["name"] == "Deletion Semantics"
    assert tombstone_dict["run_trueaegis_after_ingest"] is True
    assert tombstone_dict["linked_job_count"] == 5
    assert tombstone_dict["linked_active_job_count"] == 2
    assert tombstone_dict["deleted"] is True
    assert tombstone_dict["deleted_at"]

    for job_id, before in snapshots.items():
        after = job_dict(connection, job_id)
        assert after == before, (job_id, before, after)
        assert after["schedule_id"] == schedule["schedule_id"]

    unrelated_row = connection.execute(
        "SELECT * FROM scan_schedules WHERE schedule_id = ?",
        (unrelated_schedule["schedule_id"],),
    ).fetchone()
    assert unrelated_row is not None
    assert (
        job_dict(connection, unrelated_job["job_id"])
        == unrelated_snapshot
    )

    history = [
        deltaaegis.scan_schedule_history_row_to_dict(row)
        for row in deltaaegis.query_scan_schedule_history(
            connection,
            limit=50,
        )
    ]
    deleted_history = [
        item
        for item in history
        if item["schedule_id"] == schedule["schedule_id"]
    ]
    assert len(deleted_history) == 5
    assert all(item["deleted"] for item in deleted_history)
    assert all(item["deleted_at"] for item in deleted_history)
    assert {
        item["job"]["job_id"]
        for item in deleted_history
        if item["job"]
    } == set(linked_jobs)

    scoped_history = [
        deltaaegis.scan_schedule_history_row_to_dict(row)
        for row in deltaaegis.query_scan_schedule_history(
            connection,
            limit=50,
            scope=schedule["network_scope"],
        )
    ]
    assert scoped_history
    assert all(
        item["schedule_id"] == schedule["schedule_id"]
        for item in scoped_history
    )

    running_id = linked_jobs[1]
    deltaaegis.update_scan_job(
        connection,
        running_id,
        status="COMPLETED",
        heartbeat_at=deltaaegis.utc_now_text(),
        finished_at=deltaaegis.utc_now_text(),
        exit_code=0,
        message="completed after schedule deletion",
    )
    completed_after_delete = job_dict(connection, running_id)

    updated_tombstone = deltaaegis.update_scan_schedule_after_job(
        connection,
        schedule["schedule_id"],
        schedule["cadence_minutes"],
        completed_after_delete,
    )
    connection.commit()

    assert updated_tombstone["deleted"] is True
    assert updated_tombstone["last_job_id"] == running_id
    assert updated_tombstone["last_status"] == "COMPLETED"
    assert updated_tombstone["next_run_at"] is None
    assert updated_tombstone["linked_job_count"] == 5
    assert updated_tombstone["linked_active_job_count"] == 1
    assert updated_tombstone["linked_job_status_counts"] == {
        "CANCELLED": 1,
        "COMPLETED": 2,
        "FAILED": 1,
        "QUEUED": 1,
    }
    assert connection.execute(
        "SELECT 1 FROM scan_schedules WHERE schedule_id = ?",
        (schedule["schedule_id"],),
    ).fetchone() is None
    assert job_dict(connection, running_id)["status"] == "COMPLETED"

    try:
        deltaaegis.dashboard_netsniper_schedule_delete_payload(
            connection,
            {
                "schedule_id": schedule["schedule_id"],
                "confirmation": confirmation,
            },
        )
    except deltaaegis.DeltaAegisError as exc:
        assert "not found" in str(exc).lower()
    else:
        raise AssertionError("repeated deletion unexpectedly succeeded")

    connection.close()

    reopened = deltaaegis.connect(db_path)
    missing = EXPECTED_TOMBSTONE_COLUMNS - table_columns(
        reopened,
        "scan_schedule_deletions",
    )
    assert not missing, sorted(missing)
    assert reopened.execute(
        "SELECT 1 FROM scan_schedule_deletions WHERE schedule_id = ?",
        (schedule["schedule_id"],),
    ).fetchone() is not None
    reopened.close()

print("PASS: schedule deletion tombstone schema")
print("PASS: schema initialization idempotence")
print("PASS: exact API confirmation requirement")
print("PASS: linked status and active-job summary")
print("PASS: queued and running jobs preserved")
print("PASS: terminal jobs preserved")
print("PASS: job schedule_id evidence preserved")
print("PASS: unrelated schedules and jobs untouched")
print("PASS: deleted schedule history remains readable")
print("PASS: deleted schedule scope filtering")
print("PASS: post-deletion job completion refreshes tombstone summary")
print("PASS: repeated deletion reports not found")
print("PASS: no implicit job mutation or cancellation")
PY

git diff --check

printf '%s\n' \
  "PASS: DeltaAegis v0.39 schedule deletion semantics validator"
