#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

printf '%s\n' \
  "DeltaAegis v0.39 Cancellation Backend Validator" \
  "================================================"

python3 -m py_compile deltaaegis.py

python3 - <<'PY'
from __future__ import annotations

from pathlib import Path
import inspect
import os
import sqlite3
import tempfile
import threading
import time

import deltaaegis


EXPECTED_COLUMNS = {
    "cancel_requested_at",
    "cancel_requested_by",
    "cancel_reason",
    "cancelled_at",
}


def table_columns(connection, table):
    return {
        row[1]
        for row in connection.execute(f"PRAGMA table_info({table})")
    }


def read_job(db_path: Path, job_id: str) -> dict:
    connection = deltaaegis.connect(db_path)
    try:
        row = connection.execute(
            "SELECT * FROM scan_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        assert row is not None
        return deltaaegis.scan_job_to_dict(row)
    finally:
        connection.close()


source = Path("deltaaegis.py").read_text(encoding="utf-8")
execute_source = inspect.getsource(deltaaegis.execute_scan_job)

assert "CANCELLED" in deltaaegis.SCAN_JOB_STATUSES
assert "def request_scan_job_cancellation(" in source
assert "def terminate_scan_process_group(" in source
assert "AND cancel_requested_at IS NULL" in execute_source
assert "process.wait(timeout=5.0)" in execute_source
assert "scan_job_cancellation_request(" in execute_source
assert 'status="CANCELLED"' in execute_source
assert "os.killpg(process.pid, signal.SIGTERM)" in source
assert "os.killpg(process.pid, signal.SIGKILL)" in source

with tempfile.TemporaryDirectory(prefix="deltaaegis-v039-cancel-") as temp_dir:
    temp = Path(temp_dir)
    db_path = temp / "deltaaegis.db"
    runs_dir = temp / "runs"
    logs_dir = temp / "logs"
    events_path = temp / "events.jsonl"
    runs_dir.mkdir()
    logs_dir.mkdir()

    connection = deltaaegis.connect(db_path)
    missing = EXPECTED_COLUMNS - table_columns(connection, "scan_jobs")
    assert not missing, sorted(missing)

    queued = deltaaegis.create_scan_job(
        connection,
        "192.168.80.0/24",
        temp / "fake-queued.sh",
        runs_dir,
        scan_profile="balanced",
    )
    connection.commit()

    assert queued["cancel_requested_at"] is None
    assert queued["cancel_requested_by"] == ""
    assert queued["cancel_reason"] == ""
    assert queued["cancelled_at"] is None

    cancelled_queued = deltaaegis.request_scan_job_cancellation(
        connection,
        queued["job_id"],
        requested_by="validator",
        reason="cancel before launch",
    )
    connection.commit()

    assert cancelled_queued["status"] == "CANCELLED"
    assert cancelled_queued["cancel_requested_at"]
    assert cancelled_queued["cancel_requested_by"] == "validator"
    assert cancelled_queued["cancel_reason"] == "cancel before launch"
    assert cancelled_queued["cancelled_at"]
    assert cancelled_queued["finished_at"]
    assert cancelled_queued["exit_code"] == 130
    assert cancelled_queued["cancellation_action"] == "cancelled_before_start"

    repeated_queued = deltaaegis.request_scan_job_cancellation(
        connection,
        queued["job_id"],
        requested_by="other",
        reason="must not overwrite",
    )
    assert repeated_queued["cancellation_action"] == "already_cancelled"
    assert repeated_queued["cancel_requested_by"] == "validator"
    assert repeated_queued["cancel_reason"] == "cancel before launch"

    filtered = deltaaegis.query_scan_jobs(
        connection,
        status="CANCELLED",
        limit=10,
    )
    assert any(row["job_id"] == queued["job_id"] for row in filtered)
    connection.close()

    slow_scanner = temp / "fake-slow-netsniper.sh"
    slow_scanner.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf 'phase one\\n'\n"
        "printf 'stderr one\\n' >&2\n"
        "sleep 30\n"
        "printf 'phase two\\n'\n"
        "printf 'stderr two\\n' >&2\n",
        encoding="utf-8",
    )
    slow_scanner.chmod(0o755)

    connection = deltaaegis.connect(db_path)
    running_job = deltaaegis.create_scan_job(
        connection,
        "192.168.81.0/24",
        slow_scanner,
        runs_dir,
        scan_profile="balanced",
    )
    connection.commit()
    connection.close()

    result_holder = {}
    error_holder = {}

    def run_job():
        worker = deltaaegis.connect(db_path)
        try:
            result_holder["job"] = deltaaegis.execute_scan_job(
                worker,
                running_job["job_id"],
                "192.168.81.0/24",
                slow_scanner,
                runs_dir,
                logs_dir,
                events_path,
                scan_profile="balanced",
            )
        except Exception as exc:
            error_holder["error"] = exc
        finally:
            worker.close()

    thread = threading.Thread(target=run_job)
    thread.start()

    active = None
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        candidate = read_job(db_path, running_job["job_id"])
        if (
            candidate["status"] == "RUNNING"
            and candidate.get("process_pid")
            and candidate.get("heartbeat_at")
        ):
            active = candidate
            break
        time.sleep(0.1)

    assert active is not None
    process_pid = int(active["process_pid"])
    os.kill(process_pid, 0)

    requester = deltaaegis.connect(db_path)
    requested = deltaaegis.request_scan_job_cancellation(
        requester,
        running_job["job_id"],
        requested_by="validator",
        reason="stop the slow scan",
    )
    requester.commit()

    repeated = deltaaegis.request_scan_job_cancellation(
        requester,
        running_job["job_id"],
        requested_by="second-actor",
        reason="must not replace first request",
    )
    requester.close()

    assert requested["status"] == "RUNNING"
    assert requested["cancellation_action"] == "requested"
    assert repeated["cancellation_action"] == "already_requested"
    assert repeated["cancel_requested_by"] == "validator"
    assert repeated["cancel_reason"] == "stop the slow scan"

    thread.join(timeout=12.0)
    assert not thread.is_alive()
    assert "error" not in error_holder, error_holder.get("error")
    cancelled = result_holder["job"]

    assert cancelled["status"] == "CANCELLED"
    assert cancelled["exit_code"] == 130
    assert cancelled["process_pid"] == process_pid
    assert cancelled["cancel_requested_at"]
    assert cancelled["cancelled_at"]
    assert cancelled["finished_at"]
    assert cancelled["cancel_requested_by"] == "validator"
    assert cancelled["cancel_reason"] == "stop the slow scan"
    assert cancelled["status_json"]["cancellation"]["state"] == "CANCELLED"

    try:
        os.kill(process_pid, 0)
    except ProcessLookupError:
        pass
    else:
        raise AssertionError("cancelled process still exists")

    stdout_text = Path(cancelled["stdout_log"]).read_text(
        encoding="utf-8",
        errors="replace",
    )
    stderr_text = Path(cancelled["stderr_log"]).read_text(
        encoding="utf-8",
        errors="replace",
    )
    assert "phase one" in stdout_text
    assert "phase two" not in stdout_text
    assert "stderr one" in stderr_text
    assert "stderr two" not in stderr_text

    terminal_connection = deltaaegis.connect(db_path)
    idempotent = deltaaegis.request_scan_job_cancellation(
        terminal_connection,
        running_job["job_id"],
        requested_by="validator",
        reason="repeat terminal request",
    )
    assert idempotent["cancellation_action"] == "already_cancelled"

    completed = deltaaegis.create_scan_job(
        terminal_connection,
        "192.168.82.0/24",
        slow_scanner,
        runs_dir,
    )
    deltaaegis.update_scan_job(
        terminal_connection,
        completed["job_id"],
        status="COMPLETED",
        finished_at=deltaaegis.utc_now_text(),
        exit_code=0,
    )
    terminal_connection.commit()

    try:
        deltaaegis.request_scan_job_cancellation(
            terminal_connection,
            completed["job_id"],
            requested_by="validator",
            reason="too late",
        )
    except deltaaegis.DeltaAegisError:
        pass
    else:
        raise AssertionError("COMPLETED job accepted cancellation")
    terminal_connection.close()

    legacy_db = temp / "legacy.db"
    legacy = sqlite3.connect(legacy_db)
    legacy.executescript(
        "CREATE TABLE scan_jobs ("
        "job_id TEXT PRIMARY KEY,"
        "target TEXT NOT NULL,"
        "network_scope TEXT NOT NULL DEFAULT '',"
        "schedule_id TEXT NOT NULL DEFAULT '',"
        "status TEXT NOT NULL,"
        "created_at TEXT NOT NULL,"
        "updated_at TEXT NOT NULL,"
        "started_at TEXT,"
        "heartbeat_at TEXT,"
        "finished_at TEXT,"
        "process_pid INTEGER,"
        "netsniper_path TEXT NOT NULL DEFAULT '',"
        "runs_dir TEXT NOT NULL DEFAULT '',"
        "scan_profile TEXT NOT NULL DEFAULT 'balanced',"
        "bundle_path TEXT,"
        "exit_code INTEGER,"
        "auto_ingest INTEGER NOT NULL DEFAULT 0,"
        "stdout_log TEXT,"
        "stderr_log TEXT,"
        "status_json TEXT NOT NULL DEFAULT '{}',"
        "message TEXT NOT NULL DEFAULT ''"
        ");"
    )
    legacy.commit()
    legacy.close()

    upgraded = deltaaegis.connect(legacy_db)
    missing = EXPECTED_COLUMNS - table_columns(upgraded, "scan_jobs")
    assert not missing, sorted(missing)
    upgraded.close()

    reopened = deltaaegis.connect(legacy_db)
    missing = EXPECTED_COLUMNS - table_columns(reopened, "scan_jobs")
    assert not missing, sorted(missing)
    reopened.close()

print("PASS: CANCELLED terminal status")
print("PASS: fresh cancellation schema")
print("PASS: legacy cancellation migration")
print("PASS: migration idempotence")
print("PASS: queued cancellation without process launch")
print("PASS: running cancellation request persistence")
print("PASS: repeated request idempotence")
print("PASS: worker-owned process-group termination")
print("PASS: SIGTERM with SIGKILL escalation path")
print("PASS: cancellation metadata preservation")
print("PASS: cancelled process termination")
print("PASS: cancelled log evidence preservation")
print("PASS: completed job cancellation rejection")
print("PASS: explicit CANCELLED query support")
PY

git diff --check

printf '%s\n' \
  "PASS: DeltaAegis v0.39 cancellation backend validator"
