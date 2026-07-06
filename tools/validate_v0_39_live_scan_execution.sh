#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

printf '%s\n' \
  "DeltaAegis v0.39 Live Scan Execution Validator" \
  "================================================"

python3 -m py_compile deltaaegis.py

python3 - <<'PY'
from __future__ import annotations

from pathlib import Path
import inspect
import os
import tempfile
import threading
import time

import deltaaegis


def write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def read_job(db_path: Path, job_id: str) -> dict:
    connection = deltaaegis.connect(db_path)

    try:
        row = connection.execute(
            "SELECT * FROM scan_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()

        assert row is not None, f"scan job missing: {job_id}"
        return deltaaegis.scan_job_to_dict(row)
    finally:
        connection.close()


source = inspect.getsource(deltaaegis.execute_scan_job)

required_source = (
    "subprocess.Popen(",
    "start_new_session=True",
    "stdout=stdout_handle",
    "stderr=stderr_handle",
    "process.wait(timeout=5.0)",
    "heartbeat_at=utc_now_text()",
    "process_pid=process.pid",
    "os.killpg(process.pid, signal.SIGTERM)",
)

for fragment in required_source:
    assert fragment in source, f"missing execution requirement: {fragment}"

for forbidden in (
    "subprocess.run(",
    "stdout=subprocess.PIPE",
    "stderr=subprocess.PIPE",
    "shell=True",
):
    assert forbidden not in source, (
        f"forbidden execution pattern remains: {forbidden}"
    )


with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v039-live-scan-"
) as temp_dir:
    temp = Path(temp_dir)

    db_path = temp / "deltaaegis.db"
    runs_dir = temp / "runs"
    logs_dir = temp / "logs"
    events_path = temp / "events.jsonl"

    runs_dir.mkdir()
    logs_dir.mkdir()

    success_scanner = temp / "fake-success-netsniper.sh"

    write_executable(
        success_scanner,
        """#!/usr/bin/env bash
set -euo pipefail
printf 'scan phase one\n'
printf 'stderr phase one\n' >&2
sleep 7
printf 'scan phase two\n'
printf 'stderr phase two\n' >&2
exit 0
""",
    )

    connection = deltaaegis.connect(db_path)

    success_job = deltaaegis.create_scan_job(
        connection,
        "192.168.50.0/24",
        success_scanner,
        runs_dir,
        scan_profile="balanced",
    )
    connection.commit()
    connection.close()

    result_holder: dict[str, dict] = {}
    error_holder: dict[str, Exception] = {}

    def run_success_job() -> None:
        worker_connection = deltaaegis.connect(db_path)

        try:
            result_holder["job"] = deltaaegis.execute_scan_job(
                worker_connection,
                success_job["job_id"],
                "192.168.50.0/24",
                success_scanner,
                runs_dir,
                logs_dir,
                events_path,
                scan_profile="balanced",
            )
        except Exception as exc:
            error_holder["error"] = exc
        finally:
            worker_connection.close()

    thread = threading.Thread(
        target=run_success_job,
        name="v039-live-scan-validator",
    )
    thread.start()

    running_job = None
    live_deadline = time.monotonic() + 4.0

    while time.monotonic() < live_deadline:
        candidate = read_job(
            db_path,
            success_job["job_id"],
        )

        stdout_path = Path(candidate.get("stdout_log") or "")
        stderr_path = Path(candidate.get("stderr_log") or "")

        stdout_text = (
            stdout_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
            if stdout_path.is_file()
            else ""
        )

        stderr_text = (
            stderr_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
            if stderr_path.is_file()
            else ""
        )

        if (
            candidate["status"] == "RUNNING"
            and candidate.get("process_pid")
            and candidate.get("heartbeat_at")
            and "scan phase one" in stdout_text
            and "stderr phase one" in stderr_text
        ):
            running_job = candidate
            break

        time.sleep(0.1)

    assert running_job is not None, (
        "running job did not expose PID, heartbeat, "
        "and live stdout/stderr content"
    )

    stdout_path = Path(running_job["stdout_log"])
    stderr_path = Path(running_job["stderr_log"])

    stdout_live = stdout_path.read_text(
        encoding="utf-8",
        errors="replace",
    )
    stderr_live = stderr_path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    assert "scan phase one" in stdout_live
    assert "scan phase two" not in stdout_live
    assert "stderr phase one" in stderr_live
    assert "stderr phase two" not in stderr_live

    process_pid = running_job["process_pid"]
    initial_heartbeat = running_job["heartbeat_at"]

    assert isinstance(process_pid, int)
    assert process_pid > 0

    # Signal 0 verifies that the process exists without modifying it.
    os.kill(process_pid, 0)

    heartbeat_advanced = False
    heartbeat_deadline = time.monotonic() + 7.0

    while time.monotonic() < heartbeat_deadline:
        candidate = read_job(
            db_path,
            success_job["job_id"],
        )

        if (
            candidate["status"] == "RUNNING"
            and candidate.get("heartbeat_at")
            and candidate["heartbeat_at"] != initial_heartbeat
            and thread.is_alive()
        ):
            heartbeat_advanced = True
            break

        time.sleep(0.1)

    assert heartbeat_advanced, (
        "heartbeat did not advance while process remained active"
    )

    thread.join(timeout=15.0)

    assert not thread.is_alive(), (
        "successful scan worker did not terminate"
    )
    assert "error" not in error_holder, error_holder.get("error")
    assert "job" in result_holder

    completed = result_holder["job"]

    assert completed["status"] == "COMPLETED"
    assert completed["exit_code"] == 0
    assert completed["process_pid"] == process_pid
    assert completed["heartbeat_at"]
    assert completed["finished_at"]

    final_stdout = stdout_path.read_text(
        encoding="utf-8",
        errors="replace",
    )
    final_stderr = stderr_path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    assert "scan phase one" in final_stdout
    assert "scan phase two" in final_stdout
    assert "stderr phase one" in final_stderr
    assert "stderr phase two" in final_stderr

    failure_scanner = temp / "fake-failure-netsniper.sh"

    write_executable(
        failure_scanner,
        """#!/usr/bin/env bash
set -euo pipefail
printf 'failure stdout\n'
printf 'failure stderr\n' >&2
exit 7
""",
    )

    connection = deltaaegis.connect(db_path)

    failure_job = deltaaegis.create_scan_job(
        connection,
        "192.168.60.0/24",
        failure_scanner,
        runs_dir,
        scan_profile="balanced",
    )
    connection.commit()

    failed = deltaaegis.execute_scan_job(
        connection,
        failure_job["job_id"],
        "192.168.60.0/24",
        failure_scanner,
        runs_dir,
        logs_dir,
        events_path,
        scan_profile="balanced",
    )

    connection.close()

    assert failed["status"] == "FAILED"
    assert failed["exit_code"] == 7
    assert isinstance(failed["process_pid"], int)
    assert failed["process_pid"] > 0
    assert failed["heartbeat_at"]
    assert failed["finished_at"]

    assert "failure stdout" in Path(
        failed["stdout_log"]
    ).read_text(
        encoding="utf-8",
        errors="replace",
    )

    assert "failure stderr" in Path(
        failed["stderr_log"]
    ).read_text(
        encoding="utf-8",
        errors="replace",
    )

print("PASS: fixed-argv Popen execution")
print("PASS: isolated process group")
print("PASS: live stdout visibility")
print("PASS: live stderr visibility")
print("PASS: running PID persistence")
print("PASS: active heartbeat advancement")
print("PASS: successful terminal lifecycle")
print("PASS: nonzero exit-code lifecycle")
print("PASS: no shell or buffered PIPE execution")
PY

git diff --check

printf '%s\n' \
  "PASS: DeltaAegis v0.39 live scan execution validator"
