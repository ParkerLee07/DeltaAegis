#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


EXPECTED_BRANCH = "feature/v0.39-job-lifecycle-observability"
REQUIRED_UX_COMMIT = "a70c157"
REPO = Path.home() / "DeltaAegis"
SOURCE = REPO / "deltaaegis.py"


def git_output(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=REPO,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def reserve_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request_bytes(
    url: str,
    *,
    token: str | None = None,
    method: str = "GET",
    payload: Any = None,
    timeout: float = 5.0,
) -> tuple[int, bytes]:
    headers = {"Accept": "application/json"}

    if token:
        headers["X-DeltaAegis-Token"] = token

    data = None

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read()


def request_json(
    url: str,
    *,
    token: str | None = None,
    method: str = "GET",
    payload: Any = None,
    timeout: float = 5.0,
) -> tuple[int, dict[str, Any]]:
    status, body = request_bytes(
        url,
        token=token,
        method=method,
        payload=payload,
        timeout=timeout,
    )
    decoded = json.loads(body.decode("utf-8"))

    if not isinstance(decoded, dict):
        raise AssertionError(
            f"expected JSON object from {url}, "
            f"got {type(decoded).__name__}"
        )

    return status, decoded


def stop_process_group(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return

    try:
        process.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5.0)


if not SOURCE.is_file():
    raise SystemExit(f"ERROR: missing source file: {SOURCE}")

branch = git_output("branch", "--show-current")
if branch != EXPECTED_BRANCH:
    raise SystemExit(
        f"ERROR: expected branch {EXPECTED_BRANCH!r}, "
        f"found {branch!r}"
    )

ancestor = subprocess.run(
    [
        "git",
        "merge-base",
        "--is-ancestor",
        REQUIRED_UX_COMMIT,
        "HEAD",
    ],
    cwd=REPO,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

if ancestor.returncode != 0:
    raise SystemExit(
        "ERROR: required dashboard cancellation commit "
        f"{REQUIRED_UX_COMMIT} is not an ancestor of HEAD"
    )

with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v039-schedule-delete-http-"
) as temp_dir:
    temp = Path(temp_dir)
    db_path = temp / "deltaaegis.db"
    events_path = temp / "events.jsonl"
    dashboard_log = temp / "dashboard.log"
    runner = temp / "dashboard_runner.py"
    scanner = temp / "netsniper.sh"
    runs_dir = temp / "runs"
    token = "deltaaegis-v039-schedule-delete-token"
    port = reserve_local_port()
    base_url = f"http://127.0.0.1:{port}"

    runs_dir.mkdir()
    scanner.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    scanner.chmod(0o755)

    sys.path.insert(0, str(REPO))
    import deltaaegis

    connection = deltaaegis.connect(db_path)
    schedule = deltaaegis.create_scan_schedule(
        connection,
        name="HTTP Delete Semantics",
        target="192.168.121.0/24",
        scan_profile="balanced",
        cadence_minutes=60,
        enabled=True,
    )

    queued = deltaaegis.create_scan_job(
        connection,
        "192.168.122.0/24",
        scanner,
        runs_dir,
        schedule_id=schedule["schedule_id"],
    )
    running = deltaaegis.create_scan_job(
        connection,
        "192.168.123.0/24",
        scanner,
        runs_dir,
        schedule_id=schedule["schedule_id"],
    )
    deltaaegis.update_scan_job(
        connection,
        running["job_id"],
        status="RUNNING",
        started_at=deltaaegis.utc_now_text(),
        heartbeat_at=deltaaegis.utc_now_text(),
        process_pid=999999,
        message="HTTP fixture running",
    )
    completed = deltaaegis.create_scan_job(
        connection,
        "192.168.124.0/24",
        scanner,
        runs_dir,
        schedule_id=schedule["schedule_id"],
    )
    deltaaegis.update_scan_job(
        connection,
        completed["job_id"],
        status="COMPLETED",
        finished_at=deltaaegis.utc_now_text(),
        exit_code=0,
        message="HTTP fixture completed",
    )
    connection.commit()

    before_jobs = {
        row["job_id"]: dict(row)
        for row in connection.execute(
            "SELECT * FROM scan_jobs WHERE schedule_id = ? ORDER BY job_id",
            (schedule["schedule_id"],),
        ).fetchall()
    }
    connection.close()

    runner.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from pathlib import Path",
                "import argparse",
                "import sys",
                f"sys.path.insert(0, {str(REPO)!r})",
                "import deltaaegis",
                "args = argparse.Namespace(",
                f"    db=Path({str(db_path)!r}),",
                f"    events=Path({str(events_path)!r}),",
                "    host='127.0.0.1',",
                f"    port={port},",
                f"    token={token!r},",
                "    scope=None,",
                "    quiet=True,",
                "    require_login=False,",
                "    enable_scheduled_scans=False,",
                "    schedule_worker_interval_seconds=60,",
                ")",
                "raise SystemExit(deltaaegis.command_dashboard(args))",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    runner.chmod(0o755)

    log_handle = dashboard_log.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [sys.executable, str(runner)],
        cwd=REPO,
        text=True,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )

    try:
        ready = False
        deadline = time.monotonic() + 10.0

        while time.monotonic() < deadline:
            if process.poll() is not None:
                break

            try:
                status, body = request_bytes(
                    f"{base_url}/healthz",
                    timeout=1.0,
                )
                if status == 200 and body.decode("utf-8").strip() == "ok":
                    ready = True
                    break
            except (OSError, urllib.error.URLError):
                pass

            time.sleep(0.1)

        if not ready:
            log_handle.flush()
            raise AssertionError(
                "dashboard did not become healthy\n"
                + dashboard_log.read_text(
                    encoding="utf-8",
                    errors="replace",
                )
            )

        status, page = request_bytes(
            f"{base_url}/netsniper",
            token=token,
        )
        assert status == 200
        html = page.decode("utf-8")

        for marker in (
            "Existing queued or running scan jobs are not cancelled",
            "Use the dedicated",
            "Cancel active scan control to stop an active job.",
            "DELETE SCHEDULE ${scheduleId}",
            "await loadNetSniperScheduleHistory();",
        ):
            assert marker in html, marker

        endpoint = f"{base_url}/api/netsniper/schedule-delete"

        status, unauthorized = request_json(
            endpoint,
            method="POST",
            payload={
                "schedule_id": schedule["schedule_id"],
                "confirmation": f"DELETE SCHEDULE {schedule['schedule_id']}",
            },
        )
        assert status == 401
        assert unauthorized.get("error") == "unauthorized"

        status, missing_confirmation = request_json(
            endpoint,
            token=token,
            method="POST",
            payload={"schedule_id": schedule["schedule_id"]},
        )
        assert status == 400
        assert missing_confirmation.get("ok") is False
        assert "confirmation" in (
            missing_confirmation.get("error")
            or missing_confirmation.get("message")
            or ""
        ).lower()

        confirmation = f"DELETE SCHEDULE {schedule['schedule_id']}"
        status, deleted = request_json(
            endpoint,
            token=token,
            method="POST",
            payload={
                "schedule_id": schedule["schedule_id"],
                "confirmation": confirmation,
            },
        )
        assert status == 200
        assert deleted.get("ok") is True
        assert deleted["confirmation_required"] == confirmation
        assert deleted["linked_job_count"] == 3
        assert deleted["linked_active_job_count"] == 2
        assert deleted["linked_job_status_counts"] == {
            "COMPLETED": 1,
            "QUEUED": 1,
            "RUNNING": 1,
        }
        assert deleted["linked_jobs_preserved"] is True
        assert deleted["active_jobs_cancelled"] is False
        assert deleted["cancellation_required_for_active_jobs"] is True

        status, history_payload = request_json(
            f"{base_url}/api/netsniper/schedule-history?limit=50",
            token=token,
        )
        assert status == 200
        history = history_payload.get("history") or []
        deleted_history = [
            item
            for item in history
            if item.get("schedule_id") == schedule["schedule_id"]
        ]
        assert len(deleted_history) == 3
        assert all(item.get("deleted") for item in deleted_history)
        assert {
            item["job"]["job_id"]
            for item in deleted_history
            if item.get("job")
        } == {queued["job_id"], running["job_id"], completed["job_id"]}

        status, repeated = request_json(
            endpoint,
            token=token,
            method="POST",
            payload={
                "schedule_id": schedule["schedule_id"],
                "confirmation": confirmation,
            },
        )
        assert status == 400
        assert repeated.get("ok") is False
        assert "not found" in (
            repeated.get("error")
            or repeated.get("message")
            or ""
        ).lower()

        connection = deltaaegis.connect(db_path)
        try:
            assert connection.execute(
                "SELECT 1 FROM scan_schedules WHERE schedule_id = ?",
                (schedule["schedule_id"],),
            ).fetchone() is None

            tombstone = connection.execute(
                "SELECT * FROM scan_schedule_deletions WHERE schedule_id = ?",
                (schedule["schedule_id"],),
            ).fetchone()
            assert tombstone is not None

            after_jobs = {
                row["job_id"]: dict(row)
                for row in connection.execute(
                    "SELECT * FROM scan_jobs WHERE schedule_id = ? ORDER BY job_id",
                    (schedule["schedule_id"],),
                ).fetchall()
            }
            assert after_jobs == before_jobs
        finally:
            connection.close()

        print("PASS: schedule deletion warning served")
        print("PASS: unauthenticated deletion rejection")
        print("PASS: exact confirmation required")
        print("PASS: authenticated schedule deletion")
        print("PASS: linked job status summary")
        print("PASS: queued and running jobs not cancelled")
        print("PASS: terminal job preserved")
        print("PASS: deleted schedule history visible over HTTP")
        print("PASS: tombstone evidence persisted")
        print("PASS: repeated deletion reports not found")

    finally:
        stop_process_group(process)
        log_handle.close()
