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
REQUIRED_API_COMMIT = "18d255c"
REPO = Path(__file__).resolve().parents[1]
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
    headers = {}

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
        REQUIRED_API_COMMIT,
        "HEAD",
    ],
    cwd=REPO,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

if ancestor.returncode != 0:
    raise SystemExit(
        "ERROR: required cancellation API commit "
        f"{REQUIRED_API_COMMIT} is not an ancestor of HEAD"
    )

with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v039-dashboard-cancel-"
) as temp_dir:
    temp = Path(temp_dir)
    db_path = temp / "deltaaegis.db"
    events_path = temp / "events.jsonl"
    netsniper_root = temp / "NetSniper"
    runs_dir = temp / "runs"
    logs_dir = temp / "scan-logs"
    dashboard_log = temp / "dashboard.log"
    runner = temp / "dashboard_runner.py"
    token = "deltaaegis-v039-dashboard-cancel-token"
    port = reserve_local_port()
    base_url = f"http://127.0.0.1:{port}"

    netsniper_root.mkdir()
    runs_dir.mkdir()
    logs_dir.mkdir()

    fake_scanner = netsniper_root / "netsniper.sh"
    fake_scanner.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf 'cancel smoke phase one\\n'\n"
        "printf 'cancel smoke stderr one\\n' >&2\n"
        "sleep 30\n"
        "printf 'cancel smoke phase two\\n'\n"
        "printf 'cancel smoke stderr two\\n' >&2\n",
        encoding="utf-8",
    )
    fake_scanner.chmod(0o755)

    runner.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from pathlib import Path",
                "import argparse",
                "import sys",
                f"sys.path.insert(0, {str(REPO)!r})",
                "import deltaaegis",
                f"deltaaegis.DEFAULT_SCAN_LOGS = Path({str(logs_dir)!r})",
                (
                    "deltaaegis.dashboard_netsniper_root_path = "
                    f"lambda: Path({str(netsniper_root)!r})"
                ),
                (
                    "deltaaegis.dashboard_netsniper_runs_dir = "
                    f"lambda: Path({str(runs_dir)!r})"
                ),
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

    scan_pid = None

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
            'id="netsniper-live-job-cancel-form"',
            'id="netsniper-live-job-cancel-reason"',
            'id="netsniper-live-job-cancel"',
            "window.confirm(",
            'fetch("/api/netsniper/scan-cancel"',
            "A cancellation reason is required.",
        ):
            assert marker in html, marker

        status, started = request_json(
            f"{base_url}/api/netsniper/scan-start",
            token=token,
            method="POST",
            payload={
                "target": "192.168.93.0/24",
                "scan_profile": "balanced",
            },
        )
        assert status in {200, 202}
        assert started.get("ok") is True
        job_id = started["job_id"]

        running = None
        deadline = time.monotonic() + 10.0

        while time.monotonic() < deadline:
            status, detail = request_json(
                (
                    f"{base_url}/api/netsniper/job-detail"
                    f"?job_id={job_id}&tail_bytes=16384"
                ),
                token=token,
            )
            assert status == 200

            job = detail["job"]
            stdout = detail["stdout"]
            stderr = detail["stderr"]

            if (
                job.get("status") == "RUNNING"
                and job.get("process_pid")
                and "cancel smoke phase one" in stdout.get("text", "")
                and "cancel smoke stderr one" in stderr.get("text", "")
            ):
                running = detail
                break

            time.sleep(0.2)

        assert running is not None
        scan_pid = int(running["job"]["process_pid"])
        os.kill(scan_pid, 0)

        status, cancel = request_json(
            f"{base_url}/api/netsniper/scan-cancel",
            token=token,
            method="POST",
            payload={
                "job_id": job_id,
                "reason": "dashboard cancellation smoke",
            },
        )
        assert status == 200
        assert cancel.get("ok") is True
        assert cancel["cancellation_action"] == "requested"
        assert cancel["job"]["cancel_requested_at"]
        assert (
            cancel["job"]["cancel_reason"]
            == "dashboard cancellation smoke"
        )

        terminal = None
        deadline = time.monotonic() + 15.0

        while time.monotonic() < deadline:
            status, detail = request_json(
                (
                    f"{base_url}/api/netsniper/job-detail"
                    f"?job_id={job_id}&tail_bytes=16384"
                ),
                token=token,
            )
            assert status == 200

            if detail["job"].get("status") == "CANCELLED":
                terminal = detail
                break

            time.sleep(0.25)

        assert terminal is not None
        job = terminal["job"]

        assert job["cancel_requested_at"]
        assert job["cancel_requested_by"] == "dashboard"
        assert job["cancel_reason"] == "dashboard cancellation smoke"
        assert job["cancelled_at"]
        assert job["finished_at"]
        assert job["exit_code"] == 130
        assert job["process_pid"] == scan_pid
        assert "cancel smoke phase one" in terminal["stdout"]["text"]
        assert "cancel smoke phase two" not in terminal["stdout"]["text"]
        assert "cancel smoke stderr one" in terminal["stderr"]["text"]
        assert "cancel smoke stderr two" not in terminal["stderr"]["text"]

        try:
            os.kill(scan_pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError(
                "cancelled NetSniper process still exists"
            )

        sys.path.insert(0, str(REPO))
        import deltaaegis

        connection = deltaaegis.connect(db_path)
        try:
            row = connection.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            assert row is not None
            persisted = deltaaegis.scan_job_to_dict(row)
            assert persisted["status"] == "CANCELLED"

            audit = connection.execute(
                """
                SELECT *
                FROM access_audit_log
                WHERE action = 'NETSNIPER_SCAN_CANCEL_REQUEST'
                  AND target_type = 'scan_job'
                  AND target_key = ?
                ORDER BY audit_id DESC
                LIMIT 1
                """,
                (job_id,),
            ).fetchone()
            assert audit is not None
            details = json.loads(audit["detail_json"])
            assert details["reason"] == "dashboard cancellation smoke"
            assert details["cancellation_action"] == "requested"
        finally:
            connection.close()

        print("PASS: dashboard cancellation controls served")
        print("PASS: real HTTP scan start")
        print("PASS: live slow NetSniper process")
        print("PASS: authenticated HTTP cancellation request")
        print("PASS: worker-owned process-group termination")
        print("PASS: terminal CANCELLED detail visibility")
        print("PASS: cancellation metadata persistence")
        print("PASS: cancelled log evidence preservation")
        print("PASS: cancellation access-audit evidence")
        print("PASS: no completed phase-two output")

    finally:
        if scan_pid is not None:
            try:
                os.killpg(scan_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        stop_process_group(process)
        log_handle.close()
