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
REQUIRED_BACKEND_COMMIT = "5f61d99"
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


def http_json(
    url: str,
    *,
    token: str | None = None,
    method: str = "GET",
    payload: Any = None,
    raw_body: bytes | None = None,
    content_type: str = "application/json",
    timeout: float = 5.0,
) -> tuple[int, dict[str, Any]]:
    headers = {"Accept": "application/json"}

    if token:
        headers["X-DeltaAegis-Token"] = token

    data = raw_body

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    if data is not None:
        headers["Content-Type"] = content_type

    request = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(response.status)
            body = response.read()
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        body = exc.read()

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
        f"ERROR: expected branch {EXPECTED_BRANCH!r}, found {branch!r}"
    )

ancestor = subprocess.run(
    [
        "git",
        "merge-base",
        "--is-ancestor",
        REQUIRED_BACKEND_COMMIT,
        "HEAD",
    ],
    cwd=REPO,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

if ancestor.returncode != 0:
    raise SystemExit(
        "ERROR: required cancellation backend commit "
        f"{REQUIRED_BACKEND_COMMIT} is not an ancestor of HEAD"
    )

source = SOURCE.read_text(encoding="utf-8")

assert '("POST", "/api/netsniper/scan-cancel", "scan.start")' in source
assert "def dashboard_netsniper_scan_cancel_payload(" in source
assert 'action="NETSNIPER_SCAN_CANCEL_REQUEST"' in source
assert 'if route == "/api/netsniper/scan-cancel":' in source

route_start = source.index(
    '            if route == "/api/netsniper/scan-cancel":'
)
route_end = source.index(
    '            if route == "/api/netsniper/scan-start":',
    route_start,
)
route_text = source[route_start:route_end]

for forbidden in (
    "process_pid",
    "os.kill",
    "os.killpg",
    "signal.SIGTERM",
    "signal.SIGKILL",
):
    assert forbidden not in route_text, forbidden

with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v039-cancel-api-"
) as temp_dir:
    temp = Path(temp_dir)
    db_path = temp / "deltaaegis.db"
    events_path = temp / "events.jsonl"
    dashboard_log = temp / "dashboard.log"
    runner = temp / "dashboard_runner.py"
    token = "deltaaegis-v039-cancel-api-token"
    port = reserve_local_port()
    base_url = f"http://127.0.0.1:{port}"

    sys.path.insert(0, str(REPO))
    import deltaaegis

    connection = deltaaegis.connect(db_path)

    queued = deltaaegis.create_scan_job(
        connection,
        "192.168.90.0/24",
        temp / "queued.sh",
        temp / "runs",
    )

    running = deltaaegis.create_scan_job(
        connection,
        "192.168.91.0/24",
        temp / "running.sh",
        temp / "runs",
    )
    deltaaegis.update_scan_job(
        connection,
        running["job_id"],
        status="RUNNING",
        started_at=deltaaegis.utc_now_text(),
        heartbeat_at=deltaaegis.utc_now_text(),
        process_pid=999999,
    )

    completed = deltaaegis.create_scan_job(
        connection,
        "192.168.92.0/24",
        temp / "completed.sh",
        temp / "runs",
    )
    deltaaegis.update_scan_job(
        connection,
        completed["job_id"],
        status="COMPLETED",
        finished_at=deltaaegis.utc_now_text(),
        exit_code=0,
    )
    connection.commit()
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
                with urllib.request.urlopen(
                    f"{base_url}/healthz",
                    timeout=1.0,
                ) as response:
                    if response.read().decode("utf-8").strip() == "ok":
                        ready = True
                        break
            except (OSError, urllib.error.URLError):
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

        status, payload = http_json(
            f"{base_url}/api/netsniper/scan-cancel",
            method="POST",
            payload={
                "job_id": queued["job_id"],
                "reason": "queued API cancellation",
            },
        )
        assert status == 401
        assert payload.get("error") == "unauthorized"

        status, payload = http_json(
            f"{base_url}/api/netsniper/scan-cancel",
            token=token,
            method="POST",
            raw_body=b"{not-json",
        )
        assert status == 400
        assert payload.get("ok") is False

        status, payload = http_json(
            f"{base_url}/api/netsniper/scan-cancel",
            token=token,
            method="POST",
            payload={
                "job_id": queued["job_id"],
                "reason": "queued API cancellation",
                "requested_by": "caller-controlled",
                "process_pid": 1,
            },
        )
        assert status == 200
        assert payload.get("ok") is True
        assert payload["cancellation_action"] == "cancelled_before_start"
        assert payload["job"]["status"] == "CANCELLED"
        assert payload["job"]["cancel_requested_by"] == "dashboard"
        assert payload["job"]["cancel_requested_by"] != "caller-controlled"
        assert payload["job"]["cancel_reason"] == "queued API cancellation"

        status, repeated = http_json(
            f"{base_url}/api/netsniper/scan-cancel",
            token=token,
            method="POST",
            payload={
                "job_id": queued["job_id"],
                "reason": "must not overwrite",
            },
        )
        assert status == 200
        assert repeated["cancellation_action"] == "already_cancelled"
        assert repeated["job"]["cancel_reason"] == "queued API cancellation"

        status, running_payload = http_json(
            f"{base_url}/api/netsniper/scan-cancel",
            token=token,
            method="POST",
            payload={
                "job_id": running["job_id"],
                "reason": "running API cancellation",
            },
        )
        assert status == 200
        assert running_payload["cancellation_action"] == "requested"
        assert running_payload["job"]["status"] == "RUNNING"
        assert running_payload["job"]["cancel_requested_at"]
        assert running_payload["job"]["cancel_requested_by"] == "dashboard"

        status, missing = http_json(
            f"{base_url}/api/netsniper/scan-cancel",
            token=token,
            method="POST",
            payload={
                "job_id": "scan-missing-api-validator",
                "reason": "missing",
            },
        )
        assert status == 404
        assert missing.get("ok") is False

        status, terminal = http_json(
            f"{base_url}/api/netsniper/scan-cancel",
            token=token,
            method="POST",
            payload={
                "job_id": completed["job_id"],
                "reason": "too late",
            },
        )
        assert status == 400
        assert terminal.get("ok") is False

        connection = deltaaegis.connect(db_path)
        try:
            queued_row = connection.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (queued["job_id"],),
            ).fetchone()
            running_row = connection.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (running["job_id"],),
            ).fetchone()

            queued_job = deltaaegis.scan_job_to_dict(queued_row)
            running_job = deltaaegis.scan_job_to_dict(running_row)

            assert queued_job["status"] == "CANCELLED"
            assert queued_job["cancel_requested_by"] == "dashboard"
            assert running_job["status"] == "RUNNING"
            assert running_job["cancel_requested_at"]
            assert running_job["cancel_requested_by"] == "dashboard"

            audit_rows = connection.execute(
                "SELECT actor_username, actor_role, action, "
                "target_type, target_key, detail_json "
                "FROM access_audit_log "
                "WHERE action = 'NETSNIPER_SCAN_CANCEL_REQUEST' "
                "ORDER BY audit_id"
            ).fetchall()

            assert len(audit_rows) == 3

            targets = [row["target_key"] for row in audit_rows]
            assert targets.count(queued["job_id"]) == 2
            assert targets.count(running["job_id"]) == 1

            for row in audit_rows:
                assert row["actor_username"] == "dashboard"
                assert row["actor_role"] == "ADMIN"
                assert row["target_type"] == "scan_job"
                details = json.loads(row["detail_json"])
                assert details["requested_by"] == "dashboard"
                assert details["cancellation_action"] in {
                    "cancelled_before_start",
                    "already_cancelled",
                    "requested",
                }
        finally:
            connection.close()

        print("PASS: scan.start RBAC route policy")
        print("PASS: unauthenticated cancellation rejection")
        print("PASS: malformed JSON rejection")
        print("PASS: authenticated queued cancellation")
        print("PASS: authenticated running cancellation request")
        print("PASS: server-derived requester identity")
        print("PASS: caller PID and requester fields ignored")
        print("PASS: repeated cancellation idempotence")
        print("PASS: missing job returns 404")
        print("PASS: terminal job cancellation returns 400")
        print("PASS: cancellation access-audit evidence")
        print("PASS: no direct HTTP process signaling")

    finally:
        stop_process_group(process)
        log_handle.close()
