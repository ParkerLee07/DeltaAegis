#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


EXPECTED_BRANCH = "feature/v0.39-job-lifecycle-observability"
EXPECTED_HEAD = "88726cf"
REPO = Path.home() / "DeltaAegis"
SOURCE = REPO / "deltaaegis.py"


def fail(message: str) -> None:
    raise AssertionError(message)


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
    payload: dict[str, Any] | None = None,
    timeout: float = 5.0,
) -> bytes:
    data = None
    headers = {
        "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
    }

    if token:
        headers["X-DeltaAegis-Token"] = token

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method=method,
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def request_json(
    url: str,
    *,
    token: str,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    body = request_bytes(
        url,
        token=token,
        method=method,
        payload=payload,
        timeout=timeout,
    )
    decoded = json.loads(body.decode("utf-8"))

    if not isinstance(decoded, dict):
        fail(f"expected JSON object from {url}")

    return decoded


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


def stop_active_scan_processes(db_path: Path) -> None:
    if not db_path.is_file():
        return

    connection = sqlite3.connect(db_path)

    try:
        rows = connection.execute(
            """
            SELECT process_pid
            FROM scan_jobs
            WHERE status IN ('QUEUED', 'RUNNING')
              AND process_pid IS NOT NULL
            """
        ).fetchall()
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()

    for row in rows:
        try:
            process_pid = int(row[0])
        except (TypeError, ValueError):
            continue

        if process_pid <= 0:
            continue

        try:
            os.killpg(process_pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
        except PermissionError:
            continue


if not SOURCE.is_file():
    raise SystemExit(f"ERROR: missing source file: {SOURCE}")

branch = git_output("branch", "--show-current")
if branch != EXPECTED_BRANCH:
    raise SystemExit(
        f"ERROR: expected branch {EXPECTED_BRANCH!r}, found {branch!r}"
    )

head = git_output("rev-parse", "--short", "HEAD")
if head != EXPECTED_HEAD:
    raise SystemExit(
        f"ERROR: expected HEAD {EXPECTED_HEAD}, found {head}"
    )

status_lines = [
    line
    for line in git_output("status", "--short").splitlines()
    if line.strip()
]

allowed_status_lines = {
    "?? tools/validate_v0_39_dashboard_http_smoke.py",
    "?? tools/validate_v0_39_dashboard_http_smoke.sh",
}

unexpected_status_lines = [
    line
    for line in status_lines
    if line not in allowed_status_lines
]

if unexpected_status_lines:
    raise SystemExit(
        "ERROR: unrelated working-tree changes are present before the "
        "HTTP smoke test:\n"
        + "\n".join(unexpected_status_lines)
    )


with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v039-dashboard-http-"
) as temp_dir:
    temp = Path(temp_dir)
    db_path = temp / "deltaaegis.db"
    events_path = temp / "events" / "events.jsonl"
    netsniper_root = temp / "NetSniper"
    netsniper_runs = netsniper_root / "runs"
    logs_dir = temp / "scan-logs"
    bundle_dir = netsniper_runs / "smoke-run"
    manifest_path = bundle_dir / "manifest.json"
    fake_netsniper = netsniper_root / "netsniper.sh"
    runner = temp / "dashboard_runner.py"
    dashboard_log = temp / "dashboard.log"
    token = "deltaaegis-v039-http-smoke-token"
    port = reserve_local_port()
    base_url = f"http://127.0.0.1:{port}"

    events_path.parent.mkdir(parents=True)
    netsniper_runs.mkdir(parents=True)
    logs_dir.mkdir(parents=True)

    fake_source = "\n".join(
        [
            "#!/usr/bin/env python3",
            "from pathlib import Path",
            "import json",
            "import sys",
            "import time",
            f"bundle_dir = Path({str(bundle_dir)!r})",
            f"manifest_path = Path({str(manifest_path)!r})",
            "print('scan phase one', flush=True)",
            "print('stderr phase one', file=sys.stderr, flush=True)",
            "time.sleep(7)",
            "bundle_dir.mkdir(parents=True, exist_ok=True)",
            "manifest_path.write_text('{}\\n', encoding='utf-8')",
            "print('scan phase two', flush=True)",
            "print('stderr phase two', file=sys.stderr, flush=True)",
            "print(json.dumps({",
            "    'status': 'COMPLETE',",
            "    'return_code': 0,",
            "    'scan_id': 'v039-dashboard-http-smoke',",
            "    'run_dir': str(bundle_dir),",
            "    'manifest_path': str(manifest_path),",
            "}), flush=True)",
        ]
    )
    fake_netsniper.write_text(fake_source + "\n", encoding="utf-8")
    fake_netsniper.chmod(0o755)

    runner_source = "\n".join(
        [
            "#!/usr/bin/env python3",
            "from pathlib import Path",
            "import argparse",
            "import sys",
            f"sys.path.insert(0, {str(REPO)!r})",
            "import deltaaegis",
            f"temp = Path({str(temp)!r})",
            f"db_path = Path({str(db_path)!r})",
            f"events_path = Path({str(events_path)!r})",
            f"netsniper_root = Path({str(netsniper_root)!r})",
            f"netsniper_runs = Path({str(netsniper_runs)!r})",
            f"logs_dir = Path({str(logs_dir)!r})",
            f"token = {token!r}",
            f"port = {port}",
            "deltaaegis.DEFAULT_SCAN_LOGS = logs_dir",
            "deltaaegis.dashboard_netsniper_root_path = lambda: netsniper_root",
            "deltaaegis.dashboard_netsniper_runs_dir = lambda: netsniper_runs",
            "deltaaegis.ingest_manifest = lambda connection, manifest, events: 'ACCEPTED'",
            "deltaaegis.scan_job_auto_ingest_evidence = lambda *args, **kwargs: {",
            "    'schema_version': 'deltaaegis-scan-auto-ingest-evidence-v1',",
            "    'requested': True,",
            "    'attempted': True,",
            "    'performed': True,",
            "    'accepted': True,",
            "    'quality_status': 'ACCEPTED',",
            "    'scan_id': 'v039-dashboard-http-smoke',",
            "    'manifest_path': str(netsniper_runs / 'smoke-run' / 'manifest.json'),",
            "    'network_scope': '192.168.250.0/24',",
            "    'result': 'ACCEPTED',",
            "}",
            "args = argparse.Namespace(",
            "    db=db_path,",
            "    events=events_path,",
            "    host='127.0.0.1',",
            "    port=port,",
            "    token=token,",
            "    scope=None,",
            "    quiet=True,",
            "    require_login=False,",
            "    enable_scheduled_scans=False,",
            "    schedule_worker_interval_seconds=60,",
            ")",
            "raise SystemExit(deltaaegis.command_dashboard(args))",
        ]
    )
    runner.write_text(runner_source + "\n", encoding="utf-8")
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
        health_ready = False
        health_deadline = time.monotonic() + 12.0

        while time.monotonic() < health_deadline:
            if process.poll() is not None:
                break

            try:
                body = request_bytes(
                    f"{base_url}/healthz",
                    timeout=1.0,
                )
                if body.decode("utf-8").strip() == "ok":
                    health_ready = True
                    break
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)

        if not health_ready:
            output = dashboard_log.read_text(
                encoding="utf-8",
                errors="replace",
            )
            fail(
                "dashboard did not become healthy on localhost\n"
                f"dashboard output:\n{output}"
            )

        page = request_bytes(
            f"{base_url}/netsniper",
            token=token,
        ).decode("utf-8", errors="replace")

        for fragment in (
            'id="netsniper-live-job-panel"',
            'id="netsniper-live-job-stdout"',
            'id="netsniper-live-job-stderr"',
            "async function loadNetSniperJobDetail(jobId)",
            "if (netSniperJobIsActive(payload.job)",
        ):
            if fragment not in page:
                fail(f"NetSniper page missing live-viewer marker: {fragment}")

        start_payload = request_json(
            f"{base_url}/api/netsniper/scan-start",
            token=token,
            method="POST",
            payload={
                "target": "192.168.250.0/24",
                "scan_profile": "balanced",
            },
        )

        if not start_payload.get("ok"):
            fail(f"scan-start response was not successful: {start_payload}")

        job_id = str(start_payload.get("job_id") or "").strip()
        if not job_id:
            fail("scan-start response did not include a job_id")

        detail_url = (
            f"{base_url}/api/netsniper/job-detail"
            f"?job_id={job_id}&tail_bytes=16384"
        )

        running_detail = None
        running_deadline = time.monotonic() + 5.0

        while time.monotonic() < running_deadline:
            detail = request_json(detail_url, token=token)
            job = detail.get("job") or {}
            stdout = detail.get("stdout") or {}
            stderr = detail.get("stderr") or {}

            if (
                detail.get("ok")
                and job.get("status") == "RUNNING"
                and job.get("process_pid")
                and job.get("heartbeat_at")
                and "scan phase one" in str(stdout.get("text") or "")
                and "stderr phase one" in str(stderr.get("text") or "")
            ):
                running_detail = detail
                break

            time.sleep(0.1)

        if running_detail is None:
            fail(
                "HTTP job-detail route did not expose RUNNING state, "
                "PID, heartbeat, and live log tails"
            )

        running_job = running_detail["job"]
        process_pid = int(running_job["process_pid"])
        initial_heartbeat = str(running_job["heartbeat_at"])

        heartbeat_advanced = False
        heartbeat_deadline = time.monotonic() + 7.0

        while time.monotonic() < heartbeat_deadline:
            detail = request_json(detail_url, token=token)
            job = detail.get("job") or {}

            if (
                job.get("status") == "RUNNING"
                and job.get("heartbeat_at")
                and str(job["heartbeat_at"]) != initial_heartbeat
            ):
                heartbeat_advanced = True
                break

            time.sleep(0.1)

        if not heartbeat_advanced:
            fail(
                "HTTP job-detail heartbeat did not advance while "
                "the fake scan remained RUNNING"
            )

        terminal_detail = None
        terminal_deadline = time.monotonic() + 15.0

        while time.monotonic() < terminal_deadline:
            detail = request_json(detail_url, token=token)
            job = detail.get("job") or {}

            if job.get("status") in {"COMPLETED", "FAILED"}:
                terminal_detail = detail
                break

            time.sleep(0.1)

        if terminal_detail is None:
            fail("scan job did not reach a terminal state through HTTP")

        terminal_job = terminal_detail["job"]
        terminal_stdout = terminal_detail.get("stdout") or {}
        terminal_stderr = terminal_detail.get("stderr") or {}

        if terminal_job.get("status") != "COMPLETED":
            fail(f"expected COMPLETED terminal job: {terminal_job}")

        if terminal_job.get("exit_code") != 0:
            fail(f"expected exit code 0: {terminal_job}")

        if int(terminal_job.get("process_pid") or 0) != process_pid:
            fail("terminal detail did not preserve the original process PID")

        if "scan phase two" not in str(terminal_stdout.get("text") or ""):
            fail("terminal stdout tail did not include scan phase two")

        if "stderr phase two" not in str(terminal_stderr.get("text") or ""):
            fail("terminal stderr tail did not include stderr phase two")

        ledger_body = request_bytes(
            f"{base_url}/api/scan-jobs?limit=10",
            token=token,
        )
        ledger = json.loads(ledger_body.decode("utf-8"))

        if isinstance(ledger, list):
            jobs = ledger
        elif isinstance(ledger, dict):
            jobs = (
                ledger.get("jobs")
                or ledger.get("scan_jobs")
                or ledger.get("items")
                or []
            )
        else:
            fail(
                "scan-job ledger returned unsupported JSON type: "
                f"{type(ledger).__name__}"
            )

        if not any(
            isinstance(item, dict)
            and item.get("job_id") == job_id
            and item.get("status") == "COMPLETED"
            for item in jobs
        ):
            fail("completed smoke-test job was not visible in scan-job ledger")

        stable_heartbeat = str(terminal_job.get("heartbeat_at") or "")
        time.sleep(3.5)
        stable_detail = request_json(detail_url, token=token)
        stable_job = stable_detail.get("job") or {}

        if stable_job.get("status") != "COMPLETED":
            fail("terminal job status changed unexpectedly")

        if str(stable_job.get("heartbeat_at") or "") != stable_heartbeat:
            fail("terminal heartbeat changed after process completion")

        print("PASS: localhost-only dashboard startup")
        print("PASS: token-authenticated NetSniper page")
        print("PASS: real HTTP scan-start route")
        print("PASS: asynchronous scan job creation")
        print("PASS: live HTTP stdout and stderr tails")
        print("PASS: PID and heartbeat HTTP visibility")
        print("PASS: heartbeat advancement while RUNNING")
        print("PASS: completed terminal lifecycle through HTTP")
        print("PASS: terminal heartbeat stability")
        print("PASS: scan-job ledger visibility")
        print("PASS: real NetSniper checkout remained untouched")

    finally:
        stop_active_scan_processes(db_path)
        stop_process_group(process)
        log_handle.close()
