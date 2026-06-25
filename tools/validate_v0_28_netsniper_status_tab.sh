#!/usr/bin/env bash
set -euo pipefail

NETSNIPER_RUN_DIR="${1:-/home/parker/NetSniper/runs/20260623-123007}"

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py || fail "deltaaegis.py does not compile"

grep -q 'def dashboard_netsniper_status_payload' deltaaegis.py \
    || fail "missing dashboard_netsniper_status_payload"

grep -q 'def render_netsniper_page' deltaaegis.py \
    || fail "missing render_netsniper_page"

grep -q '"/api/netsniper/status"' deltaaegis.py \
    || fail "missing /api/netsniper/status route"

grep -q '"/netsniper"' deltaaegis.py \
    || fail "missing /netsniper route"

grep -q 'Raw shell command execution is intentionally not exposed' deltaaegis.py \
    || fail "missing no-raw-shell design boundary note"

python3 - <<'PY'
import contextlib
import http.client
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(port, method, path):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path)
    response = conn.getresponse()
    data = response.read().decode("utf-8", "replace")
    headers = {k.lower(): v for k, v in response.getheaders()}
    conn.close()
    return response.status, headers, data


def wait_for_dashboard(port):
    deadline = time.time() + 12
    while time.time() < deadline:
        try:
            status, _, _ = request(port, "GET", "/healthz")
            if status == 200:
                return
        except OSError:
            time.sleep(0.2)
    raise AssertionError("dashboard did not start")


with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "deltaaegis.db"
    port = free_port()

    process = subprocess.Popen(
        [
            sys.executable,
            "deltaaegis.py",
            "--db",
            str(db_path),
            "dashboard",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--no-require-login",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        wait_for_dashboard(port)

        status, headers, body = request(port, "GET", "/netsniper")
        assert status == 200, (status, headers, body[:400])
        assert "DeltaAegis NetSniper" in body, body[:500]
        assert "/api/netsniper/status" in body, body[:500]
        assert "This tab does not run arbitrary shell commands" in body, body[:5000]

        status, headers, body = request(port, "GET", "/api/netsniper/status")
        assert status == 200, (status, headers, body[:400])
        payload = json.loads(body)

        required = [
            "netsniper_root",
            "netsniper_script",
            "netsniper_installed",
            "runs_dir",
            "runs_dir_exists",
            "latest_run",
            "latest_run_status",
            "latest_manifest_found",
            "import_ready",
            "notes",
        ]

        missing = [key for key in required if key not in payload]
        assert not missing, missing

        assert payload["netsniper_root"].endswith("/NetSniper"), payload
        assert payload["runs_dir"].endswith("/NetSniper/runs"), payload
        assert any("lightweight CLI" in note for note in payload["notes"]), payload["notes"]

    finally:
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=5)

print("[PASS] NetSniper dashboard status tab validated")
PY

pass "DeltaAegis v0.28 NetSniper status tab validation passed"
