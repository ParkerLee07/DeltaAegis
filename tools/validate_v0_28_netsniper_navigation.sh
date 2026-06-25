#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py || fail "deltaaegis.py does not compile"

grep -q 'def dashboard_inject_netsniper_navigation' deltaaegis.py \
    || fail "missing dashboard_inject_netsniper_navigation"

grep -q 'dashboard_inject_netsniper_navigation(body)' deltaaegis.py \
    || fail "dashboard_html_response does not call NetSniper navigation injector"

grep -q 'id="deltaaegis-netsniper-dashboard-link"' deltaaegis.py \
    || fail "missing NetSniper dashboard link id"

grep -q 'href="/netsniper"' deltaaegis.py \
    || fail "missing /netsniper dashboard link"

python3 - <<'PY'
import contextlib
import http.client
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

        status, headers, body = request(port, "GET", "/")
        assert status == 200, (status, headers, body[:400])
        assert 'id="deltaaegis-netsniper-dashboard-link"' in body, body[:2000]
        assert 'href="/netsniper"' in body, body[:2000]
        assert ">NetSniper<" in body, body[:2000]

        status, headers, body = request(port, "GET", "/netsniper")
        assert status == 200, (status, headers, body[:400])
        assert "DeltaAegis NetSniper" in body, body[:1000]
        assert 'id="deltaaegis-netsniper-dashboard-link"' not in body, "NetSniper page should not inject a duplicate self-link"

    finally:
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=5)

print("[PASS] dashboard NetSniper navigation link validated")
PY

pass "DeltaAegis v0.28 NetSniper navigation validation passed"
