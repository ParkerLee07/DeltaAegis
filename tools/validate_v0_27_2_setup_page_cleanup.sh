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

if grep -nE 'value="parker\.admin"|value="Parker Admin"|placeholder="parker\.admin"|placeholder="Parker Admin"' deltaaegis.py; then
    fail "first-admin setup page contains Parker-specific defaults"
fi

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
    db_path = Path(tmpdir) / "fresh.db"
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
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        wait_for_dashboard(port)

        status, headers, body = request(port, "GET", "/setup")
        assert status == 200, (status, headers, body[:300])
        assert "Create first admin" in body, body[:500]

        forbidden = [
            'value="parker.admin"',
            'value="Parker Admin"',
            'placeholder="parker.admin"',
            'placeholder="Parker Admin"',
            'id="deltaaegis-operator-floating-button"',
            ">Operator<",
        ]

        for item in forbidden:
            assert item not in body, item

        status, headers, body = request(port, "GET", "/login")
        assert status in {302, 303}, (status, headers, body[:300])
        assert headers.get("location") == "/setup", headers

    finally:
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=5)

print("[PASS] setup page has no user-specific defaults or operator button")
PY

if [[ -x "./tools/validate_v0_27_1_release.sh" ]]; then
    ./tools/validate_v0_27_1_release.sh "$NETSNIPER_RUN_DIR" \
        || fail "v0.27.1 release gate failed after setup page cleanup"
fi

pass "DeltaAegis v0.27.2 setup page cleanup validation passed"
