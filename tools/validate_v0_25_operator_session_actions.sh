#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

NETSNIPER_RUN_DIR="${1:-/home/parker/NetSniper/runs/20260623-123007}"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

for needle in \
    'def dashboard_operator_session_shell_html_base_v025_actions' \
    'operator-refresh-session' \
    'operator-copy-session-json' \
    'operator-session-json-output' \
    'navigator.clipboard.writeText' \
    'Copy /api/session JSON' \
    'Refresh session'
do
    grep -Fq -- "$needle" deltaaegis.py || fail "missing v0.25 operator session action marker: $needle"
done

python3 - <<'PY2'
from pathlib import Path
import http.client
import socket
import subprocess
import sys
import tempfile
import time

import deltaaegis as da


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(port: int, method: str, path: str, body: str | None = None, cookie: str | None = None):
    headers = {}

    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(body.encode("utf-8")))

    if cookie:
        headers["Cookie"] = cookie

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)

    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        data = response.read().decode("utf-8", errors="replace")
        headers_out = {key.lower(): value for key, value in response.getheaders()}
        return response.status, headers_out, data
    finally:
        conn.close()


with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "deltaaegis-v025-operator-actions.db"

    with da.connect(db_path) as connection:
        da.create_access_user(
            connection,
            "actions.operator",
            role="ADMIN",
            password="actions-password",
            display_name="Actions Operator",
        )

    port = free_port()
    proc = subprocess.Popen(
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
            "--quiet",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        for _ in range(50):
            try:
                status, headers, body = request(port, "GET", "/healthz")
                if status == 200:
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("dashboard did not start")

        status, headers, body = request(
            port,
            "POST",
            "/login",
            body="username=actions.operator&password=actions-password",
        )
        assert status == 303, (status, headers, body)
        session_cookie = headers.get("set-cookie", "").split(";", 1)[0]

        status, headers, body = request(port, "GET", "/operator", cookie=session_cookie)
        assert status == 200, (status, headers, body)
        assert "Operator Session" in body, body
        assert "operator-refresh-session" in body, body
        assert "operator-copy-session-json" in body, body
        assert "operator-session-json-output" in body, body
        assert "navigator.clipboard.writeText" in body, body

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

print("[PASS] synthetic v0.25 operator session actions validated")
PY2

./tools/validate_v0_25_dashboard_operator_link.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.25 dashboard operator link validation failed"

pass "DeltaAegis v0.25 operator session actions validation passed"
