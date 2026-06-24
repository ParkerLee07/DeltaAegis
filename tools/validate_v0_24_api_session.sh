#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

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
    'def dashboard_session_payload' \
    'route == "/api/session"' \
    '"authenticated": True' \
    '"auth_type": actor.get("auth_type") or "dashboard_session"'
do
    grep -q -- "$needle" deltaaegis.py || fail "missing v0.24 /api/session marker: $needle"
done

python3 - <<'PY2'
from pathlib import Path
import http.client
import json
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
    db_path = Path(tmpdir) / "deltaaegis-api-session.db"

    with da.connect(db_path) as connection:
        da.create_access_user(
            connection,
            "session.api.admin",
            role="ADMIN",
            password="api-session-password",
            display_name="API Session Admin",
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

        status, headers, body = request(port, "GET", "/api/session")
        assert status == 401, (status, headers, body)

        status, headers, body = request(
            port,
            "POST",
            "/login",
            body="username=session.api.admin&password=api-session-password",
        )
        assert status == 303, (status, headers, body)
        session_cookie = headers.get("set-cookie", "").split(";", 1)[0]
        assert session_cookie.startswith("deltaaegis_session=ds_"), session_cookie

        status, headers, body = request(port, "GET", "/api/session", cookie=session_cookie)
        assert status == 200, (status, headers, body)
        payload = json.loads(body)

        assert payload["authenticated"] is True, payload
        assert payload["user"]["username"] == "session.api.admin", payload
        assert payload["user"]["display_name"] == "API Session Admin", payload
        assert payload["user"]["role"] == "ADMIN", payload
        assert payload["role"] == "ADMIN", payload
        assert payload["session_id"], payload
        assert payload["expires_at"], payload
        assert payload["auth_type"] == "dashboard_session", payload

        status, headers, body = request(port, "GET", "/logout", cookie=session_cookie)
        assert status == 303, (status, headers, body)

        status, headers, body = request(port, "GET", "/api/session", cookie=session_cookie)
        assert status == 401, (status, headers, body)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

print("[PASS] synthetic v0.24 /api/session validated")
PY2

pass "DeltaAegis v0.24 /api/session validation passed"
