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
    'def dashboard_login_html' \
    'def dashboard_has_active_password_users' \
    'def dashboard_session_cookie_header' \
    'def dashboard_clear_session_cookie_header' \
    'def dashboard_redirect_response' \
    'def command_user_password' \
    'ACCESS_USER_PASSWORD_SET' \
    'route == "/login"' \
    'route == "/logout"' \
    'dashboard_user_login(' \
    'authenticate_dashboard_session(' \
    'username/password login required' \
    '--require-login'
do
    grep -q -- "$needle" deltaaegis.py || fail "missing v0.24 login/logout marker: $needle"
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
    db_path = Path(tmpdir) / "deltaaegis-login-routes.db"

    with da.connect(db_path) as connection:
        da.create_access_user(
            connection,
            "web.admin",
            role="ADMIN",
            password="web-login-password",
            display_name="Web Admin",
        )
        assert da.dashboard_has_active_password_users(connection) is True

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

        status, headers, body = request(port, "GET", "/")
        assert status == 303, (status, headers, body)
        assert headers.get("location") == "/login", headers

        status, headers, body = request(port, "GET", "/login")
        assert status == 200, (status, headers, body)
        assert "Operator Login" in body, body

        status, headers, body = request(port, "GET", "/api/scopes")
        assert status == 401, (status, headers, body)

        bad_body = "username=web.admin&password=bad-password"
        status, headers, body = request(port, "POST", "/login", body=bad_body)
        assert status == 200, (status, headers, body)
        assert "Invalid username or password" in body, body

        good_body = "username=web.admin&password=web-login-password"
        status, headers, body = request(port, "POST", "/login", body=good_body)
        assert status == 303, (status, headers, body)
        assert headers.get("location") == "/", headers
        set_cookie = headers.get("set-cookie", "")
        assert "deltaaegis_session=ds_" in set_cookie, set_cookie
        assert "HttpOnly" in set_cookie, set_cookie
        assert "SameSite=Lax" in set_cookie, set_cookie

        session_cookie = set_cookie.split(";", 1)[0]

        status, headers, body = request(port, "GET", "/api/scopes", cookie=session_cookie)
        assert status == 200, (status, headers, body)

        status, headers, body = request(port, "GET", "/logout", cookie=session_cookie)
        assert status == 303, (status, headers, body)
        assert headers.get("location") == "/login", headers
        assert "Max-Age=0" in headers.get("set-cookie", ""), headers

        status, headers, body = request(port, "GET", "/api/scopes", cookie=session_cookie)
        assert status == 401, (status, headers, body)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

print("[PASS] synthetic v0.24 login/logout routes validated")
PY2

pass "DeltaAegis v0.24 login/logout route validation passed"
