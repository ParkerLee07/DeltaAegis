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

[[ -d "$NETSNIPER_RUN_DIR" ]] || fail "NetSniper run directory missing: $NETSNIPER_RUN_DIR"

for needle in \
    'def dashboard_operator_users_shell_html' \
    'route == "/operator/users"' \
    'required_role="ADMIN"'
do
    grep -Fq -- "$needle" deltaaegis.py || fail "missing v0.26 operator users page source marker: $needle"
done

python3 - <<'PYHTML'
import deltaaegis as da

html = da.dashboard_operator_users_shell_html()

for needle in [
    'fetch("/api/admin/users"',
    "operator-users-body",
    "User Management",
]:
    assert needle in html, f"missing rendered v0.26 operator users page marker: {needle}"

print("[PASS] rendered v0.26 operator users page markers validated")
PYHTML

python3 - <<'PY'
import contextlib
import http.client
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode

import deltaaegis as da


@contextlib.contextmanager
def deltaaegis_test_db(db_path: Path):
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    finally:
        connection.close()


def free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(port: int, method: str, path: str, body: str | None = None, cookie: str | None = None):
    headers = {}
    if cookie:
        headers["Cookie"] = cookie
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(body.encode("utf-8")))

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        data = response.read().decode("utf-8", "replace")
        response_headers = {k.lower(): v for k, v in response.getheaders()}
        conn.close()
        return response.status, response_headers, data
    except Exception as exc:
        try:
            conn.close()
        except Exception:
            pass
        raise AssertionError(f"HTTP request failed during {method} {path}: {exc!r}") from exc


def wait_for_dashboard(port: int) -> None:
    deadline = time.time() + 12
    while time.time() < deadline:
        try:
            status, _, _ = request(port, "GET", "/login")
            if status in {200, 302, 401, 403}:
                return
        except (OSError, AssertionError):
            time.sleep(0.2)
    raise AssertionError("dashboard did not start")


def login(port: int, username: str, password: str) -> str:
    body = urlencode({"username": username, "password": password})
    status, headers, data = request(port, "POST", "/login", body=body)
    assert status in {302, 303}, (status, headers, data)
    cookie = headers.get("set-cookie", "").split(";", 1)[0]
    assert cookie.startswith("deltaaegis_session=ds_"), (status, headers, data)
    return cookie


forbidden_page_markers = [
    "password_hash",
    "token_hash",
    "session_token_hash",
    "pbkdf2_sha256",
]

with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "deltaaegis-v026-users-page.db"

    with deltaaegis_test_db(db_path) as connection:
        da.create_access_user(
            connection,
            "page.admin",
            display_name="Page Admin",
            role="ADMIN",
            password="admin-password",
        )
        da.create_access_user(
            connection,
            "page.analyst",
            display_name="Page Analyst",
            role="ANALYST",
            password="analyst-password",
        )
        connection.commit()

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
            "--require-login",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        wait_for_dashboard(port)

        status, headers, body = request(port, "GET", "/operator/users")
        assert status in {302, 401, 403}, (status, body)

        analyst_cookie = login(port, "page.analyst", "analyst-password")
        status, headers, body = request(port, "GET", "/operator/users", cookie=analyst_cookie)
        assert status in {401, 403}, (status, body)

        admin_cookie = login(port, "page.admin", "admin-password")
        status, headers, body = request(port, "GET", "/operator/users", cookie=admin_cookie)
        assert status == 200, (status, body)
        assert "DeltaAegis User Management" in body, body
        assert 'fetch("/api/admin/users"' in body, body
        assert "operator-users-body" in body, body
        assert (
            "State-changing user actions are intentionally not available" in body
            or "State-changing user actions require ADMIN access" in body
        ), body

        lowered = body.lower()
        for marker in forbidden_page_markers:
            assert marker not in lowered, f"unsafe marker leaked in page HTML: {marker}"

        status, headers, body = request(port, "GET", "/api/admin/users", cookie=admin_cookie)
        assert status == 200, (status, body)
        payload = json.loads(body)
        assert payload["count"] == 2, payload
        assert {user["username"] for user in payload["users"]} == {
            "page.admin",
            "page.analyst",
        }, payload

    finally:
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=5)
        if process.returncode not in {0, -15}:
            print("----- dashboard process output -----")
            print(output)
            print("----- end dashboard process output -----")

print("[PASS] synthetic v0.26 operator users page validated")
PY

./tools/validate_v0_26_admin_users_api.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.26 admin users API compatibility gate failed"

pass "DeltaAegis v0.26 operator users page validation passed"
