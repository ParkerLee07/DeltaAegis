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

python3 - <<'PYHTML'
import deltaaegis as da

html = da.dashboard_operator_users_shell_html()

for needle in [
    "operator-create-user-form",
    "operator-create-username",
    "operator-create-password",
    "operator-users-refresh",
    'data-action="role"',
    'data-action="password"',
    'data-action="${toggleAction}"',
    'adminPost("/api/admin/users"',
    '/api/admin/users/${encodeURIComponent(username)}/role',
    '/api/admin/users/${encodeURIComponent(username)}/password',
    '/api/admin/users/${encodeURIComponent(username)}/${action}',
    "State-changing user actions require ADMIN access",
]:
    assert needle in html, f"missing v0.26 operator user action control marker: {needle}"

print("[PASS] rendered v0.26 operator user action controls markers validated")
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


def request(
    port: int,
    method: str,
    path: str,
    body: str | None = None,
    cookie: str | None = None,
    json_payload: dict | None = None,
):
    headers = {}

    if cookie:
        headers["Cookie"] = cookie

    if json_payload is not None:
        body = json.dumps(json_payload)
        headers["Content-Type"] = "application/json"

    if body is not None:
        headers["Content-Length"] = str(len(body.encode("utf-8")))

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    data = response.read().decode("utf-8", "replace")
    response_headers = {k.lower(): v for k, v in response.getheaders()}
    conn.close()
    return response.status, response_headers, data


def wait_for_dashboard(port: int) -> None:
    deadline = time.time() + 12
    while time.time() < deadline:
        try:
            status, _, _ = request(port, "GET", "/login")
            if status in {200, 302, 401, 403}:
                return
        except OSError:
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
    db_path = Path(tmpdir) / "deltaaegis-v026-user-action-controls.db"

    with deltaaegis_test_db(db_path) as connection:
        da.create_access_user(
            connection,
            "ui.admin",
            display_name="UI Admin",
            role="ADMIN",
            password="admin-password",
        )
        da.create_access_user(
            connection,
            "ui.analyst",
            display_name="UI Analyst",
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

        analyst_cookie = login(port, "ui.analyst", "analyst-password")
        status, headers, body = request(
            port,
            "POST",
            "/api/admin/users",
            cookie=analyst_cookie,
            json_payload={
                "username": "ui.denied",
                "display_name": "UI Denied",
                "role": "VIEWER",
                "password": "denied-password",
            },
        )
        assert status in {401, 403}, (status, body)

        admin_cookie = login(port, "ui.admin", "admin-password")

        status, headers, body = request(port, "GET", "/operator/users", cookie=admin_cookie)
        assert status == 200, (status, body)
        assert "operator-create-user-form" in body, body
        assert "operator-create-password" in body, body
        assert 'data-action="role"' in body, body
        assert 'data-action="password"' in body, body
        assert 'data-action="${toggleAction}"' in body, body
        assert "Passwords are never displayed after submission" in body, body

        lowered = body.lower()
        for marker in forbidden_page_markers:
            assert marker not in lowered, f"unsafe marker leaked in page HTML: {marker}"

        status, headers, body = request(
            port,
            "POST",
            "/api/admin/users",
            cookie=admin_cookie,
            json_payload={
                "username": "ui.created",
                "display_name": "UI Created",
                "role": "VIEWER",
                "password": "created-password",
            },
        )
        assert status == 200, (status, body)
        payload = json.loads(body)
        assert payload["ok"] is True, payload
        assert payload["target_username"] == "ui.created", payload

        status, headers, body = request(
            port,
            "POST",
            "/api/admin/users/ui.created/role",
            cookie=admin_cookie,
            json_payload={"role": "ANALYST"},
        )
        assert status == 200, (status, body)

        status, headers, body = request(
            port,
            "POST",
            "/api/admin/users/ui.created/password",
            cookie=admin_cookie,
            json_payload={"password": "rotated-password"},
        )
        assert status == 200, (status, body)

        status, headers, body = request(
            port,
            "POST",
            "/api/admin/users/ui.created/disable",
            cookie=admin_cookie,
            json_payload={},
        )
        assert status == 200, (status, body)

        status, headers, body = request(
            port,
            "POST",
            "/api/admin/users/ui.created/enable",
            cookie=admin_cookie,
            json_payload={},
        )
        assert status == 200, (status, body)

        with deltaaegis_test_db(db_path) as connection:
            user = da.access_user_by_username(connection, "ui.created")
            assert user is not None
            assert user["role"] == "ANALYST", dict(user)
            assert int(user["is_active"]) == 1, dict(user)
            assert da.verify_access_password("rotated-password", user["password_hash"]) is True

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

print("[PASS] synthetic v0.26 operator user action controls validated")
PY

./tools/validate_v0_26_admin_user_actions.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.26 admin user actions compatibility gate failed"

pass "DeltaAegis v0.26 operator user action controls validation passed"
