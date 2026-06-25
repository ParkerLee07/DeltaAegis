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
    "Recent user-management audit events",
    "operator-users-audit-refresh",
    "operator-users-audit-status",
    "operator-users-audit-body",
    'fetch("/api/access-audit?limit=50"',
    "ACCESS_USER_DASHBOARD_",
    "loadOperatorUserAuditEvents",
    "safeAuditDetails",
]:
    assert needle in html, f"missing rendered v0.26 user audit visibility marker: {needle}"

for forbidden in [
    "password_hash",
    "token_hash",
    "session_token_hash",
    "pbkdf2_sha256",
]:
    assert forbidden not in html.lower(), f"unsafe marker leaked in rendered audit page: {forbidden}"

print("[PASS] rendered v0.26 user audit visibility markers validated")
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


def walk_dicts(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_dicts(child)


forbidden_payload_markers = [
    "password_hash",
    "token_hash",
    "session_token_hash",
    "pbkdf2_sha256",
    "rotated-password",
    "created-password",
]

with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "deltaaegis-v026-user-audit-visibility.db"

    with deltaaegis_test_db(db_path) as connection:
        da.create_access_user(
            connection,
            "audit.admin",
            display_name="Audit Admin",
            role="ADMIN",
            password="admin-password",
        )
        da.create_access_user(
            connection,
            "audit.viewer",
            display_name="Audit Viewer",
            role="VIEWER",
            password="viewer-password",
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

        viewer_cookie = login(port, "audit.viewer", "viewer-password")
        status, headers, body = request(
            port,
            "GET",
            "/operator/users",
            cookie=viewer_cookie,
        )
        assert status in {401, 403}, (status, body)

        admin_cookie = login(port, "audit.admin", "admin-password")

        status, headers, body = request(port, "GET", "/operator/users", cookie=admin_cookie)
        assert status == 200, (status, body)
        assert "operator-users-audit-body" in body, body
        assert "loadOperatorUserAuditEvents" in body, body
        assert "/api/access-audit?limit=50" in body, body

        status, headers, body = request(
            port,
            "POST",
            "/api/admin/users",
            cookie=admin_cookie,
            json_payload={
                "username": "audit.created",
                "display_name": "Audit Created",
                "role": "VIEWER",
                "password": "created-password",
            },
        )
        assert status == 200, (status, body)

        status, headers, body = request(
            port,
            "POST",
            "/api/admin/users/audit.created/password",
            cookie=admin_cookie,
            json_payload={"password": "rotated-password"},
        )
        assert status == 200, (status, body)

        status, headers, body = request(
            port,
            "GET",
            "/api/access-audit?limit=50",
            cookie=admin_cookie,
        )
        assert status == 200, (status, body)
        payload = json.loads(body)

        events = [
            item
            for item in walk_dicts(payload)
            if str(item.get("action", "")).startswith("ACCESS_USER_DASHBOARD_")
        ]

        actions = {event.get("action") for event in events}
        assert "ACCESS_USER_DASHBOARD_CREATE" in actions, actions
        assert "ACCESS_USER_DASHBOARD_PASSWORD_ROTATE" in actions, actions

        targets = {
            str(event.get("target_key") or event.get("target_username") or event.get("target") or "")
            for event in events
        }
        assert "audit.created" in targets, targets

        encoded = json.dumps(payload).lower()
        for marker in forbidden_payload_markers:
            assert marker not in encoded, f"unsafe marker leaked in audit payload: {marker}"

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

print("[PASS] synthetic v0.26 user audit visibility validated")
PY

./tools/validate_v0_26_operator_user_action_controls.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.26 operator user action controls compatibility gate failed"

pass "DeltaAegis v0.26 user audit visibility validation passed"
