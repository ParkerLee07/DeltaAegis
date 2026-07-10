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
    'def dashboard_admin_users_payload' \
    'route == "/api/admin/users"' \
    'require_permission("admin.users.read")' \
    '"password_configured"' \
    '"active_token_count"' \
    '"last_token_used_at"'
do
    grep -Fq -- "$needle" deltaaegis.py || fail "missing v0.26 admin users API marker: $needle"
done

python3 - <<'PY'
import contextlib
import http.client
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

import deltaaegis as da


def free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(port: int, path: str, token: str | None = None):
    headers = {}
    if token:
        headers["X-DeltaAegis-Token"] = token

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path, headers=headers)
    response = conn.getresponse()
    body = response.read().decode("utf-8", "replace")
    conn.close()
    return response.status, body


def wait_for_dashboard(port: int) -> None:
    deadline = time.time() + 12
    while time.time() < deadline:
        try:
            status, _ = request(port, "/api/session")
            if status in {200, 401, 403}:
                return
        except OSError:
            time.sleep(0.2)
    raise AssertionError("dashboard did not start")



@contextlib.contextmanager
def deltaaegis_test_db(db_path: Path):
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    finally:
        connection.close()

forbidden_response_markers = [
    "password_hash",
    "token_hash",
    "session_token",
    "session_token_hash",
    "cookie",
    "secret",
    "da_",
    "pbkdf2_sha256",
]

with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "deltaaegis-v026-admin-users.db"

    with deltaaegis_test_db(db_path) as connection:
        admin = da.create_access_user(
            connection,
            "admin.user",
            display_name="Admin User",
            role="ADMIN",
            password="admin-password",
        )
        analyst = da.create_access_user(
            connection,
            "analyst.user",
            display_name="Analyst User",
            role="ANALYST",
            password="analyst-password",
        )
        viewer = da.create_access_user(
            connection,
            "viewer.user",
            display_name="Viewer User",
            role="VIEWER",
            password="viewer-password",
        )

        admin_token = da.create_access_api_token(
            connection,
            admin["user_id"],
            token_name="admin validator token",
            role="ADMIN",
        )["token"]

        analyst_token = da.create_access_api_token(
            connection,
            analyst["user_id"],
            token_name="analyst validator token",
            role="ANALYST",
        )["token"]

        viewer_token = da.create_access_api_token(
            connection,
            viewer["user_id"],
            token_name="viewer validator token",
            role="VIEWER",
        )["token"]

        connection.commit()

        payload = da.dashboard_admin_users_payload(connection)
        assert payload["count"] == 3, payload
        assert payload["enabled_count"] == 3, payload
        assert payload["role_counts"]["ADMIN"] == 1, payload
        assert payload["role_counts"]["ANALYST"] == 1, payload
        assert payload["role_counts"]["VIEWER"] == 1, payload

        usernames = {user["username"] for user in payload["users"]}
        assert usernames == {"admin.user", "analyst.user", "viewer.user"}, payload

        encoded = json.dumps(payload).lower()
        for marker in forbidden_response_markers:
            assert marker not in encoded, f"unsafe marker leaked in direct payload: {marker}"

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
            "--token",
            "legacy-validator-token",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        wait_for_dashboard(port)

        status, body = request(port, "/api/admin/users")
        assert status in {401, 403}, (status, body)

        status, body = request(port, "/api/admin/users", token=viewer_token)
        assert status in {401, 403}, (status, body)

        status, body = request(port, "/api/admin/users", token=analyst_token)
        assert status in {401, 403}, (status, body)

        status, body = request(port, "/api/admin/users", token=admin_token)
        assert status == 200, (status, body)

        payload = json.loads(body)
        assert payload["count"] == 3, payload
        assert {user["username"] for user in payload["users"]} == {
            "admin.user",
            "analyst.user",
            "viewer.user",
        }, payload

        encoded = json.dumps(payload).lower()
        for marker in forbidden_response_markers:
            assert marker not in encoded, f"unsafe marker leaked in HTTP payload: {marker}"

        admin_row = next(user for user in payload["users"] if user["username"] == "admin.user")
        assert admin_row["role"] == "ADMIN", admin_row
        assert admin_row["enabled"] is True, admin_row
        assert admin_row["password_configured"] is True, admin_row
        assert admin_row["active_token_count"] >= 1, admin_row

    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

print("[PASS] synthetic v0.26 admin users API validated")
PY

for inherited_validator in \
    tools/validate_v0_25_operator_session_page.sh \
    tools/validate_v0_25_operator_session_actions.sh \
    tools/validate_v0_25_backward_compatibility.sh
do
    if [[ -x "$inherited_validator" ]]; then
        "$inherited_validator" "$NETSNIPER_RUN_DIR" \
            || fail "inherited v0.25 compatibility gate failed: $inherited_validator"
    fi
done


pass "DeltaAegis v0.26 admin users API validation passed"
