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
    'def dashboard_admin_handle_user_action' \
    'def dashboard_admin_create_user' \
    'def dashboard_admin_set_user_enabled' \
    'def dashboard_admin_set_user_role' \
    'def dashboard_admin_rotate_user_password' \
    'cannot disable the last active ADMIN user' \
    'ACCESS_USER_DASHBOARD_CREATE' \
    'ACCESS_USER_DASHBOARD_DISABLE' \
    'ACCESS_USER_DASHBOARD_ENABLE' \
    'ACCESS_USER_DASHBOARD_ROLE_CHANGE' \
    'ACCESS_USER_DASHBOARD_PASSWORD_ROTATE'
do
    grep -Fq -- "$needle" deltaaegis.py || fail "missing v0.26 admin user action marker: $needle"
done

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


def request(port: int, method: str, path: str, token: str | None = None, payload: dict | None = None):
    headers = {}
    body = None

    if token:
        headers["X-DeltaAegis-Token"] = token

    if payload is not None:
        body = json.dumps(payload)
        headers["Content-Type"] = "application/json"
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
            status, _, _ = request(port, "GET", "/api/session")
            if status in {200, 401, 403}:
                return
        except (OSError, AssertionError):
            time.sleep(0.2)
    raise AssertionError("dashboard did not start")


def as_json(body: str) -> dict:
    return json.loads(body)


forbidden_markers = [
    "password_hash",
    "token_hash",
    "session_token_hash",
    "pbkdf2_sha256",
]

with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "deltaaegis-v026-admin-actions.db"

    with deltaaegis_test_db(db_path) as connection:
        admin = da.create_access_user(
            connection,
            "actions.admin",
            display_name="Actions Admin",
            role="ADMIN",
            password="admin-password",
        )
        second_admin = da.create_access_user(
            connection,
            "backup.admin",
            display_name="Backup Admin",
            role="ADMIN",
            password="backup-password",
        )
        analyst = da.create_access_user(
            connection,
            "actions.analyst",
            display_name="Actions Analyst",
            role="ANALYST",
            password="analyst-password",
        )
        admin_token = da.create_access_api_token(
            connection,
            admin["user_id"],
            token_name="admin actions token",
            role="ADMIN",
        )["token"]
        backup_admin_token = da.create_access_api_token(
            connection,
            second_admin["user_id"],
            token_name="backup admin actions token",
            role="ADMIN",
        )["token"]
        analyst_token = da.create_access_api_token(
            connection,
            analyst["user_id"],
            token_name="analyst actions token",
            role="ANALYST",
        )["token"]
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
            "--token",
            "legacy-validator-token",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        wait_for_dashboard(port)

        status, _, body = request(
            port,
            "POST",
            "/api/admin/users",
            token=analyst_token,
            payload={
                "username": "denied.user",
                "display_name": "Denied User",
                "role": "VIEWER",
                "password": "denied-password",
            },
        )
        assert status in {401, 403}, (status, body)

        status, _, body = request(
            port,
            "POST",
            "/api/admin/users",
            token=admin_token,
            payload={
                "username": "created.user",
                "display_name": "Created User",
                "role": "VIEWER",
                "password": "created-password",
            },
        )
        assert status == 200, (status, body)
        payload = as_json(body)
        assert payload["ok"] is True, payload
        assert payload["action"] == "create", payload
        assert payload["target_username"] == "created.user", payload

        encoded = json.dumps(payload).lower()
        for marker in forbidden_markers:
            assert marker not in encoded, f"secret marker leaked after create: {marker}"

        status, _, body = request(
            port,
            "POST",
            "/api/admin/users/created.user/role",
            token=admin_token,
            payload={"role": "ANALYST"},
        )
        assert status == 200, (status, body)
        payload = as_json(body)
        assert payload["action"] == "role", payload
        updated_user = next(
            user for user in payload["access"]["users"]
            if user["username"] == "created.user"
        )
        assert updated_user["role"] == "ANALYST", updated_user

        status, _, body = request(
            port,
            "POST",
            "/api/admin/users/created.user/password",
            token=admin_token,
            payload={"password": "rotated-password"},
        )
        assert status == 200, (status, body)
        payload = as_json(body)
        assert payload["action"] == "password", payload

        status, _, body = request(
            port,
            "POST",
            "/api/admin/users/created.user/disable",
            token=admin_token,
            payload={},
        )
        assert status == 200, (status, body)
        payload = as_json(body)
        assert payload["action"] == "disable", payload
        updated_user = next(
            user for user in payload["access"]["users"]
            if user["username"] == "created.user"
        )
        assert updated_user["enabled"] is False, updated_user

        status, _, body = request(
            port,
            "POST",
            "/api/admin/users/created.user/enable",
            token=admin_token,
            payload={},
        )
        assert status == 200, (status, body)
        payload = as_json(body)
        assert payload["action"] == "enable", payload
        updated_user = next(
            user for user in payload["access"]["users"]
            if user["username"] == "created.user"
        )
        assert updated_user["enabled"] is True, updated_user

        status, _, body = request(
            port,
            "POST",
            "/api/admin/users/created.user/role",
            token=admin_token,
            payload={"role": "ROOT"},
        )
        assert status == 400, (status, body)

        status, _, body = request(
            port,
            "POST",
            "/api/admin/users/actions.admin/disable",
            token=admin_token,
            payload={},
        )
        assert status == 200, (status, body)

        status, _, body = request(
            port,
            "POST",
            "/api/admin/users/backup.admin/disable",
            token=backup_admin_token,
            payload={},
        )
        assert status == 409, (status, body)
        assert "last active ADMIN" in body, body

        with deltaaegis_test_db(db_path) as connection:
            created = da.access_user_by_username(connection, "created.user")
            assert created is not None
            assert created["role"] == "ANALYST", dict(created)
            assert int(created["is_active"]) == 1, dict(created)
            assert da.verify_access_password("rotated-password", created["password_hash"]) is True

            backup = da.access_user_by_username(connection, "backup.admin")
            assert backup is not None
            assert int(backup["is_active"]) == 1, dict(backup)

            actions = [
                row["action"]
                for row in connection.execute(
                    "SELECT action FROM access_audit_log ORDER BY audit_id"
                ).fetchall()
            ]

            for expected in [
                "ACCESS_USER_DASHBOARD_CREATE",
                "ACCESS_USER_DASHBOARD_ROLE_CHANGE",
                "ACCESS_USER_DASHBOARD_PASSWORD_ROTATE",
                "ACCESS_USER_DASHBOARD_DISABLE",
                "ACCESS_USER_DASHBOARD_ENABLE",
            ]:
                assert expected in actions, actions

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

print("[PASS] synthetic v0.26 admin user actions validated")
PY

./tools/validate_v0_26_operator_users_page.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.26 operator users page compatibility gate failed"

pass "DeltaAegis v0.26 admin user actions validation passed"
