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
    'def dashboard_request_token' \
    'def authenticate_dashboard_request' \
    'authenticate_access_api_token(' \
    'self.require_auth(required_role="ANALYST")' \
    'DASHBOARD_TICKET_STATUS_UPDATE' \
    'DASHBOARD_ASSET_INVESTIGATION_UPDATE' \
    'DB Tokens: accepted'
do
    grep -q "$needle" deltaaegis.py || fail "missing dashboard DB-token auth marker: $needle"
done

python3 - <<'PY'
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


def request(port: int, method: str, path: str, token: str | None = None, body: dict | None = None):
    headers = {}

    payload = None

    if token:
        headers["X-DeltaAegis-Token"] = token

    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(payload))

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)

    try:
        conn.request(method, path, body=payload, headers=headers)
        response = conn.getresponse()
        data = response.read().decode("utf-8", errors="replace")
        return response.status, data
    finally:
        conn.close()


with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "deltaaegis-dashboard-auth-test.db"

    with da.connect(db_path) as connection:
        admin = da.create_access_user(
            connection,
            "dashboard.admin",
            role="ADMIN",
            password="admin-password",
        )
        viewer = da.create_access_user(
            connection,
            "dashboard.viewer",
            role="VIEWER",
            password="viewer-password",
        )
        admin_token = da.create_access_api_token(
            connection,
            admin["user_id"],
            token_name="admin dashboard token",
            role="ADMIN",
        )["token"]
        viewer_token = da.create_access_api_token(
            connection,
            viewer["user_id"],
            token_name="viewer dashboard token",
            role="VIEWER",
        )["token"]

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
            "--token",
            "legacy-token",
            "--quiet",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        for _ in range(50):
            try:
                status, body = request(port, "GET", "/healthz")
                if status == 200:
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("dashboard did not start")

        status, body = request(port, "GET", "/api/scopes")
        assert status == 401, (status, body)

        status, body = request(port, "GET", "/api/scopes", token="legacy-token")
        assert status == 200, (status, body)

        status, body = request(port, "GET", "/api/scopes", token=viewer_token)
        assert status == 200, (status, body)

        status, body = request(
            port,
            "POST",
            "/api/ticket-status",
            token=viewer_token,
            body={
                "subject_key": "mac:00:11:22:33:44:55",
                "status": "IN_REVIEW",
                "analyst": "viewer",
                "note": "viewer should be denied",
            },
        )
        assert status == 401, (status, body)

        status, body = request(
            port,
            "POST",
            "/api/ticket-status",
            token=admin_token,
            body={
                "subject_key": "mac:00:11:22:33:44:55",
                "status": "IN_REVIEW",
                "analyst": "admin",
                "note": "admin dashboard auth smoke",
            },
        )
        assert status == 200, (status, body)
        parsed = json.loads(body)
        assert parsed["ok"] is True

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

    with da.connect(db_path) as connection:
        admin_row = connection.execute(
            "SELECT last_used_at FROM access_api_tokens WHERE token_prefix = ?",
            (admin_token[:12],),
        ).fetchone()
        viewer_row = connection.execute(
            "SELECT last_used_at FROM access_api_tokens WHERE token_prefix = ?",
            (viewer_token[:12],),
        ).fetchone()
        assert admin_row is not None
        assert viewer_row is not None
        assert admin_row["last_used_at"], dict(admin_row)
        assert viewer_row["last_used_at"], dict(viewer_row)

        actions = [
            row["action"]
            for row in connection.execute(
                "SELECT action FROM access_audit_log ORDER BY audit_id"
            ).fetchall()
        ]
        assert "DASHBOARD_TICKET_STATUS_UPDATE" in actions, actions

print("[PASS] synthetic v0.23 dashboard DB-token auth workflow validated")
PY

./tools/validate_v0_23_access_cli_tokens.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.23 access CLI/token compatibility gate failed"

./tools/validate_v0_23_access_model.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.23 access model compatibility gate failed"

./tools/validate_v0_23_backward_compatibility.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.23 backward compatibility gate failed"

pass "DeltaAegis v0.23 dashboard DB-token auth validation passed"
