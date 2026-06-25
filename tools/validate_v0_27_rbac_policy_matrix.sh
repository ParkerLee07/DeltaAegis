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

python3 -m py_compile deltaaegis.py || fail "deltaaegis.py does not compile"

for marker in \
    "ACCESS_RBAC_PERMISSIONS" \
    "ACCESS_RBAC_ROUTE_POLICIES" \
    "def access_rbac_required_role" \
    "def access_rbac_allows" \
    "def dashboard_route_permission" \
    "def require_permission" \
    '"admin.users.read": "ADMIN"' \
    '"admin.users.write": "ADMIN"' \
    '"admin.audit.read": "ADMIN"' \
    '"workflow.write": "ANALYST"'
do
    grep -Fq "$marker" deltaaegis.py || fail "missing v0.27 RBAC marker: $marker"
done

python3 - <<'PYUNIT'
import deltaaegis as da

expected = {
    "dashboard.read": "VIEWER",
    "operator.session.read": "VIEWER",
    "session.read": "VIEWER",
    "admin.users.read": "ADMIN",
    "admin.users.write": "ADMIN",
    "admin.audit.read": "ADMIN",
    "workflow.write": "ANALYST",
}

for permission, role in expected.items():
    assert da.access_rbac_required_role(permission) == role, permission

assert da.access_rbac_allows("VIEWER", "dashboard.read")
assert da.access_rbac_allows("ANALYST", "dashboard.read")
assert da.access_rbac_allows("ADMIN", "dashboard.read")

assert not da.access_rbac_allows("VIEWER", "workflow.write")
assert da.access_rbac_allows("ANALYST", "workflow.write")
assert da.access_rbac_allows("ADMIN", "workflow.write")

assert not da.access_rbac_allows("VIEWER", "admin.users.read")
assert not da.access_rbac_allows("ANALYST", "admin.users.read")
assert da.access_rbac_allows("ADMIN", "admin.users.read")

route_cases = {
    ("GET", "/"): "dashboard.read",
    ("GET", "/operator"): "operator.session.read",
    ("GET", "/operator/users"): "admin.users.read",
    ("GET", "/api/session"): "session.read",
    ("GET", "/api/admin/users"): "admin.users.read",
    ("GET", "/api/access-audit"): "admin.audit.read",
    ("GET", "/api/access-audit?limit=20"): "admin.audit.read",
    ("POST", "/api/admin/users"): "admin.users.write",
    ("POST", "/api/admin/users/example/password"): "admin.users.write",
    ("POST", "/api/ticket-status"): "workflow.write",
    ("POST", "/api/investigate-asset"): "workflow.write",
}

for route_case, permission in route_cases.items():
    assert da.dashboard_route_permission(*route_case) == permission, route_case

try:
    da.access_rbac_required_role("not.real")
except ValueError:
    pass
else:
    raise AssertionError("unknown permission did not raise ValueError")

print("[PASS] v0.27 RBAC policy matrix unit checks passed")
PYUNIT

python3 - <<'PYHTTP'
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


def request(port: int, method: str, path: str, body: str | None = None, cookie: str | None = None, content_type: str = "application/x-www-form-urlencoded"):
    headers = {}

    if cookie:
        headers["Cookie"] = cookie

    if body is not None:
        headers["Content-Type"] = content_type
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
    assert status in {302, 303}, (username, status, data)
    cookie = headers.get("set-cookie", "").split(";", 1)[0]
    assert cookie.startswith("deltaaegis_session=ds_"), (username, cookie)
    return cookie


def expect(port: int, method: str, path: str, cookie: str, expected: int, body: str | None = None, content_type: str = "application/x-www-form-urlencoded"):
    status, headers, data = request(port, method, path, body=body, cookie=cookie, content_type=content_type)
    assert status == expected, (method, path, expected, status, data[:500])
    return data


with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "deltaaegis-v027-rbac-policy.db"

    with deltaaegis_test_db(db_path) as connection:
        da.create_access_user(connection, "rbac.admin", display_name="RBAC Admin", role="ADMIN", password="admin-password")
        da.create_access_user(connection, "rbac.analyst", display_name="RBAC Analyst", role="ANALYST", password="analyst-password")
        da.create_access_user(connection, "rbac.viewer", display_name="RBAC Viewer", role="VIEWER", password="viewer-password")
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

        admin = login(port, "rbac.admin", "admin-password")
        analyst = login(port, "rbac.analyst", "analyst-password")
        viewer = login(port, "rbac.viewer", "viewer-password")

        for cookie in [admin, analyst, viewer]:
            expect(port, "GET", "/", cookie, 200)
            expect(port, "GET", "/operator", cookie, 200)
            expect(port, "GET", "/api/session", cookie, 200)

        expect(port, "GET", "/operator/users", admin, 200)
        expect(port, "GET", "/api/admin/users", admin, 200)
        expect(port, "GET", "/api/access-audit?limit=20", admin, 200)

        for cookie in [analyst, viewer]:
            expect(port, "GET", "/operator/users", cookie, 403)
            expect(port, "GET", "/api/admin/users", cookie, 403)
            expect(port, "GET", "/api/access-audit?limit=20", cookie, 403)

        create_payload = json.dumps({
            "username": "rbac.created",
            "display_name": "Created User",
            "role": "VIEWER",
            "password": "created-password",
        })
        expect(port, "POST", "/api/admin/users", admin, 200, body=create_payload, content_type="application/json")

        for cookie in [analyst, viewer]:
            expect(
                port,
                "POST",
                "/api/admin/users",
                cookie,
                403,
                body=json.dumps({"username": "rbac.denied", "role": "VIEWER", "password": "denied-password"}),
                content_type="application/json",
            )

        expect(
            port,
            "POST",
            "/api/ticket-status",
            viewer,
            403,
            body=json.dumps({"subject_key": "synthetic", "status": "OPEN"}),
            content_type="application/json",
        )

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

print("[PASS] synthetic v0.27 dashboard RBAC enforcement validated")
PYHTTP

./tools/validate_v0_26_release.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.26 inherited release gate failed"

pass "DeltaAegis v0.27 RBAC policy matrix validation passed"
