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

python3 -m py_compile deltaaegis.py || fail "deltaaegis.py does not compile"

for marker in \
    "def dashboard_access_user_count" \
    "def dashboard_first_admin_setup_required" \
    "def dashboard_first_admin_setup_html" \
    'if route == "/setup":' \
    "Create first admin" \
    "setup_disabled"
do
    grep -Fq "$marker" deltaaegis.py || fail "missing v0.27 first-admin setup marker: $marker"
done

python3 - <<'PYLOGIN'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

do_get = text.find("        def do_GET(self):")
do_post = text.find("        def do_POST(self):", do_get)

if do_get == -1 or do_post == -1:
    raise SystemExit("Could not locate do_GET/do_POST boundaries")

get_section = text[do_get:do_post]
login_pos = get_section.find('            if route == "/login":')
logout_pos = get_section.find('            if route == "/logout":', login_pos)

if login_pos == -1 or logout_pos == -1:
    raise SystemExit("Could not locate GET /login block")

login_block = get_section[login_pos:logout_pos]

# Ignore comments so security notes do not look like executable calls.
login_code_only = "\n".join(
    line for line in login_block.splitlines()
    if not line.lstrip().startswith("#")
)

if "require_permission(" in login_code_only:
    raise SystemExit("GET /login must not call require_permission before rendering login/setup")

if "require_auth(" in login_code_only:
    raise SystemExit("GET /login must not call require_auth before rendering login/setup")

if 'dashboard_html_response(self, dashboard_login_html())' not in login_code_only:
    raise SystemExit("GET /login does not render login HTML")

if 'dashboard_first_admin_setup_required(connection)' not in login_code_only:
    raise SystemExit("GET /login does not check first-admin setup")
PYLOGIN

python3 - <<'PY'
import contextlib
import http.client
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode


def free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(port, method, path, body=None, headers=None, cookie=None):
    headers = dict(headers or {})
    if cookie:
        headers["Cookie"] = cookie
    if body is not None:
        headers["Content-Length"] = str(len(body.encode("utf-8")))
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    data = response.read().decode("utf-8", "replace")
    response_headers = {k.lower(): v for k, v in response.getheaders()}
    conn.close()
    return response.status, response_headers, data


def wait_for_dashboard(port):
    deadline = time.time() + 12
    while time.time() < deadline:
        try:
            status, _, _ = request(port, "GET", "/healthz")
            if status == 200:
                return
        except OSError:
            time.sleep(0.2)
    raise AssertionError("dashboard did not start")


with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "deltaaegis-v027-first-admin.db"
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

        status, headers, body = request(port, "GET", "/login")
        assert status in {302, 303}, (status, headers, body[:300])
        assert headers.get("location") == "/setup", headers

        status, headers, body = request(port, "GET", "/setup")
        assert status == 200, (status, headers, body[:300])
        assert "Create first admin" in body, body[:300]

        setup_body = urlencode({
            "username": "first.admin",
            "display_name": "First Admin",
            "password": "first-admin-password",
            "password_confirm": "first-admin-password",
        })
        status, headers, body = request(
            port,
            "POST",
            "/setup",
            body=setup_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert status in {302, 303}, (status, headers, body[:300])
        cookie = headers.get("set-cookie", "")
        assert "deltaaegis_session=ds_" in cookie, cookie
        cookie_pair = cookie.split(";", 1)[0]

        status, headers, body = request(port, "GET", "/api/session", cookie=cookie_pair)
        assert status == 200, (status, headers, body[:300])
        assert '"username": "first.admin"' in body, body[:500]
        assert '"role": "ADMIN"' in body, body[:500]

        status, headers, body = request(port, "GET", "/setup", cookie=cookie_pair)
        assert status in {302, 303}, (status, headers, body[:300])

        status, headers, body = request(
            port,
            "POST",
            "/setup",
            body=setup_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert status == 403, (status, headers, body[:300])
        assert "setup_disabled" in body, body[:300]

    finally:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)

print("[PASS] synthetic v0.27 first-admin setup validated")
PY

if [[ -x "./tools/validate_v0_27_rbac_policy_matrix.sh" ]]; then
    ./tools/validate_v0_27_rbac_policy_matrix.sh "$NETSNIPER_RUN_DIR" \
        || fail "v0.27 RBAC checkpoint gate failed"
fi

pass "DeltaAegis v0.27 first-admin setup validation passed"
