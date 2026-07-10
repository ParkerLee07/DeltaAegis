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
python3 -m py_compile tools/bootstrap_first_admin.py || fail "bootstrap_first_admin.py does not compile"

grep -Fq '"--no-require-login"' deltaaegis.py \
    || fail "missing --no-require-login development escape hatch"

grep -Fq "default=True" deltaaegis.py \
    || fail "dashboard require_login must default to True"

grep -Fq 'DELTAAEGIS_DB_PATH="${DELTAAEGIS_DB_PATH:-data/deltaaegis.db}"' install.sh \
    || fail "install.sh must default to data/deltaaegis.db"

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
    tmpdir = Path(tmpdir)
    db_path = tmpdir / "deltaaegis.db"

    # This simulates install.sh creating the first admin in the default DB.
    bootstrap = subprocess.run(
        [
            sys.executable,
            "tools/bootstrap_first_admin.py",
            "--db",
            str(db_path),
            "--username",
            "simple.admin",
            "--password",
            "simple-admin-password",
            "--display-name",
            "Simple Admin",
            "--non-interactive",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert bootstrap.returncode == 0, (bootstrap.returncode, bootstrap.stdout, bootstrap.stderr)

    port = free_port()

    # This intentionally does NOT pass --require-login.
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
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        wait_for_dashboard(port)

        status, headers, body = request(port, "GET", "/api/session")
        assert status == 401, (status, headers, body[:300])

        status, headers, body = request(port, "GET", "/login")
        assert status == 200, (status, headers, body[:300])
        assert "DeltaAegis Login" in body, body[:500]

        status, headers, body = request(port, "GET", "/setup")
        assert status in {302, 303}, (status, headers, body[:300])
        assert headers.get("location") == "/login", headers

        login_body = urlencode({
            "username": "simple.admin",
            "password": "simple-admin-password",
        })
        status, headers, body = request(
            port,
            "POST",
            "/login",
            body=login_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert status in {302, 303}, (status, headers, body[:300])
        cookie = headers.get("set-cookie", "")
        assert "deltaaegis_session=ds_" in cookie, cookie
        cookie_pair = cookie.split(";", 1)[0]

        status, headers, body = request(port, "GET", "/api/session", cookie=cookie_pair)
        assert status == 200, (status, headers, body[:500])
        assert '"username": "simple.admin"' in body, body[:500]
        assert '"role": "ADMIN"' in body, body[:500]

    finally:
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=5)
        if process.returncode not in {0, -15}:
            print("----- dashboard output -----")
            print(output)
            print("----- end dashboard output -----")

print("[PASS] simple install-created admin works with plain `deltaaegis dashboard`")
PY


pass "DeltaAegis v0.27.1 dashboard defaults validation passed"
