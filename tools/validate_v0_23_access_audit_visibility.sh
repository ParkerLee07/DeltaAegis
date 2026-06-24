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
    'def list_access_audit_events' \
    'def dashboard_access_audit_payload' \
    'def command_access_audit' \
    'function renderAccessAudit' \
    '"/api/access-audit' \
    'sub.add_parser("access-audit"' \
    'if args.command == "access-audit": return command_access_audit(args)'
do
    grep -q "$needle" deltaaegis.py || fail "missing access audit visibility marker: $needle"
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


def request(port: int, path: str, token: str | None = None):
    headers = {}
    if token:
        headers["X-DeltaAegis-Token"] = token

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        data = response.read().decode("utf-8", errors="replace")
        return response.status, data
    finally:
        conn.close()


with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "deltaaegis-audit-visibility-test.db"

    subprocess.run(
        [
            sys.executable,
            "deltaaegis.py",
            "--db",
            str(db_path),
            "user-create",
            "audit.admin",
            "--role",
            "ADMIN",
            "--actor",
            "validator",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    token_proc = subprocess.run(
        [
            sys.executable,
            "deltaaegis.py",
            "--db",
            str(db_path),
            "api-token-create",
            "audit.admin",
            "--name",
            "audit visibility token",
            "--role",
            "ADMIN",
            "--actor",
            "validator",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    token = token_proc.stdout.strip().splitlines()[-1]
    assert token.startswith("da_")

    audit_proc = subprocess.run(
        [
            sys.executable,
            "deltaaegis.py",
            "--db",
            str(db_path),
            "access-audit",
            "--limit",
            "10",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "ACCESS_USER_CREATE" in audit_proc.stdout, audit_proc.stdout
    assert "ACCESS_API_TOKEN_CREATE" in audit_proc.stdout, audit_proc.stdout

    with da.connect(db_path) as connection:
        payload = da.dashboard_access_audit_payload(connection, limit=10)
        assert payload["available"] is True
        assert payload["item_count"] >= 2, payload
        actions = {row["action"] for row in payload["items"]}
        assert "ACCESS_USER_CREATE" in actions, actions
        assert "ACCESS_API_TOKEN_CREATE" in actions, actions
        assert payload["summary"]["event_count"] >= 2, payload

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
                status, body = request(port, "/healthz")
                if status == 200:
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("dashboard did not start")

        status, body = request(port, "/api/access-audit", token=token)
        assert status == 200, (status, body)
        parsed = json.loads(body)
        assert parsed["available"] is True
        assert parsed["item_count"] >= 2, parsed

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

print("[PASS] synthetic v0.23 access audit visibility validated")
PY

./tools/validate_v0_23_dashboard_db_token_auth.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.23 dashboard DB-token auth compatibility gate failed"

./tools/validate_v0_23_access_cli_tokens.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.23 access CLI/token compatibility gate failed"

./tools/validate_v0_23_access_model.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.23 access model compatibility gate failed"

pass "DeltaAegis v0.23 access audit visibility validation passed"
