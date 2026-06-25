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

grep -q '"/api/netsniper/import-latest", "workflow.write"' deltaaegis.py \
    || fail "missing RBAC policy for /api/netsniper/import-latest"

grep -q 'def dashboard_netsniper_import_latest_payload' deltaaegis.py \
    || fail "missing dashboard_netsniper_import_latest_payload"

grep -q 'id="netsniper-import-latest"' deltaaegis.py \
    || fail "missing import-latest dashboard button"

grep -q 'async function importLatestNetSniperRun' deltaaegis.py \
    || fail "missing import-latest browser handler"

grep -q 'route == "/api/netsniper/import-latest"' deltaaegis.py \
    || fail "missing POST route for /api/netsniper/import-latest"

if [[ ! -d "$NETSNIPER_RUN_DIR" ]]; then
    fail "NetSniper run directory does not exist: $NETSNIPER_RUN_DIR"
fi

if [[ ! -f "$NETSNIPER_RUN_DIR/manifest.json" ]]; then
    fail "NetSniper run manifest does not exist: $NETSNIPER_RUN_DIR/manifest.json"
fi

NETSNIPER_ROOT="$(cd "$NETSNIPER_RUN_DIR/../.." && pwd)"

python3 - "$NETSNIPER_ROOT" <<'PY'
import contextlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


netsniper_root = Path(sys.argv[1]).resolve()


def free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(port, method, path, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    headers = {}

    if body is not None:
        encoded = body.encode("utf-8")
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(encoded))
    else:
        encoded = None

    conn.request(method, path, body=encoded, headers=headers)
    response = conn.getresponse()
    data = response.read().decode("utf-8", "replace")
    headers = {k.lower(): v for k, v in response.getheaders()}
    conn.close()
    return response.status, headers, data


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
    tmpdir_path = Path(tmpdir)
    db_path = tmpdir_path / "deltaaegis.db"
    events_path = tmpdir_path / "deltaaegis-events.jsonl"
    port = free_port()

    env = dict(os.environ)
    env["DELTAAEGIS_NETSNIPER_ROOT"] = str(netsniper_root)

    process = subprocess.Popen(
        [
            sys.executable,
            "deltaaegis.py",
            "--db",
            str(db_path),
            "--events",
            str(events_path),
            "dashboard",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--no-require-login",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )

    try:
        wait_for_dashboard(port)

        status, headers, body = request(port, "GET", "/netsniper")
        assert status == 200, (status, headers, body[:400])
        assert 'id="netsniper-import-latest"' in body, body[:2000]
        assert "/api/netsniper/import-latest" in body, body[:5000]

        status, headers, body = request(port, "GET", "/api/netsniper/status")
        assert status == 200, (status, headers, body[:400])
        status_payload = json.loads(body)
        assert status_payload["runs_dir"] == str(netsniper_root / "runs"), status_payload
        assert status_payload["latest_manifest_found"] is True, status_payload

        status, headers, body = request(port, "POST", "/api/netsniper/import-latest", "{}")
        assert status == 200, (status, headers, body[:800])
        payload = json.loads(body)

        assert payload["ok"] is True, payload
        assert payload["action"] == "netsniper.import_latest", payload
        assert payload["run_id"], payload
        assert payload["manifest_path"].endswith("/manifest.json"), payload
        assert payload["result"].startswith(("IMPORT ", "SKIP ")), payload

        status, headers, body = request(port, "GET", "/api/summary")
        assert status == 200, (status, headers, body[:400])
        summary = json.loads(body)
        snapshot_total = summary.get("snapshot_count", summary.get("snapshots", 0))
        assert snapshot_total >= 1, summary

    finally:
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=5)

print("[PASS] dashboard NetSniper import-latest endpoint validated")
PY

pass "DeltaAegis v0.28 NetSniper import-latest validation passed"
