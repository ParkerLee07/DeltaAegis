#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

grep -q 'data-tab-target="scan-jobs"' deltaaegis.py \
    || fail "dashboard scan-jobs tab button missing"

grep -q 'data-tab-panel="scan-jobs"' deltaaegis.py \
    || fail "dashboard scan-jobs panel missing"

grep -q 'id="scan-jobs-body"' deltaaegis.py \
    || fail "scan-jobs table body missing"

grep -q 'function renderScanJobs' deltaaegis.py \
    || fail "renderScanJobs function missing"

grep -q 'api(scopedPath("/api/scan-jobs?limit=10"))' deltaaegis.py \
    || fail "dashboard does not fetch /api/scan-jobs"

grep -q 'renderScanJobs(scanJobs)' deltaaegis.py \
    || fail "dashboard does not render scan jobs"

grep -q 'deltaaegis scan-start --target' deltaaegis.py \
    || fail "dashboard does not point users to CLI scan-start"

if grep -q 'route == "/api/scan-start"' deltaaegis.py; then
    fail "dashboard API should not expose /api/scan-start in checkpoint 3"
fi

if grep -q 'fetch(scopedPath("/api/scan-start"' deltaaegis.py; then
    fail "dashboard should not POST scan-start in checkpoint 3"
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

db="$tmp_dir/deltaaegis.db"

python3 - "$db" <<'PY'
import json
import sqlite3
import sys
from pathlib import Path

import deltaaegis

db = Path(sys.argv[1])
connection = deltaaegis.connect(db)

now = deltaaegis.utc_now_text()

connection.execute(
    """
    INSERT INTO scan_jobs (
        job_id,
        target,
        network_scope,
        status,
        created_at,
        updated_at,
        started_at,
        finished_at,
        netsniper_path,
        runs_dir,
        bundle_path,
        exit_code,
        auto_ingest,
        stdout_log,
        stderr_log,
        status_json,
        message
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
    (
        "scan-ui-001",
        "192.168.5.0/24",
        "192.168.5.0/24",
        "COMPLETED",
        now,
        now,
        now,
        now,
        "/home/parker/NetSniper/netsniper.sh",
        "/home/parker/NetSniper/runs",
        "/home/parker/NetSniper/runs/example",
        0,
        0,
        "/tmp/stdout.log",
        "/tmp/stderr.log",
        json.dumps({"status": "completed"}),
        "dashboard validation sample",
    ),
)

connection.commit()

payload = deltaaegis.dashboard_scan_jobs_payload(
    connection,
    limit=10,
    scope="192.168.5.0/24",
)

assert len(payload) == 1, payload
assert payload[0]["job_id"] == "scan-ui-001", payload
assert payload[0]["status"] == "COMPLETED", payload
assert payload[0]["bundle_path"] == "/home/parker/NetSniper/runs/example", payload
assert payload[0]["status_json"]["status"] == "completed", payload

empty = deltaaegis.dashboard_scan_jobs_payload(
    connection,
    limit=10,
    scope="192.168.4.0/24",
)

assert empty == [], empty

html = deltaaegis.dashboard_index_html()
required = [
    'data-tab-target="scan-jobs"',
    'data-tab-panel="scan-jobs"',
    'id="scan-jobs-body"',
    'function renderScanJobs',
    'api(scopedPath("/api/scan-jobs?limit=10"))',
    'renderScanJobs(scanJobs)',
]

for item in required:
    assert item in html, item

print("[PASS] dashboard scan-jobs payload and HTML wiring validated")
PY

pass "DeltaAegis v0.14 scan jobs dashboard validation passed"
