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

grep -q 'CREATE TABLE IF NOT EXISTS scan_jobs' deltaaegis.py \
    || fail "scan_jobs schema is missing"

grep -q 'def build_netsniper_headless_command' deltaaegis.py \
    || fail "safe NetSniper command builder is missing"

grep -q 'def validate_private_cidr' deltaaegis.py \
    || fail "private CIDR validator is missing"

grep -q 'def command_scan_jobs' deltaaegis.py \
    || fail "scan-jobs CLI command is missing"

grep -q 'route == "/api/scan-jobs"' deltaaegis.py \
    || fail "/api/scan-jobs dashboard API route is missing"

grep -q 'sub.add_parser("scan-jobs"' deltaaegis.py \
    || fail "scan-jobs parser registration is missing"

grep -q 'if args.command == "scan-jobs": return command_scan_jobs(args)' deltaaegis.py \
    || fail "scan-jobs main dispatch is missing"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

db="$tmp_dir/deltaaegis.db"

python3 deltaaegis.py --db "$db" scan-jobs --limit 5 \
    | grep -q 'No scan jobs found.' \
    || fail "empty scan-jobs CLI output was not correct"

python3 - "$db" <<'PY'
import json
import sqlite3
import sys
from pathlib import Path

import deltaaegis

db = Path(sys.argv[1])
connection = deltaaegis.connect(db)

columns = {
    row[1]
    for row in connection.execute("PRAGMA table_info(scan_jobs)").fetchall()
}

required_columns = {
    "job_id",
    "target",
    "network_scope",
    "status",
    "created_at",
    "updated_at",
    "started_at",
    "finished_at",
    "netsniper_path",
    "runs_dir",
    "bundle_path",
    "exit_code",
    "auto_ingest",
    "stdout_log",
    "stderr_log",
    "status_json",
    "message",
}

missing = sorted(required_columns - columns)

if missing:
    raise SystemExit(f"missing scan_jobs columns: {missing}")

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
        netsniper_path,
        runs_dir,
        auto_ingest,
        status_json,
        message
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
    (
        "scan-test-001",
        "192.168.5.0/24",
        "192.168.5.0/24",
        "QUEUED",
        now,
        now,
        "/home/parker/NetSniper/netsniper.sh",
        "/home/parker/NetSniper/runs",
        1,
        json.dumps({"state": "queued"}),
        "registry validation sample",
    ),
)

connection.commit()

rows = deltaaegis.query_scan_jobs(connection, limit=10)
assert len(rows) == 1, rows

payload = deltaaegis.dashboard_scan_jobs_payload(connection, limit=10)
assert payload[0]["job_id"] == "scan-test-001", payload
assert payload[0]["auto_ingest"] is True, payload
assert payload[0]["status_json"]["state"] == "queued", payload

command = deltaaegis.build_netsniper_headless_command(
    Path("/home/parker/NetSniper/netsniper.sh"),
    "192.168.5.0/24",
)

assert command == [
    "/home/parker/NetSniper/netsniper.sh",
    "--non-interactive",
    "--target",
    "192.168.5.0/24",
    "--greenbone",
    "no",
    "--json-status",
], command

try:
    deltaaegis.build_netsniper_headless_command(
        Path("/home/parker/NetSniper/netsniper.sh"),
        "8.8.8.0/24",
    )
except deltaaegis.DeltaAegisError:
    pass
else:
    raise SystemExit("public target was not rejected")

print("[PASS] scan_jobs schema, payload, and safe command builder validated")
PY

python3 deltaaegis.py --db "$db" scan-jobs --limit 5 \
    | grep -q 'scan-test-001' \
    || fail "scan-jobs CLI did not list inserted job"

pass "DeltaAegis v0.14 scan job registry validation passed"
