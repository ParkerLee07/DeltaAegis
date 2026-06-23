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

grep -q 'def command_scan_start' deltaaegis.py \
    || fail "scan-start command function is missing"

grep -q 'def execute_scan_job' deltaaegis.py \
    || fail "execute_scan_job helper is missing"

grep -q 'sub.add_parser("scan-start"' deltaaegis.py \
    || fail "scan-start parser registration is missing"

grep -q 'if args.command == "scan-start": return command_scan_start(args)' deltaaegis.py \
    || fail "scan-start main dispatch is missing"

grep -q 'subprocess.run' deltaaegis.py \
    || fail "scan-start does not invoke subprocess.run"

grep -q -- '--greenbone' deltaaegis.py \
    || fail "fixed NetSniper command does not include --greenbone"

grep -q -- '--json-status' deltaaegis.py \
    || fail "fixed NetSniper command does not include --json-status"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

db="$tmp_dir/deltaaegis.db"
fake_ns_dir="$tmp_dir/fake-netsniper"
fake_runs="$tmp_dir/runs"
logs="$tmp_dir/logs"

mkdir -p "$fake_ns_dir" "$fake_runs" "$logs"

cat > "$fake_ns_dir/netsniper.sh" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$@" > "$(dirname "$0")/args.txt"

echo "[*] Fake NetSniper v1.8 headless scan"
echo '{"status":"completed","exit_code":0,"bundle_dir":"/tmp/fake-netsniper-run"}'
FAKE

chmod +x "$fake_ns_dir/netsniper.sh"

python3 deltaaegis.py \
    --db "$db" \
    --runs-dir "$fake_runs" \
    --events "$tmp_dir/events.jsonl" \
    scan-start \
    --target 192.168.5.0/24 \
    --netsniper-path "$fake_ns_dir/netsniper.sh" \
    --scan-logs-dir "$logs" \
    > "$tmp_dir/scan-start.out"

grep -q 'Status: COMPLETED' "$tmp_dir/scan-start.out" \
    || fail "scan-start did not complete successfully"

expected_args='--non-interactive --target 192.168.5.0/24 --greenbone no --json-status'
actual_args="$(tr '\n' ' ' < "$fake_ns_dir/args.txt" | sed 's/[[:space:]]*$//')"

[ "$actual_args" = "$expected_args" ] \
    || fail "NetSniper command args were not fixed/safe. Got: $actual_args"

python3 - "$db" "$logs" <<'PY'
import json
import sqlite3
import sys
from pathlib import Path

db = Path(sys.argv[1])
logs = Path(sys.argv[2])

connection = sqlite3.connect(db)
connection.row_factory = sqlite3.Row

rows = connection.execute("SELECT * FROM scan_jobs").fetchall()

assert len(rows) == 1, rows

row = rows[0]

assert row["status"] == "COMPLETED", dict(row)
assert row["target"] == "192.168.5.0/24", dict(row)
assert row["network_scope"] == "192.168.5.0/24", dict(row)
assert row["exit_code"] == 0, dict(row)
assert row["bundle_path"] == "/tmp/fake-netsniper-run", dict(row)
assert row["stdout_log"], dict(row)
assert row["stderr_log"], dict(row)

stdout_log = Path(row["stdout_log"])
stderr_log = Path(row["stderr_log"])

assert stdout_log.is_file(), stdout_log
assert stderr_log.is_file(), stderr_log
assert logs in stdout_log.parents, stdout_log

status_json = json.loads(row["status_json"])
assert status_json["status"] == "completed", status_json
assert status_json["bundle_dir"] == "/tmp/fake-netsniper-run", status_json

print("[PASS] scan-start completed job row and logs validated")
PY

python3 deltaaegis.py --db "$db" scan-jobs --limit 5 \
    | grep -q 'COMPLETED' \
    || fail "scan-jobs did not show completed scan-start job"

if python3 deltaaegis.py \
    --db "$tmp_dir/reject.db" \
    scan-start \
    --target 8.8.8.0/24 \
    --netsniper-path "$fake_ns_dir/netsniper.sh" \
    --scan-logs-dir "$logs" \
    > "$tmp_dir/public-target.out" 2>&1
then
    fail "public target scan-start unexpectedly succeeded"
fi

grep -q 'target must be a private IPv4 CIDR' "$tmp_dir/public-target.out" \
    || fail "public target rejection message was not clear"

pass "DeltaAegis v0.14 scan-start validation passed"
