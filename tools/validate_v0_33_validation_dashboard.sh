#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

fixture="examples/trueaegis-fixtures/basic-validation/validation_results.json"
if [[ ! -f "$fixture" ]]; then
    echo "[FAIL] Missing fixture: $fixture" >&2
    exit 1
fi

grep -Fq '"/api/validation-summary"' deltaaegis.py
grep -Fq '"/api/validations"' deltaaegis.py
grep -Fq 'def dashboard_validation_summary_payload' deltaaegis.py
grep -Fq 'def dashboard_validations_payload' deltaaegis.py
grep -Fq 'route == "/api/validation-summary"' deltaaegis.py
grep -Fq 'route == "/api/validations"' deltaaegis.py
grep -Fq 'function renderTrueAegisValidationPanel' deltaaegis.py
grep -Fq 'trueaegis-validation-foundation-panel' deltaaegis.py

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

db="$tmpdir/deltaaegis-validation-dashboard.db"
python3 deltaaegis.py --db "$db" validation-ingest "$fixture" >/dev/null

python3 - "$db" <<'PY_CHECK'
import sys
from pathlib import Path
import deltaaegis

db = Path(sys.argv[1])
connection = deltaaegis.connect(db)

summary = deltaaegis.dashboard_validation_summary_payload(connection)
assert summary["schema_version"] == "deltaaegis-trueaegis-validation-summary-v1"
assert summary["validation_run_count"] == 1, summary
assert summary["observation_count"] == 5, summary
assert summary["confirmed_count"] == 1, summary
assert summary["protected_count"] == 1, summary

counts = {row["status"]: row["count"] for row in summary["status_counts"]}
expected = {
    "CONFIRMED": 1,
    "REACHABLE": 1,
    "PROTECTED": 1,
    "PROTOCOL_MISMATCH": 1,
    "NOT_REACHABLE": 1,
}
assert counts == expected, counts

payload = deltaaegis.dashboard_validations_payload(connection, limit=25)
assert payload["schema_version"] == "deltaaegis-trueaegis-validations-v1"
assert payload["count"] == 5, payload
statuses = {row["status"] for row in payload["observations"]}
assert statuses == set(expected), statuses

protected = [row for row in payload["observations"] if row["status"] == "PROTECTED"][0]
assert protected["finding_id"] == "SMB_EXPOSED"
assert protected["validated"] is True
assert protected["safe"] is True
assert protected["confidence"] == "HIGH"
assert isinstance(protected["details"], list)
assert isinstance(protected["evidence"], list)
assert isinstance(protected["metadata"], dict)

filtered = deltaaegis.dashboard_validations_payload(connection, status="CONFIRMED", limit=25)
assert filtered["count"] == 1, filtered
assert filtered["observations"][0]["status"] == "CONFIRMED"

print("[PASS] v0.33 validation dashboard payload checks passed")
PY_CHECK

# Exercise the actual read-only HTTP API routes with authentication disabled for local validator use.
port="$(python3 - <<'PY_PORT'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY_PORT
)"

python3 deltaaegis.py --db "$db" dashboard --host 127.0.0.1 --port "$port" --no-require-login --quiet > "$tmpdir/dashboard.log" 2>&1 &
server_pid="$!"

cleanup_server() {
    if kill -0 "$server_pid" >/dev/null 2>&1; then
        kill "$server_pid" >/dev/null 2>&1 || true
        wait "$server_pid" >/dev/null 2>&1 || true
    fi
}
trap 'cleanup_server; rm -rf "$tmpdir"' EXIT

python3 - "$port" <<'PY_HTTP'
import json
import sys
import time
import urllib.request

port = sys.argv[1]
base = f"http://127.0.0.1:{port}"

deadline = time.time() + 8
last_error = None
while time.time() < deadline:
    try:
        with urllib.request.urlopen(base + "/api/validation-summary", timeout=1) as response:
            summary = json.loads(response.read().decode("utf-8"))
        break
    except Exception as exc:
        last_error = exc
        time.sleep(0.2)
else:
    raise SystemExit(f"dashboard API did not become ready: {last_error}")

assert summary["observation_count"] == 5, summary
assert summary["confirmed_count"] == 1, summary

with urllib.request.urlopen(base + "/api/validations?limit=25", timeout=2) as response:
    validations = json.loads(response.read().decode("utf-8"))

assert validations["count"] == 5, validations
assert any(row["status"] == "PROTECTED" for row in validations["observations"]), validations

print("[PASS] v0.33 validation dashboard HTTP API checks passed")
PY_HTTP

cleanup_server
trap 'rm -rf "$tmpdir"' EXIT

echo "[PASS] DeltaAegis v0.33 validation dashboard/API checks passed"
