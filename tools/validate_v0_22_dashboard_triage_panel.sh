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

grep -q 'id="triage-bucket-filter"' deltaaegis.py \
    || fail "dashboard triage bucket filter missing"

grep -q 'id="triage-urgency-filter"' deltaaegis.py \
    || fail "dashboard triage urgency filter missing"

grep -q 'id="investigation-triage-summary"' deltaaegis.py \
    || fail "dashboard triage summary panel missing"

grep -q 'function ticketTriageBadge' deltaaegis.py \
    || fail "ticket triage badge helper missing"

grep -q 'function renderTriageSummaryPanel' deltaaegis.py \
    || fail "triage summary render helper missing"

grep -q 'params.set("triage_bucket", triageBucket)' deltaaegis.py \
    || fail "dashboard request path missing triage_bucket"

grep -q 'params.set("triage_urgency", triageUrgency)' deltaaegis.py \
    || fail "dashboard request path missing triage_urgency"

grep -q 'ticketTriageBadge(row)' deltaaegis.py \
    || fail "Investigation Center rows do not render triage badge"

grep -q 'triage_summary' deltaaegis.py \
    || fail "Investigation Center payload missing triage_summary"

python3 - <<'PY'
import sqlite3
from pathlib import Path
import deltaaegis as da

html = da.dashboard_index_html()

required = [
    'id="triage-bucket-filter"',
    'id="triage-urgency-filter"',
    'id="investigation-triage-summary"',
    'ticket-triage-badge',
    'function ticketTriageBadge',
    'function renderTriageSummaryPanel',
    'params.set("triage_bucket", triageBucket)',
    'params.set("triage_urgency", triageUrgency)',
]

for marker in required:
    assert marker in html, marker

filters = da.investigation_center_filter_payload(
    ticket_status="all",
    ticket_signal="all",
    triage_bucket="needs-review",
    triage_urgency="high",
)

assert filters["triage_bucket"] == "NEEDS_REVIEW", filters
assert filters["triage_urgency"] == "HIGH", filters
assert filters["triage_buckets"].count("NEEDS_REVIEW") == 1, filters
assert filters["triage_urgencies"].count("HIGH") == 1, filters

source = Path("deltaaegis.py").read_text(encoding="utf-8")
start = source.index("def investigation_center_filter_payload(")
end = source.index("\ndef ", start + 1)
function_text = source[start:end]

assert function_text.count('"triage_bucket":') == 1, function_text
assert function_text.count('"triage_urgency":') == 1, function_text

db_path = Path("data/deltaaegis.db")
if db_path.exists():
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        payload = da.dashboard_investigation_center_payload(
            connection,
            limit=5,
            scope="192.168.5.0/24",
            triage_bucket="NEEDS_REVIEW",
            triage_urgency="IMMEDIATE",
        )

    assert "triage_summary" in payload, payload.keys()
    assert payload["filters"]["triage_bucket"] == "NEEDS_REVIEW", payload["filters"]
    assert payload["filters"]["triage_urgency"] == "IMMEDIATE", payload["filters"]

print("[PASS] static v0.22 dashboard triage panel validated")
PY

./tools/validate_v0_22_triage_queue_api_cli.sh \
    || fail "v0.22 triage queue API/CLI validator failed"

./tools/validate_v0_22_triage_state_model.sh \
    || fail "v0.22 triage state model validator failed"

pass "DeltaAegis v0.22 dashboard triage panel validation passed"
