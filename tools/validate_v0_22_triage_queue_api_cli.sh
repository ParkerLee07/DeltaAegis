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

grep -q 'def normalize_triage_bucket_filter' deltaaegis.py \
    || fail "triage bucket filter normalizer missing"

grep -q 'def filter_operator_triage_rows' deltaaegis.py \
    || fail "triage row filter missing"

grep -q 'def operator_triage_queue_sort_key' deltaaegis.py \
    || fail "triage queue sort key missing"

grep -q 'triage_summary' deltaaegis.py \
    || fail "investigation center payload missing triage_summary"

grep -q 'triage_bucket = query.get("triage_bucket"' deltaaegis.py \
    || fail "API route does not parse triage_bucket"

grep -q -- '--triage-bucket' deltaaegis.py \
    || fail "CLI parser missing --triage-bucket"

grep -q 'getattr(args, "triage_bucket", "ALL")' deltaaegis.py \
    || fail "CLI command does not pass triage bucket safely"

grep -q 'Triage:' deltaaegis.py \
    || fail "CLI output missing triage line"

python3 deltaaegis.py investigation-center --help | grep -q -- '--triage-bucket' \
    || fail "investigation-center help does not expose --triage-bucket"

python3 deltaaegis.py investigation-center --help | grep -q -- '--triage-urgency' \
    || fail "investigation-center help does not expose --triage-urgency"

python3 - <<'PY'
import deltaaegis as da

rows = [
    da.operator_triage_enrich_row({
        "subject_key": "a",
        "ticket_status": "OPEN",
        "ticket_signal_state": "MEANINGFUL_CHANGE",
        "priority_score": 80,
        "latest_event_at": "2026-06-24T17:00:00+00:00",
    }),
    da.operator_triage_enrich_row({
        "subject_key": "b",
        "ticket_status": "OPEN",
        "ticket_signal_state": "BASELINE_CONTEXT",
        "priority_score": 20,
        "latest_event_at": "2026-06-24T16:00:00+00:00",
    }),
]

filters = da.investigation_center_filter_payload(
    ticket_status="open",
    ticket_signal="all",
    triage_bucket="needs-review",
    triage_urgency="immediate",
)

assert filters["ticket_status"] == "OPEN", filters
assert filters["triage_bucket"] == "NEEDS_REVIEW", filters
assert filters["triage_urgency"] == "IMMEDIATE", filters
assert "NEEDS_REVIEW" in filters["triage_buckets"], filters
assert "IMMEDIATE" in filters["triage_urgencies"], filters

filtered = da.filter_operator_triage_rows(
    rows,
    triage_bucket="NEEDS_REVIEW",
)

assert len(filtered) == 1, filtered
assert filtered[0]["subject_key"] == "a", filtered
assert filtered[0]["triage_bucket"] == "NEEDS_REVIEW", filtered

summary = da.operator_triage_summary(rows)
assert summary["total"] == 2, summary
assert summary["needs_review"] == 1, summary
assert summary["needs_context"] == 1, summary

sorted_rows = sorted(rows, key=da.operator_triage_queue_sort_key)
assert sorted_rows[0]["subject_key"] == "a", sorted_rows

print("[PASS] synthetic v0.22 triage queue API/CLI helpers validated")
PY

./tools/validate_v0_22_triage_state_model.sh \
    || fail "v0.22 triage state model validator failed"

pass "DeltaAegis v0.22 triage queue API/CLI validation passed"
