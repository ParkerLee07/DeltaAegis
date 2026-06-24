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

grep -q 'def operator_triage_enrich_row' deltaaegis.py \
    || fail "operator triage row helper missing"

grep -q 'def operator_triage_summary' deltaaegis.py \
    || fail "operator triage summary helper missing"

grep -q 'triage_changed_since_review' deltaaegis.py \
    || fail "changed-since-review field missing"

grep -q 'operator_triage_enrich_row(tuned)' deltaaegis.py \
    || fail "ticket signal tuning path does not enrich triage fields"

python3 - <<'PY'
from datetime import datetime, timezone, timedelta
import deltaaegis as da

now = datetime(2026, 6, 24, 17, 45, 0, tzinfo=timezone.utc)

rows = [
    {
        "subject_key": "mac:aa",
        "ticket_status": "OPEN",
        "ticket_signal_state": "MEANINGFUL_CHANGE",
        "priority_score": 70,
        "latest_event_at": (now - timedelta(hours=1)).isoformat(),
        "owner": None,
        "role": None,
        "criticality": None,
    },
    {
        "subject_key": "mac:bb",
        "ticket_status": "RESOLVED",
        "ticket_signal_state": "BASELINE_CONTEXT",
        "priority_score": 15,
        "latest_event_at": (now - timedelta(days=10)).isoformat(),
        "ticket_updated_at": (now - timedelta(days=8)).isoformat(),
        "owner": "network",
        "role": "printer",
        "criticality": "low",
    },
    {
        "subject_key": "mac:cc",
        "ticket_status": "RESOLVED",
        "ticket_signal_state": "ACTIONABLE",
        "priority_score": 50,
        "latest_event_at": (now - timedelta(hours=2)).isoformat(),
        "ticket_updated_at": (now - timedelta(days=1)).isoformat(),
        "owner": "network",
        "role": "server",
        "criticality": "medium",
    },
]

enriched = da.operator_triage_enrich_rows(rows, now=now)

assert enriched[0]["triage_bucket"] == "NEEDS_REVIEW", enriched[0]
assert enriched[0]["triage_missing_owner"] is True, enriched[0]
assert enriched[0]["triage_missing_context"] is True, enriched[0]
assert enriched[0]["triage_urgency_label"] in {"HIGH", "IMMEDIATE"}, enriched[0]

assert enriched[1]["triage_bucket"] == "STALE_CLOSED", enriched[1]
assert enriched[1]["triage_missing_owner"] is False, enriched[1]
assert enriched[1]["triage_missing_context"] is False, enriched[1]

assert enriched[2]["triage_bucket"] == "CHANGED_SINCE_REVIEW", enriched[2]
assert enriched[2]["triage_changed_since_review"] is True, enriched[2]

summary = da.operator_triage_summary(enriched)
assert summary["total"] == 3, summary
assert summary["needs_review"] == 1, summary
assert summary["stale_closed"] == 1, summary
assert summary["changed_since_review"] == 1, summary
assert summary["missing_owner"] == 1, summary
assert summary["missing_context"] == 1, summary

tuned = da.tune_investigation_center_ticket_signal({
    "subject_key": "mac:dd",
    "ticket_status": "OPEN",
    "ticket_signal_state": "ACTIONABLE",
    "priority_score": 40,
    "latest_event_at": now.isoformat(),
})
assert "triage_bucket" in tuned, tuned
assert "triage_urgency_score" in tuned, tuned
assert "triage_missing_owner" in tuned, tuned

print("[PASS] synthetic v0.22 operator triage state model validated")
PY

pass "DeltaAegis v0.22 operator triage state model validation passed"
