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

grep -q 'def ticket_evidence_balance_timeline' deltaaegis.py \
    || fail "balanced timeline helper missing"

grep -q 'def ticket_evidence_timeline_category_order' deltaaegis.py \
    || fail "timeline category order helper missing"

python3 - <<'PYVALIDATOR'
from collections import Counter
import deltaaegis

subject = "mac:AA:AA:AA:AA:AA:01"

risk_rows = [
    {
        "subject_key": subject,
        "level": "HIGH",
        "reasons": ["Risk evidence should survive workflow-history dominance."],
        "updated_at": "2026-06-24T10:00:00+00:00",
    }
]

alert_rows = [
    {
        "subject_key": subject,
        "severity": "HIGH",
        "summary": "Alert evidence should survive workflow-history dominance.",
        "last_seen_at": "2026-06-24T11:00:00+00:00",
    }
]

event_rows = [
    {
        "subject_key": subject,
        "severity": "MEDIUM",
        "summary": "Delta event evidence should survive workflow-history dominance.",
        "created_at": "2026-06-24T12:00:00+00:00",
    }
]

port_behavior_rows = [
    {
        "subject_key": subject,
        "severity": "MEDIUM",
        "behavior": "PORT_FLAPPING",
        "protocol": "tcp",
        "port": 9100,
        "last_seen_at": "2026-06-24T13:00:00+00:00",
    }
]

ticket_history_rows = [
    {
        "ticket_key": deltaaegis.stable_ticket_key(subject),
        "previous_status": "OPEN",
        "new_status": f"STATE_{index}",
        "created_at": f"2026-06-24T15:{index:02d}:00+00:00",
    }
    for index in range(10)
]

timeline = deltaaegis.ticket_evidence_build_timeline(
    risk_rows,
    alert_rows,
    event_rows,
    port_behavior_rows,
    ticket_history_rows,
    limit=5,
)

categories = [item["category"] for item in timeline]
expected = {
    "current_risk",
    "alert",
    "delta_event",
    "port_behavior",
    "ticket_history",
}

assert len(timeline) == 5, timeline
assert set(categories) == expected, categories
assert categories == [
    "current_risk",
    "alert",
    "delta_event",
    "port_behavior",
    "ticket_history",
], categories

second_timeline = deltaaegis.ticket_evidence_build_timeline(
    risk_rows,
    alert_rows,
    event_rows,
    port_behavior_rows,
    ticket_history_rows,
    limit=5,
)

assert timeline == second_timeline, "balanced timeline output is not deterministic"

expanded = deltaaegis.ticket_evidence_build_timeline(
    risk_rows,
    alert_rows,
    event_rows,
    port_behavior_rows,
    ticket_history_rows,
    limit=7,
)

expanded_categories = [item["category"] for item in expanded]
counts = Counter(expanded_categories)

assert len(expanded) == 7, expanded
assert set(expanded_categories) >= expected, expanded_categories
assert counts["ticket_history"] == 3, counts

partial = deltaaegis.ticket_evidence_build_timeline(
    risk_rows,
    [],
    [],
    [],
    ticket_history_rows,
    limit=3,
)

partial_categories = [item["category"] for item in partial]

assert len(partial) == 3, partial
assert "current_risk" in partial_categories, partial_categories
assert "ticket_history" in partial_categories, partial_categories

empty = deltaaegis.ticket_evidence_build_timeline([], [], [], [], [], limit=5)
assert empty == [], empty

zero_limit = deltaaegis.ticket_evidence_build_timeline(
    risk_rows,
    alert_rows,
    event_rows,
    port_behavior_rows,
    ticket_history_rows,
    limit=0,
)
assert zero_limit == [], zero_limit

print("[PASS] synthetic v0.21 balanced evidence timeline validated")
PYVALIDATOR

pass "DeltaAegis v0.21 balanced evidence timeline validation passed"
