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

grep -q 'def ticket_evidence_why_now_summary' deltaaegis.py \
    || fail "why-now summary helper missing"

grep -q '"why_now": why_now' deltaaegis.py \
    || fail "why-now summary field missing from payload summary"

grep -q 'Why now:' deltaaegis.py \
    || fail "why-now output missing from CLI or report"

python3 - <<'PYVALIDATOR'
import deltaaegis

why_now = deltaaegis.ticket_evidence_why_now_summary(
    risk_rows=[
        {
            "level": "HIGH",
            "score": 74,
        }
    ],
    alert_rows=[
        {
            "severity": "MEDIUM",
            "status": "OPEN",
        }
    ],
    event_rows=[
        {
            "event_type": "ASSET_REAPPEARED",
        },
        {
            "event_type": "MONITORED_SERVICE_OPENED",
        },
    ],
    port_behavior_rows=[
        {
            "protocol": "tcp",
            "port": 9100,
        }
    ],
    ticket_history_rows=[],
    ticket_state={
        "ticket_status": "IN_REVIEW",
    },
    investigation_items=[
        {
            "priority_level": "HIGH",
            "priority_score": 88,
        }
    ],
)

expected_fragments = [
    "investigation priority is HIGH with score 88",
    "current risk context is HIGH with score 74",
    "1 active alert(s)",
    "ASSET_REAPPEARED",
    "MONITORED_SERVICE_OPENED",
    "MAC-port behavior changed on tcp/9100",
    "workflow status is IN_REVIEW",
]

for fragment in expected_fragments:
    assert fragment in why_now, why_now

fallback = deltaaegis.ticket_evidence_why_now_summary(
    [],
    [],
    [],
    [],
    [],
    {"ticket_status": "RESOLVED"},
)

assert "DeltaAegis found evidence linked to this subject" in fallback, fallback

print("[PASS] synthetic v0.21 why-now summary validated")
PYVALIDATOR

pass "DeltaAegis v0.21 why-now summary validation passed"
