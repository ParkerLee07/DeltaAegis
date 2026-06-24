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

./tools/validate_v0_20_dashboard_ticket_evidence.sh \
    || fail "v0.20 dashboard ticket evidence validation failed"

grep -q 'def command_ticket_evidence' deltaaegis.py \
    || fail "ticket-evidence command function missing"

grep -q 'def print_ticket_evidence_payload' deltaaegis.py \
    || fail "ticket evidence print helper missing"

grep -q 'sub.add_parser("ticket-evidence"' deltaaegis.py \
    || fail "ticket-evidence parser command missing"

grep -q 'args.command == "ticket-evidence"' deltaaegis.py \
    || fail "ticket-evidence dispatch missing"

grep -q 'Evidence Timeline' deltaaegis.py \
    || fail "ticket-evidence CLI does not print Evidence Timeline"

grep -q 'Current Risk Evidence' deltaaegis.py \
    || fail "ticket-evidence CLI does not print risk evidence"

python3 - <<'PY'
import contextlib
import io
from types import SimpleNamespace

import deltaaegis

subject = "mac:AA:AA:AA:AA:AA:01"

payload = {
    "available": True,
    "subject_key": deltaaegis.stable_ticket_key(subject),
    "selected_subject": subject,
    "selected_scope": "192.168.5.0/24",
    "summary": {
        "subject_key": deltaaegis.stable_ticket_key(subject),
        "selected_subject": subject,
        "scope": "192.168.5.0/24",
        "ticket_status": "IN_REVIEW",
        "ticket_signal": "ACTIONABLE",
        "priority_level": "HIGH",
        "priority_score": 88,
        "risk_count": 1,
        "alert_count": 1,
        "event_count": 1,
        "port_behavior_count": 1,
        "ticket_history_count": 1,
        "timeline_count": 5,
        "primary_reason": "Synthetic CLI reason.",
        "recommended_action": "Synthetic CLI next action.",
    },
    "ticket_state": {
        "ticket_status": "IN_REVIEW",
    },
    "timeline": [
        {
            "timestamp": "2026-06-24T15:00:00+00:00",
            "category": "current_risk",
            "severity": "HIGH",
            "source": "risk_register",
            "summary": "Synthetic risk timeline.",
        }
    ],
    "risk": [
        {
            "level": "HIGH",
            "score": 88,
            "subject_key": deltaaegis.stable_ticket_key(subject),
            "reasons": ["Synthetic CLI reason."],
        }
    ],
    "alerts": [
        {
            "alert_id": 1,
            "status": "OPEN",
            "severity": "HIGH",
            "event_type": "SYNTHETIC",
            "summary": "Synthetic alert.",
        }
    ],
    "events": [
        {
            "event_id": 2,
            "created_at": "2026-06-24T14:00:00+00:00",
            "severity": "MEDIUM",
            "event_type": "MONITORED_SERVICE_OPENED",
            "summary": "Synthetic event.",
        }
    ],
    "port_behavior": [
        {
            "severity": "MEDIUM",
            "behavior": "PORT_FLAPPING",
            "protocol": "tcp",
            "port": 22,
            "reason": "Synthetic port behavior.",
        }
    ],
    "ticket_history": [
        {
            "created_at": "2026-06-24T13:00:00+00:00",
            "previous_status": "OPEN",
            "new_status": "IN_REVIEW",
            "analyst": "Parker",
            "note": "Synthetic history.",
        }
    ],
}

stream = io.StringIO()
with contextlib.redirect_stdout(stream):
    deltaaegis.print_ticket_evidence_payload(payload)

output = stream.getvalue()

required_fragments = [
    "DeltaAegis Ticket Evidence",
    "Subject:",
    "Workflow:",
    "Priority:",
    "Why:",
    "Next action:",
    "Evidence counts:",
    "Evidence Timeline",
    "Current Risk Evidence",
    "Alerts",
    "Delta Events",
    "MAC-Port Behavior",
    "Ticket History",
    "Synthetic CLI reason.",
    "Synthetic CLI next action.",
]

missing = [fragment for fragment in required_fragments if fragment not in output]
assert not missing, f"Missing CLI fragments: {missing}"

class DummyConnection:
    def close(self):
        pass

original_connect = deltaaegis.connect
original_payload = deltaaegis.dashboard_ticket_evidence_payload

try:
    deltaaegis.connect = lambda db: DummyConnection()
    deltaaegis.dashboard_ticket_evidence_payload = lambda connection, subject_key, scope=None, limit=10: payload
    args = SimpleNamespace(
        db=":memory:",
        subject_key=subject,
        scope="192.168.5.0/24",
        limit=5,
    )
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream):
        code = deltaaegis.command_ticket_evidence(args)
    assert code == 0
    assert "DeltaAegis Ticket Evidence" in stream.getvalue()
finally:
    deltaaegis.connect = original_connect
    deltaaegis.dashboard_ticket_evidence_payload = original_payload

print("[PASS] synthetic v0.20 ticket evidence CLI validated")
PY

pass "DeltaAegis v0.20 ticket evidence CLI validation passed"
