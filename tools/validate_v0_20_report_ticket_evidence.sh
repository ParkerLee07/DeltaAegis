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

./tools/validate_v0_20_ticket_evidence_cli.sh \
    || fail "v0.20 ticket evidence CLI validation failed"

grep -q 'def report_ticket_evidence_rows' deltaaegis.py \
    || fail "report ticket evidence collector missing"

grep -q 'def append_report_ticket_evidence_appendix' deltaaegis.py \
    || fail "report ticket evidence appendix helper missing"

grep -q 'report_ticket_evidence_payloads = report_ticket_evidence_rows' deltaaegis.py \
    || fail "command_report does not collect ticket evidence payloads"

grep -q 'append_report_ticket_evidence_appendix(lines, report_ticket_evidence_payloads)' deltaaegis.py \
    || fail "command_report does not append ticket evidence appendix"

grep -q '## Ticket Evidence Appendix' deltaaegis.py \
    || fail "Ticket Evidence Appendix heading missing"

grep -q 'Evidence Timeline Sample' deltaaegis.py \
    || fail "Evidence Timeline Sample report section missing"

python3 - <<'PY'
import deltaaegis

subject = "mac:AA:AA:AA:AA:AA:01"
stable_subject = deltaaegis.stable_ticket_key(subject)

synthetic_payload = {
    "available": True,
    "subject_key": stable_subject,
    "selected_subject": subject,
    "selected_scope": "192.168.5.0/24",
    "summary": {
        "subject_key": stable_subject,
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
        "primary_reason": "Synthetic report reason.",
        "recommended_action": "Synthetic report next action.",
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
            "summary": "Synthetic report timeline.",
        }
    ],
    "risk": [
        {
            "level": "HIGH",
            "score": 88,
            "subject_key": stable_subject,
            "reasons": ["Synthetic report reason."],
        }
    ],
    "events": [
        {
            "event_id": 10,
            "created_at": "2026-06-24T14:00:00+00:00",
            "severity": "MEDIUM",
            "event_type": "MONITORED_SERVICE_OPENED",
            "summary": "Synthetic report event.",
        }
    ],
    "port_behavior": [
        {
            "severity": "MEDIUM",
            "behavior": "PORT_FLAPPING",
            "protocol": "tcp",
            "port": 9100,
            "reason": "Synthetic report port behavior.",
        }
    ],
    "ticket_history": [
        {
            "created_at": "2026-06-24T13:00:00+00:00",
            "previous_status": "OPEN",
            "new_status": "IN_REVIEW",
            "analyst": "Parker",
            "note": "Synthetic report history.",
        }
    ],
}

original_payload = deltaaegis.dashboard_ticket_evidence_payload

try:
    calls = []

    def fake_payload(connection, subject_key, scope=None, limit=5):
        calls.append((subject_key, scope, limit))
        return synthetic_payload

    deltaaegis.dashboard_ticket_evidence_payload = fake_payload

    rows = deltaaegis.report_ticket_evidence_rows(
        connection=object(),
        investigation_rows=[
            {"subject_key": subject},
            {"subject_key": ""},
            {},
        ],
        scope="192.168.5.0/24",
        limit=3,
        evidence_limit=4,
    )

    assert len(rows) == 1
    assert calls == [(subject, "192.168.5.0/24", 4)]
finally:
    deltaaegis.dashboard_ticket_evidence_payload = original_payload

lines = []
deltaaegis.append_report_ticket_evidence_appendix(lines, [synthetic_payload])
report = "\n".join(lines)

required_fragments = [
    "## Ticket Evidence Appendix",
    "Ticket Evidence 1",
    stable_subject,
    "Workflow:",
    "Priority:",
    "Synthetic report reason.",
    "Synthetic report next action.",
    "Evidence Timeline Sample",
    "Current Risk Evidence",
    "Delta Events",
    "MAC-Port Behavior",
    "Ticket History",
    "Synthetic report timeline.",
    "Synthetic report port behavior.",
    "Synthetic report history.",
]

missing = [fragment for fragment in required_fragments if fragment not in report]
assert not missing, f"Missing report fragments: {missing}"

empty_lines = []
deltaaegis.append_report_ticket_evidence_appendix(empty_lines, [])
assert "No ticket evidence payloads were available" in "\n".join(empty_lines)

print("[PASS] synthetic v0.20 report ticket evidence appendix validated")
PY

pass "DeltaAegis v0.20 report ticket evidence appendix validation passed"
