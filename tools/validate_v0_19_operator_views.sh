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

./tools/validate_v0_19_workflow_counters.sh \
    || fail "v0.19 workflow counter validation failed"

grep -q 'Filters: ' deltaaegis.py \
    || fail "CLI active filter line missing"

grep -q 'Visible queue items:' deltaaegis.py \
    || fail "CLI visible queue item line missing"

grep -q 'Workflow summary:' deltaaegis.py \
    || fail "CLI workflow summary line missing"

grep -q 'Signal summary:' deltaaegis.py \
    || fail "CLI signal summary line missing"

grep -q 'ticket_status=OPEN' deltaaegis.py \
    || fail "report dashboard usage does not mention ticket_status filter"

grep -q 'ticket_signal=ACTIONABLE' deltaaegis.py \
    || fail "report dashboard usage does not mention ticket_signal filter"

grep -q '### Investigation Queue Operator Summary' deltaaegis.py \
    || fail "report investigation operator summary missing"

grep -q 'Workflow states:' deltaaegis.py \
    || fail "report workflow states summary missing"

grep -q 'Signal labels:' deltaaegis.py \
    || fail "report signal labels summary missing"

grep -q '| Priority | Score | Workflow | Signal | Subject |' deltaaegis.py \
    || fail "report Investigation Center table does not include Workflow and Signal columns"

python3 - <<'PY'
import contextlib
import io

import deltaaegis

payload = {
    "available": True,
    "selected_scope": "192.168.5.0/24",
    "filters": {
        "ticket_status": "RESOLVED",
        "ticket_signal": "ALL",
    },
    "item_count": 1,
    "total_item_count": 3,
    "workflow_summary": {
        "open": 2,
        "in_review": 0,
        "resolved": 1,
        "suppressed": 0,
    },
    "signal_summary": {
        "actionable": 1,
        "meaningful_change": 1,
        "baseline_context": 1,
    },
    "items": [
        {
            "subject_key": "mac:AA:AA:AA:AA:AA:01",
            "priority_level": "HIGH",
            "priority_score": 74,
            "ip_address": "192.168.5.10",
            "mac_address": "AA:AA:AA:AA:AA:01",
            "device_type": "Linux Server",
            "role": "Server",
            "classification": "Linux Server",
            "identity_confidence": "mac-backed",
            "triggers": ["CURRENT_RISK"],
            "primary_reason": "Synthetic operator view check.",
            "recommended_action": "Validate CLI operator view.",
            "open_alerts": 0,
            "recent_events": 0,
            "port_behavior_count": 0,
            "current_finding_count": 1,
            "ticket_status": "RESOLVED",
            "ticket_signal_state": "ACTIONABLE",
            "ticket_analyst": "Parker",
            "ticket_updated_at": "2026-06-24T00:00:00+00:00",
            "ticket_note": "Synthetic validation note.",
        }
    ],
}

stream = io.StringIO()
with contextlib.redirect_stdout(stream):
    deltaaegis.print_investigation_center_rows(payload)

output = stream.getvalue()

assert "Filters: workflow=RESOLVED, signal=ALL" in output
assert "Visible queue items: 1 of 3" in output
assert "Workflow summary: OPEN=2, IN_REVIEW=0, RESOLVED=1, SUPPRESSED=0" in output
assert "Signal summary: ACTIONABLE=1, MEANINGFUL_CHANGE=1, BASELINE_CONTEXT=1" in output

lines = []
deltaaegis.append_report_investigation_center_section(lines, payload["items"])
report = "\n".join(lines)

assert "### Investigation Queue Operator Summary" in report
assert "Workflow states: OPEN=0, IN_REVIEW=0, RESOLVED=1, SUPPRESSED=0" in report
assert "Signal labels: ACTIONABLE=1, MEANINGFUL_CHANGE=0, BASELINE_CONTEXT=0" in report
assert "| Priority | Score | Workflow | Signal | Subject |" in report
assert "| HIGH | 74 | RESOLVED | ACTIONABLE |" in report

print("[PASS] synthetic v0.19 operator views validated")
PY

pass "DeltaAegis v0.19 operator view validation passed"
