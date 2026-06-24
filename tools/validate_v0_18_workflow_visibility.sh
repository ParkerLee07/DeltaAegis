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

./tools/validate_v0_18_ticket_history.sh \
    || fail "v0.18 ticket history validation failed"

grep -q 'v0.18 investigation workflow visibility' deltaaegis.py \
    || fail "dashboard workflow visibility CSS marker is missing"

grep -q 'function ticketWorkflowLabel' deltaaegis.py \
    || fail "ticketWorkflowLabel helper is missing"

grep -q 'function ticketWorkflowBadge' deltaaegis.py \
    || fail "ticketWorkflowBadge helper is missing"

grep -q 'function ticketWorkflowMeta' deltaaegis.py \
    || fail "ticketWorkflowMeta helper is missing"

grep -q '<th>Workflow</th>' deltaaegis.py \
    || fail "ticket workflow table header is missing"

grep -q 'ticketWorkflowBadge(row)' deltaaegis.py \
    || fail "dashboard does not render ticket workflow badge"

grep -q 'Workflow Open' deltaaegis.py \
    || fail "workflow summary metric is missing"

grep -q 'Workflow: {workflow_status}' deltaaegis.py \
    || fail "investigation-center CLI does not print workflow status"

python3 - <<'PY'
import io
import contextlib
import tempfile
from pathlib import Path

import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "workflow.db"
    conn = deltaaegis.connect(db)

    deltaaegis.set_ticket_state(
        conn,
        "mac:AA:BB:CC:DD:EE:FF",
        "IN_REVIEW",
        analyst="Parker",
        note="Workflow visibility synthetic test.",
    )

    rows = [
        {
            "subject_key": "mac:AA:BB:CC:DD:EE:FF",
            "priority_level": "HIGH",
            "priority_score": 74,
            "ip_address": "192.168.5.10",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "device_type": "Linux Server",
            "role": "Server",
            "classification": "Linux Server",
            "identity_confidence": "mac-backed",
            "triggers": ["CURRENT_RISK"],
            "primary_reason": "Synthetic high-priority workflow test.",
            "recommended_action": "Verify expected exposure.",
            "open_alerts": 1,
            "recent_events": 2,
            "port_behavior_count": 0,
            "current_finding_count": 1,
        }
    ]

    enriched = deltaaegis.apply_ticket_states_to_rows(conn, rows)
    assert enriched[0]["ticket_status"] == "IN_REVIEW"
    assert enriched[0]["ticket_analyst"] == "Parker"
    assert enriched[0]["ticket_note"] == "Workflow visibility synthetic test."

    payload = {
        "available": True,
        "selected_scope": "192.168.5.0/24",
        "items": enriched,
    }

    stream = io.StringIO()
    with contextlib.redirect_stdout(stream):
        deltaaegis.print_investigation_center_rows(payload)

    output = stream.getvalue()
    assert "Workflow: IN_REVIEW" in output
    assert "Analyst:  Parker" in output
    assert "Workflow visibility synthetic test." in output

print("[PASS] synthetic workflow visibility output validated")
PY

pass "DeltaAegis v0.18 workflow visibility validation passed"
