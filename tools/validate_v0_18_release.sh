#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

NETSNIPER_RUN="${1:-/home/parker/NetSniper/runs/20260623-123007}"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

pytest -q \
    || fail "pytest suite failed"

python3 - <<'PY'
import io
import contextlib
import tempfile
from pathlib import Path

import deltaaegis

# Static dashboard/API contract checks. These keep the v0.18 release gate
# from recursively running every older validator through checkpoint scripts.
source = Path("deltaaegis.py").read_text(encoding="utf-8")

required_fragments = [
    'route not in {"/api/investigate-asset", "/api/ticket-status"}',
    'if route == "/api/ticket-status":',
    '"ticket_state": state',
    '"investigation_center": investigation_center',
    '"ticket_state": ticket_state',
    'function ticketWorkflowLabel',
    'function ticketWorkflowBadge',
    'function ticketWorkflowActions',
    'function bindTicketWorkflowActions',
    'bindTicketWorkflowActions(ticketCards)',
    '<th>Workflow</th>',
    'Workflow Open',
    'previous_state.get("ticket_status") == normalized_status',
]

missing = [fragment for fragment in required_fragments if fragment not in source]
assert not missing, f"Missing v0.18 release contract fragments: {missing}"

with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "v018-release.db"
    conn = deltaaegis.connect(db)

    # Ticket state + history.
    first = deltaaegis.set_ticket_state(
        conn,
        "mac:AA:BB:CC:DD:EE:FF",
        "IN_REVIEW",
        analyst="Parker",
        note="Initial v0.18 release validation review.",
    )
    assert first["ticket_key"] == "mac:aa:bb:cc:dd:ee:ff"
    assert first["ticket_status"] == "IN_REVIEW"
    assert first["ticket_analyst"] == "Parker"

    history = deltaaegis.list_ticket_history(conn, "mac:aa:bb:cc:dd:ee:ff", limit=10)
    assert len(history) == 1
    assert history[0]["previous_status"] == "OPEN"
    assert history[0]["new_status"] == "IN_REVIEW"

    # No-op guard: repeated status must not create history noise or overwrite context.
    repeated = deltaaegis.set_ticket_state(
        conn,
        "mac:AA:BB:CC:DD:EE:FF",
        "IN_REVIEW",
        analyst="dashboard",
        note="Repeated no-op should not overwrite context.",
    )
    assert repeated["ticket_analyst"] == "Parker"
    assert repeated["ticket_note"] == "Initial v0.18 release validation review."
    assert repeated["ticket_updated_at"] == first["ticket_updated_at"]

    repeated_history = deltaaegis.list_ticket_history(conn, "mac:aa:bb:cc:dd:ee:ff", limit=10)
    assert len(repeated_history) == 1

    # Real transition still writes history.
    resolved = deltaaegis.set_ticket_state(
        conn,
        "mac:AA:BB:CC:DD:EE:FF",
        "RESOLVED",
        analyst="Parker",
        note="Resolved during v0.18 release validation.",
    )
    assert resolved["ticket_status"] == "RESOLVED"

    transition_history = deltaaegis.list_ticket_history(conn, "mac:aa:bb:cc:dd:ee:ff", limit=10)
    assert len(transition_history) == 2
    assert transition_history[0]["previous_status"] == "IN_REVIEW"
    assert transition_history[0]["new_status"] == "RESOLVED"

    # Investigation Center row enrichment + CLI workflow visibility.
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
            "primary_reason": "Synthetic v0.18 release validation ticket.",
            "recommended_action": "Validate the workflow state.",
            "open_alerts": 1,
            "recent_events": 2,
            "port_behavior_count": 0,
            "current_finding_count": 1,
        }
    ]

    enriched = deltaaegis.apply_ticket_states_to_rows(conn, rows)
    assert enriched[0]["ticket_status"] == "RESOLVED"
    assert enriched[0]["ticket_analyst"] == "Parker"
    assert enriched[0]["ticket_note"] == "Resolved during v0.18 release validation."

    stream = io.StringIO()
    with contextlib.redirect_stdout(stream):
        deltaaegis.print_investigation_center_rows(
            {
                "available": True,
                "selected_scope": "192.168.5.0/24",
                "items": enriched,
            }
        )

    output = stream.getvalue()
    assert "Workflow: RESOLVED" in output
    assert "Analyst:  Parker" in output
    assert "Resolved during v0.18 release validation." in output

print("[PASS] consolidated v0.18 workflow release contract validated")
PY

# Run the previous release regression once.
if [[ -x ./tools/validate_v0_17_release.sh ]]; then
    if [[ ! -d "$NETSNIPER_RUN" ]]; then
        fail "NetSniper regression run directory not found: $NETSNIPER_RUN"
    fi

    ./tools/validate_v0_17_release.sh "$NETSNIPER_RUN" \
        || fail "v0.17 release regression failed"
fi

pass "DeltaAegis v0.18 release validation passed"
