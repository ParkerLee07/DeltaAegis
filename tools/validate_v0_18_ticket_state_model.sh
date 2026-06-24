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

grep -q 'CREATE TABLE IF NOT EXISTS investigation_ticket_state' deltaaegis.py \
    || fail "ticket state table schema is missing"

grep -q 'TICKET_WORKFLOW_STATUSES' deltaaegis.py \
    || fail "ticket workflow status constants are missing"

grep -q 'def stable_ticket_key' deltaaegis.py \
    || fail "stable ticket key helper is missing"

grep -q 'def get_ticket_state' deltaaegis.py \
    || fail "get_ticket_state helper is missing"

grep -q 'def set_ticket_state' deltaaegis.py \
    || fail "set_ticket_state helper is missing"

grep -q 'def apply_ticket_states_to_rows' deltaaegis.py \
    || fail "apply_ticket_states_to_rows helper is missing"

grep -q 'rows = apply_ticket_states_to_rows(connection, rows)' deltaaegis.py \
    || fail "investigation center payload does not attach ticket state"

grep -q 'sub.add_parser("ticket-status"' deltaaegis.py \
    || fail "ticket-status CLI parser is missing"

grep -q 'sub.add_parser("ticket-list"' deltaaegis.py \
    || fail "ticket-list CLI parser is missing"

python3 - <<'PY'
import tempfile
from pathlib import Path

import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    db = str(Path(tmp) / "tickets.db")
    conn = deltaaegis.connect(Path(db))

    default_state = deltaaegis.get_ticket_state(conn, "mac:AA:BB:CC:DD:EE:FF")
    assert default_state["ticket_key"] == "mac:aa:bb:cc:dd:ee:ff"
    assert default_state["ticket_status"] == "OPEN"
    assert default_state["ticket_updated_at"] is None

    updated = deltaaegis.set_ticket_state(
        conn,
        "mac:AA:BB:CC:DD:EE:FF",
        "IN_REVIEW",
        analyst="Parker",
        note="Checking owner and expected services.",
    )
    assert updated["ticket_status"] == "IN_REVIEW"
    assert updated["ticket_analyst"] == "Parker"
    assert updated["ticket_note"] == "Checking owner and expected services."
    assert updated["ticket_updated_at"]

    conn.close()
    conn = deltaaegis.connect(Path(db))

    persisted = deltaaegis.get_ticket_state(conn, "mac:aa:bb:cc:dd:ee:ff")
    assert persisted["ticket_status"] == "IN_REVIEW"
    assert persisted["ticket_analyst"] == "Parker"

    rows = [
        {"subject_key": "mac:AA:BB:CC:DD:EE:FF", "priority_score": 74},
        {"subject_key": "ip:192.168.5.10", "priority_score": 35},
    ]
    enriched = deltaaegis.apply_ticket_states_to_rows(conn, rows)
    assert enriched[0]["ticket_status"] == "IN_REVIEW"
    assert enriched[0]["ticket_key"] == "mac:aa:bb:cc:dd:ee:ff"
    assert enriched[1]["ticket_status"] == "OPEN"
    assert enriched[1]["ticket_key"] == "ip:192.168.5.10"

    resolved = deltaaegis.set_ticket_state(conn, "mac:aa:bb:cc:dd:ee:ff", "RESOLVED")
    assert resolved["ticket_status"] == "RESOLVED"
    assert resolved["ticket_resolved_at"]
    assert not resolved["ticket_suppressed_at"]

    suppressed = deltaaegis.set_ticket_state(conn, "ip:192.168.5.10", "SUPPRESSED", note="Known baseline item.")
    assert suppressed["ticket_status"] == "SUPPRESSED"
    assert suppressed["ticket_suppressed_at"]
    assert not suppressed["ticket_resolved_at"]

    listed = deltaaegis.list_ticket_states(conn, limit=10)
    assert len(listed) == 2

    suppressed_only = deltaaegis.list_ticket_states(conn, status="SUPPRESSED", limit=10)
    assert len(suppressed_only) == 1
    assert suppressed_only[0]["ticket_key"] == "ip:192.168.5.10"

    try:
        deltaaegis.set_ticket_state(conn, "mac:aa", "BAD_STATUS")
        raise AssertionError("invalid status was accepted")
    except deltaaegis.DeltaAegisError:
        pass

print("[PASS] synthetic ticket state persistence validated")
PY

TMP_DB="$(mktemp)"
python3 deltaaegis.py --db "$TMP_DB" ticket-status mac:AA:BB:CC:DD:EE:FF >/tmp/deltaaegis-ticket-status-default.txt \
    || fail "ticket-status default CLI smoke test failed"

grep -q 'Status:     OPEN' /tmp/deltaaegis-ticket-status-default.txt \
    || fail "ticket-status default output did not show OPEN"

rm -f "$TMP_DB" /tmp/deltaaegis-ticket-status-default.txt

./tools/validate_v0_17_release.sh /home/parker/NetSniper/runs/20260623-123007 \
    || fail "v0.17 release regression failed"

pass "DeltaAegis v0.18 ticket state model validation passed"
