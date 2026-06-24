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

./tools/validate_v0_18_ticket_state_model.sh \
    || fail "v0.18 ticket state model validation failed"

grep -q 'CREATE TABLE IF NOT EXISTS investigation_ticket_history' deltaaegis.py \
    || fail "ticket history table schema is missing"

grep -q 'def add_ticket_history_event' deltaaegis.py \
    || fail "add_ticket_history_event helper is missing"

grep -q 'def list_ticket_history' deltaaegis.py \
    || fail "list_ticket_history helper is missing"

grep -q 'def command_ticket_history' deltaaegis.py \
    || fail "ticket-history CLI command is missing"

grep -q 'sub.add_parser("ticket-history"' deltaaegis.py \
    || fail "ticket-history CLI parser is missing"

grep -q 'add_ticket_history_event(' deltaaegis.py \
    || fail "set_ticket_state does not write ticket history"

python3 - <<'PY'
import tempfile
from pathlib import Path

import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "tickets.db"
    conn = deltaaegis.connect(db)

    first = deltaaegis.set_ticket_state(
        conn,
        "mac:AA:BB:CC:DD:EE:FF",
        "IN_REVIEW",
        analyst="Parker",
        note="Initial investigation.",
    )
    assert first["ticket_status"] == "IN_REVIEW"

    second = deltaaegis.set_ticket_state(
        conn,
        "mac:AA:BB:CC:DD:EE:FF",
        "RESOLVED",
        analyst="Parker",
        note="Expected service profile confirmed.",
    )
    assert second["ticket_status"] == "RESOLVED"

    history = deltaaegis.list_ticket_history(conn, "mac:aa:bb:cc:dd:ee:ff", limit=10)
    assert len(history) == 2

    assert history[0]["previous_status"] == "IN_REVIEW"
    assert history[0]["new_status"] == "RESOLVED"
    assert history[0]["analyst"] == "Parker"
    assert history[0]["note"] == "Expected service profile confirmed."

    assert history[1]["previous_status"] == "OPEN"
    assert history[1]["new_status"] == "IN_REVIEW"
    assert history[1]["note"] == "Initial investigation."

    other_history = deltaaegis.list_ticket_history(conn, "ip:192.168.5.10", limit=10)
    assert other_history == []

print("[PASS] synthetic ticket workflow history validated")
PY

TMP_DB="$(mktemp)"
python3 deltaaegis.py --db "$TMP_DB" ticket-status mac:AA:BB:CC:DD:EE:FF \
  --status IN_REVIEW \
  --analyst Parker \
  --note "CLI history smoke test." >/tmp/deltaaegis-ticket-history-status.txt \
    || fail "ticket-status CLI history smoke setup failed"

python3 deltaaegis.py --db "$TMP_DB" ticket-history mac:AA:BB:CC:DD:EE:FF >/tmp/deltaaegis-ticket-history.txt \
    || fail "ticket-history CLI smoke test failed"

grep -q 'OPEN -> IN_REVIEW' /tmp/deltaaegis-ticket-history.txt \
    || fail "ticket-history output did not include OPEN -> IN_REVIEW"

grep -q 'CLI history smoke test.' /tmp/deltaaegis-ticket-history.txt \
    || fail "ticket-history output did not include note"

rm -f "$TMP_DB" /tmp/deltaaegis-ticket-history-status.txt /tmp/deltaaegis-ticket-history.txt

pass "DeltaAegis v0.18 ticket workflow history validation passed"
