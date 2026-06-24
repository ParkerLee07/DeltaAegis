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

grep -q 'previous_state.get("ticket_status") == normalized_status' deltaaegis.py \
    || fail "set_ticket_state no-op guard is missing"

python3 - <<'PY'
import tempfile
from pathlib import Path

import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "noop.db"
    conn = deltaaegis.connect(db)

    first = deltaaegis.set_ticket_state(
        conn,
        "mac:AA:BB:CC:DD:EE:FF",
        "RESOLVED",
        analyst="Parker",
        note="First resolution.",
    )
    assert first["ticket_status"] == "RESOLVED"
    assert first["ticket_analyst"] == "Parker"
    assert first["ticket_note"] == "First resolution."

    first_history = deltaaegis.list_ticket_history(
        conn,
        "mac:aa:bb:cc:dd:ee:ff",
        limit=10,
    )
    assert len(first_history) == 1
    assert first_history[0]["previous_status"] == "OPEN"
    assert first_history[0]["new_status"] == "RESOLVED"

    second = deltaaegis.set_ticket_state(
        conn,
        "mac:AA:BB:CC:DD:EE:FF",
        "RESOLVED",
        analyst="dashboard",
        note="Repeated click should not overwrite useful analyst context.",
    )
    assert second["ticket_status"] == "RESOLVED"
    assert second["ticket_analyst"] == "Parker"
    assert second["ticket_note"] == "First resolution."
    assert second["ticket_updated_at"] == first["ticket_updated_at"]

    second_history = deltaaegis.list_ticket_history(
        conn,
        "mac:aa:bb:cc:dd:ee:ff",
        limit=10,
    )
    assert len(second_history) == 1

    third = deltaaegis.set_ticket_state(
        conn,
        "mac:AA:BB:CC:DD:EE:FF",
        "IN_REVIEW",
        analyst="Parker",
        note="Reopened for review.",
    )
    assert third["ticket_status"] == "IN_REVIEW"

    third_history = deltaaegis.list_ticket_history(
        conn,
        "mac:aa:bb:cc:dd:ee:ff",
        limit=10,
    )
    assert len(third_history) == 2
    assert third_history[0]["previous_status"] == "RESOLVED"
    assert third_history[0]["new_status"] == "IN_REVIEW"

print("[PASS] synthetic ticket no-op history guard validated")
PY

pass "DeltaAegis v0.18 ticket no-op guard validation passed"
