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

grep -q 'def normalize_ticket_status_filter' deltaaegis.py \
    || fail "ticket status filter normalizer missing"

grep -q 'def normalize_ticket_signal_filter' deltaaegis.py \
    || fail "ticket signal filter normalizer missing"

grep -q 'def filter_investigation_center_rows' deltaaegis.py \
    || fail "investigation center filter helper missing"

grep -q 'ticket_status=args.ticket_status' deltaaegis.py \
    || fail "CLI investigation-center status filter is not wired"

grep -q 'ticket_signal=args.ticket_signal' deltaaegis.py \
    || fail "CLI investigation-center signal filter is not wired"

grep -q -- '--ticket-status' deltaaegis.py \
    || fail "investigation-center --ticket-status parser option missing"

grep -q -- '--ticket-signal' deltaaegis.py \
    || fail "investigation-center --ticket-signal parser option missing"

python3 - <<'PY'
import tempfile
from pathlib import Path

import deltaaegis

rows = [
    {
        "subject_key": "mac:AA:AA:AA:AA:AA:01",
        "ticket_status": "OPEN",
        "ticket_signal_state": "ACTIONABLE",
    },
    {
        "subject_key": "mac:AA:AA:AA:AA:AA:02",
        "ticket_status": "IN_REVIEW",
        "ticket_signal_state": "MEANINGFUL_CHANGE",
    },
    {
        "subject_key": "mac:AA:AA:AA:AA:AA:03",
        "ticket_status": "RESOLVED",
        "ticket_signal_state": "BASELINE_CONTEXT",
    },
]

assert len(deltaaegis.filter_investigation_center_rows(rows)) == 3
assert [r["subject_key"] for r in deltaaegis.filter_investigation_center_rows(rows, ticket_status="OPEN")] == [
    "mac:AA:AA:AA:AA:AA:01"
]
assert [r["subject_key"] for r in deltaaegis.filter_investigation_center_rows(rows, ticket_status="in-review")] == [
    "mac:AA:AA:AA:AA:AA:02"
]
assert [r["subject_key"] for r in deltaaegis.filter_investigation_center_rows(rows, ticket_signal="baseline")] == [
    "mac:AA:AA:AA:AA:AA:03"
]
assert [r["subject_key"] for r in deltaaegis.filter_investigation_center_rows(rows, ticket_status="IN_REVIEW", ticket_signal="meaningful")] == [
    "mac:AA:AA:AA:AA:AA:02"
]

try:
    deltaaegis.normalize_ticket_signal_filter("bad-signal")
except deltaaegis.DeltaAegisError:
    pass
else:
    raise AssertionError("invalid ticket signal filter did not raise DeltaAegisError")

original_rows = deltaaegis.investigation_center_rows
original_tune = deltaaegis.tune_investigation_center_ticket_signals

def fake_rows(connection, limit=25, scope=None):
    return [
        {
            "subject_key": "mac:AA:AA:AA:AA:AA:01",
            "priority_level": "HIGH",
            "priority_score": 75,
            "ip_address": "192.168.5.10",
            "mac_address": "AA:AA:AA:AA:AA:01",
            "device_type": "Linux Server",
            "role": "Server",
            "classification": "Linux Server",
            "identity_confidence": "mac-backed",
            "triggers": ["CURRENT_RISK"],
            "primary_reason": "Actionable open item.",
            "recommended_action": "Review exposure.",
            "open_alerts": 1,
            "recent_events": 1,
            "port_behavior_count": 0,
            "current_finding_count": 1,
            "ticket_signal_state": "ACTIONABLE",
        },
        {
            "subject_key": "mac:AA:AA:AA:AA:AA:02",
            "priority_level": "MEDIUM",
            "priority_score": 55,
            "ip_address": "192.168.5.11",
            "mac_address": "AA:AA:AA:AA:AA:02",
            "device_type": "Printer",
            "role": "Printer",
            "classification": "Printer",
            "identity_confidence": "mac-backed",
            "triggers": ["PORT_BEHAVIOR"],
            "primary_reason": "Meaningful change.",
            "recommended_action": "Check expected printer ports.",
            "open_alerts": 0,
            "recent_events": 1,
            "port_behavior_count": 1,
            "current_finding_count": 0,
            "ticket_signal_state": "MEANINGFUL_CHANGE",
        },
    ]

def identity_tune(rows):
    return rows

try:
    deltaaegis.investigation_center_rows = fake_rows
    deltaaegis.tune_investigation_center_ticket_signals = identity_tune

    with tempfile.TemporaryDirectory() as tmp:
        conn = deltaaegis.connect(Path(tmp) / "filters.db")
        deltaaegis.set_ticket_state(
            conn,
            "mac:AA:AA:AA:AA:AA:02",
            "IN_REVIEW",
            analyst="Parker",
            note="Synthetic filter check.",
        )

        payload = deltaaegis.dashboard_investigation_center_payload(
            conn,
            limit=25,
            ticket_status="IN_REVIEW",
            ticket_signal="meaningful",
        )

        assert payload["available"] is True
        assert payload["filters"]["ticket_status"] == "IN_REVIEW"
        assert payload["filters"]["ticket_signal"] == "MEANINGFUL_CHANGE"
        assert payload["item_count"] == 1
        assert payload["items"][0]["subject_key"] == "mac:AA:AA:AA:AA:AA:02"
        assert payload["items"][0]["ticket_status"] == "IN_REVIEW"
finally:
    deltaaegis.investigation_center_rows = original_rows
    deltaaegis.tune_investigation_center_ticket_signals = original_tune

print("[PASS] synthetic v0.19 backend filters validated")
PY

pass "DeltaAegis v0.19 backend filter validation passed"
