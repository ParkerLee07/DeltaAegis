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

./tools/validate_v0_19_dashboard_filters.sh \
    || fail "v0.19 dashboard filter validation failed"

grep -q 'def investigation_center_workflow_summary' deltaaegis.py \
    || fail "workflow summary helper missing"

grep -q 'def investigation_center_signal_summary' deltaaegis.py \
    || fail "signal summary helper missing"

grep -q '"total_item_count": total_item_count' deltaaegis.py \
    || fail "payload total_item_count missing"

grep -q '"workflow_summary": workflow_summary' deltaaegis.py \
    || fail "payload workflow_summary missing"

grep -q '"signal_summary": signal_summary' deltaaegis.py \
    || fail "payload signal_summary missing"

grep -q '"view_workflow_summary": investigation_center_workflow_summary(rows)' deltaaegis.py \
    || fail "payload view_workflow_summary missing"

grep -q '"view_signal_summary": investigation_center_signal_summary(rows)' deltaaegis.py \
    || fail "payload view_signal_summary missing"

grep -q 'Total Queue' deltaaegis.py \
    || fail "dashboard total queue metric missing"

grep -q 'Visible Items' deltaaegis.py \
    || fail "dashboard visible items metric missing"

grep -q 'workflowSummary.in_review' deltaaegis.py \
    || fail "dashboard in-review workflow summary metric missing"

grep -q 'signalSummary.actionable' deltaaegis.py \
    || fail "dashboard actionable signal summary metric missing"

python3 - <<'PY'
import tempfile
from pathlib import Path

import deltaaegis

rows = [
    {"ticket_status": "OPEN", "ticket_signal_state": "ACTIONABLE"},
    {"ticket_status": "IN_REVIEW", "ticket_signal_state": "MEANINGFUL_CHANGE"},
    {"ticket_status": "RESOLVED", "ticket_signal_state": "BASELINE_CONTEXT"},
    {"ticket_status": "SUPPRESSED", "ticket_signal_state": "ACTIONABLE"},
]

workflow = deltaaegis.investigation_center_workflow_summary(rows)
assert workflow == {
    "open": 1,
    "in_review": 1,
    "resolved": 1,
    "suppressed": 1,
}

signals = deltaaegis.investigation_center_signal_summary(rows)
assert signals == {
    "actionable": 2,
    "meaningful_change": 1,
    "baseline_context": 1,
}

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
        conn = deltaaegis.connect(Path(tmp) / "counters.db")
        deltaaegis.set_ticket_state(
            conn,
            "mac:AA:AA:AA:AA:AA:02",
            "RESOLVED",
            analyst="Parker",
            note="Synthetic counter check.",
        )

        payload = deltaaegis.dashboard_investigation_center_payload(
            conn,
            limit=25,
            ticket_status="RESOLVED",
        )

        assert payload["available"] is True
        assert payload["item_count"] == 1
        assert payload["total_item_count"] == 2
        assert payload["workflow_summary"]["open"] == 1
        assert payload["workflow_summary"]["resolved"] == 1
        assert payload["view_workflow_summary"]["resolved"] == 1
        assert payload["view_workflow_summary"]["open"] == 0
        assert payload["signal_summary"]["actionable"] == 1
        assert payload["signal_summary"]["meaningful_change"] == 1
finally:
    deltaaegis.investigation_center_rows = original_rows
    deltaaegis.tune_investigation_center_ticket_signals = original_tune

print("[PASS] synthetic v0.19 workflow counters validated")
PY

pass "DeltaAegis v0.19 workflow counter validation passed"
