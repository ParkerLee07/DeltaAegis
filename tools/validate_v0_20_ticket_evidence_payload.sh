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

python3 -m py_compile deltaaegis.py     || fail "deltaaegis.py does not compile"

grep -q 'def dashboard_ticket_evidence_payload' deltaaegis.py     || fail "ticket evidence payload helper missing"

grep -q 'def ticket_evidence_build_timeline' deltaaegis.py     || fail "ticket evidence timeline helper missing"

python3 - <<'PY'
import deltaaegis

subject = "mac:AA:AA:AA:AA:AA:01"

originals = {
    "build_risk_register": deltaaegis.build_risk_register,
    "dashboard_asset_detail_payload": deltaaegis.dashboard_asset_detail_payload,
    "dashboard_alerts_payload": deltaaegis.dashboard_alerts_payload,
    "dashboard_events_payload": deltaaegis.dashboard_events_payload,
    "dashboard_port_behavior_payload": deltaaegis.dashboard_port_behavior_payload,
    "dashboard_investigation_center_payload": deltaaegis.dashboard_investigation_center_payload,
    "get_ticket_state": deltaaegis.get_ticket_state,
    "list_ticket_history": deltaaegis.list_ticket_history,
}

def fake_risk(connection, limit, subject_filter=None, scope=None):
    return [
        {
            "subject_key": subject,
            "level": "HIGH",
            "score": 82,
            "reasons": ["Synthetic current risk reason."],
            "recommended_action": "Validate synthetic risk evidence.",
        }
    ]

def fake_asset_detail(connection, identifier, scope=None, limit=20):
    return {
        "available": True,
        "identifier": identifier,
        "asset": {
            "subject_key": subject,
            "ip_address": "192.168.5.10",
            "mac_address": "AA:AA:AA:AA:AA:01",
            "classification": "Linux Server",
        },
    }

def fake_alerts(connection, limit, scope=None):
    return [
        {
            "subject_key": subject,
            "severity": "HIGH",
            "summary": "Synthetic open alert.",
            "status": "OPEN",
            "last_seen_at": "2026-06-24T15:00:00+00:00",
        },
        {
            "subject_key": "mac:BB:BB:BB:BB:BB:02",
            "severity": "LOW",
            "summary": "Different subject.",
        },
    ]

def fake_events(connection, limit, scope=None):
    return [
        {
            "subject_key": subject,
            "event_type": "MONITORED_SERVICE_OPENED",
            "severity": "MEDIUM",
            "summary": "Synthetic delta event.",
            "created_at": "2026-06-24T14:00:00+00:00",
        }
    ]

def fake_port_behavior(connection, limit, scope=None, lookback=5):
    return [
        {
            "subject_key": subject,
            "behavior": "PORT_FLAPPING",
            "protocol": "tcp",
            "port": 22,
            "severity": "MEDIUM",
            "last_seen_at": "2026-06-24T13:00:00+00:00",
        }
    ]

def fake_investigation_center(connection, limit=25, scope=None, ticket_status=None, ticket_signal=None):
    return {
        "available": True,
        "items": [
            {
                "subject_key": subject,
                "priority_level": "HIGH",
                "priority_score": 88,
                "ticket_signal_state": "ACTIONABLE",
                "primary_reason": "Synthetic investigation queue reason.",
                "recommended_action": "Synthetic recommended next action.",
            }
        ],
    }

def fake_ticket_state(connection, subject_key):
    return {
        "ticket_key": deltaaegis.stable_ticket_key(subject_key),
        "ticket_status": "IN_REVIEW",
        "ticket_analyst": "Parker",
        "ticket_note": "Synthetic evidence payload test.",
        "ticket_updated_at": "2026-06-24T15:30:00+00:00",
    }

def fake_ticket_history(connection, subject_key, limit=25):
    return [
        {
            "ticket_key": deltaaegis.stable_ticket_key(subject_key),
            "previous_status": "OPEN",
            "new_status": "IN_REVIEW",
            "analyst": "Parker",
            "note": "Synthetic history entry.",
            "created_at": "2026-06-24T15:30:00+00:00",
        }
    ]

try:
    deltaaegis.build_risk_register = fake_risk
    deltaaegis.dashboard_asset_detail_payload = fake_asset_detail
    deltaaegis.dashboard_alerts_payload = fake_alerts
    deltaaegis.dashboard_events_payload = fake_events
    deltaaegis.dashboard_port_behavior_payload = fake_port_behavior
    deltaaegis.dashboard_investigation_center_payload = fake_investigation_center
    deltaaegis.get_ticket_state = fake_ticket_state
    deltaaegis.list_ticket_history = fake_ticket_history

    payload = deltaaegis.dashboard_ticket_evidence_payload(
        connection=None,
        subject_key=subject,
        scope="192.168.5.0/24",
        limit=5,
    )

    assert payload["available"] is True
    assert payload["subject_key"] == deltaaegis.stable_ticket_key(subject)
    assert payload["ticket_state"]["ticket_status"] == "IN_REVIEW"
    assert payload["summary"]["priority_score"] == 88
    assert payload["summary"]["alert_count"] == 1
    assert payload["summary"]["event_count"] == 1
    assert payload["summary"]["port_behavior_count"] == 1
    assert payload["summary"]["ticket_history_count"] == 1
    assert payload["summary"]["primary_reason"] == "Synthetic investigation queue reason."
    assert payload["summary"]["recommended_action"] == "Synthetic recommended next action."
    assert len(payload["risk"]) == 1
    assert len(payload["alerts"]) == 1
    assert len(payload["events"]) == 1
    assert len(payload["port_behavior"]) == 1
    assert len(payload["ticket_history"]) == 1
    assert {item["category"] for item in payload["timeline"]} >= {
        "current_risk",
        "alert",
        "delta_event",
        "port_behavior",
        "ticket_history",
    }

    missing = deltaaegis.dashboard_ticket_evidence_payload(
        connection=None,
        subject_key="",
        scope=None,
        limit=5,
    )
    assert missing["available"] is False
    assert "subject_key is required" in missing["error"]
finally:
    for name, value in originals.items():
        setattr(deltaaegis, name, value)

print("[PASS] synthetic v0.20 ticket evidence payload validated")
PY

for gate in \
    ./tools/validate_v0_19_backend_filters.sh \
    ./tools/validate_v0_19_dashboard_filters.sh \
    ./tools/validate_v0_19_workflow_counters.sh \
    ./tools/validate_v0_19_operator_views.sh
do
    if [ ! -x "$gate" ]; then
        fail "required v0.19 compatibility gate is missing or not executable: $gate"
    fi
    "$gate" || fail "v0.19 compatibility gate failed: $gate"
done

pass "DeltaAegis v0.20 ticket evidence payload validation passed"
