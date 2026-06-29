#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

ok() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

grep -Fq 'HOURLY_BALANCED_MONITORING_NAME = "Hourly Balanced Monitoring"' deltaaegis.py \
    || fail "missing hourly monitoring schedule name constant"

grep -Fq 'def dashboard_netsniper_hourly_monitoring_payload(' deltaaegis.py \
    || fail "missing hourly monitoring backend helper"

grep -Fq '"/api/netsniper/hourly-monitoring"' deltaaegis.py \
    || fail "missing hourly monitoring API route"

grep -Fq 'id="netsniper-hourly-monitoring-enable"' deltaaegis.py \
    || fail "missing hourly monitoring enable button"

grep -Fq 'id="netsniper-hourly-monitoring-disable"' deltaaegis.py \
    || fail "missing hourly monitoring disable button"

grep -Fq 'id="netsniper-hourly-monitoring-target"' deltaaegis.py \
    || fail "missing hourly monitoring target input"

grep -Fq 'async function setHourlyNetSniperMonitoring(enabled)' deltaaegis.py \
    || fail "missing hourly monitoring JS function"

grep -Fq 'postNetSniperSchedule("/api/netsniper/hourly-monitoring"' deltaaegis.py \
    || fail "dashboard does not call hourly monitoring API"

grep -Fq 'scan_profile="balanced"' deltaaegis.py \
    || fail "hourly monitoring helper does not force balanced profile"

grep -Fq 'cadence_minutes=60' deltaaegis.py \
    || fail "hourly monitoring helper does not force 60-minute cadence"

grep -Fq 'auto_ingest=True' deltaaegis.py \
    || fail "hourly monitoring helper does not force auto-ingest"

if grep -Fq '<option value="deep"' deltaaegis.py; then
    fail "dashboard exposes deep profile"
fi

python3 - <<'DELTA_31_4_PYTEST'
from pathlib import Path
import importlib.util
import sys
import tempfile

spec = importlib.util.spec_from_file_location("deltaaegis", "deltaaegis.py")
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = module
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory() as tmp:
    tmp_path = Path(tmp)
    connection = module.connect(tmp_path / "deltaaegis.db")

    enabled = module.dashboard_netsniper_schedule_action_payload(
        connection,
        "/api/netsniper/hourly-monitoring",
        {
            "target": "192.168.5.0/24",
            "enabled": True,
        },
        tmp_path / "events.jsonl",
    )
    connection.commit()

    assert enabled["ok"] is True
    assert enabled["action"] == "hourly_monitoring.enable"
    schedule = enabled["schedule"]
    assert schedule["name"] == "Hourly Balanced Monitoring"
    assert schedule["target"] == "192.168.5.0/24"
    assert schedule["scan_profile"] == "balanced"
    assert schedule["cadence_minutes"] == 60
    assert schedule["enabled"] is True
    assert schedule["auto_ingest"] is True

    refreshed = module.dashboard_netsniper_schedule_action_payload(
        connection,
        "/api/netsniper/hourly-monitoring",
        {
            "target": "192.168.6.0/24",
            "enabled": True,
        },
        tmp_path / "events.jsonl",
    )
    connection.commit()

    named = [
        row for row in module.dashboard_scan_schedules_payload(connection)
        if row["name"] == "Hourly Balanced Monitoring"
    ]
    assert len(named) == 1
    assert refreshed["schedule"]["target"] == "192.168.6.0/24"
    assert refreshed["schedule"]["scan_profile"] == "balanced"
    assert refreshed["schedule"]["cadence_minutes"] == 60
    assert refreshed["schedule"]["auto_ingest"] is True

    disabled = module.dashboard_netsniper_schedule_action_payload(
        connection,
        "/api/netsniper/hourly-monitoring",
        {
            "enabled": False,
        },
        tmp_path / "events.jsonl",
    )
    connection.commit()

    assert disabled["ok"] is True
    assert disabled["action"] == "hourly_monitoring.disable"
    assert disabled["schedule"]["enabled"] is False

    try:
        module.dashboard_netsniper_schedule_action_payload(
            connection,
            "/api/netsniper/hourly-monitoring",
            {
                "target": "8.8.8.0/24",
                "enabled": True,
            },
            tmp_path / "events.jsonl",
        )
    except module.DeltaAegisError:
        pass
    else:
        raise AssertionError("public target was accepted for hourly monitoring")

print("[PASS] v0.31 hourly monitoring python checks passed")
DELTA_31_4_PYTEST

ok "DeltaAegis v0.31 hourly monitoring validation passed"
