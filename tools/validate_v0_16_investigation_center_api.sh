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

grep -q 'def dashboard_investigation_center_payload' deltaaegis.py \
    || fail "dashboard investigation center payload is missing"

grep -q 'def investigation_center_rows' deltaaegis.py \
    || fail "investigation center row builder is missing"

grep -q 'route == "/api/investigation-center"' deltaaegis.py \
    || fail "/api/investigation-center route is missing"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

db="$tmp_dir/deltaaegis.db"
events="$tmp_dir/events.jsonl"

python3 - "$db" "$events" <<'PY'
import sys
from pathlib import Path
import deltaaegis

db = Path(sys.argv[1])
events_path = Path(sys.argv[2])
connection = deltaaegis.connect(db)

asset_key = "mac:aa:bb:cc:dd:ee:ff"

def insert_snapshot(scan_id, created_at):
    connection.execute(
        """
        INSERT INTO snapshots (
            scan_id, manifest_path, target, network_scope, scanner_version,
            scan_profile, created_at, imported_at, bundle_status, quality_status,
            quality_reason, xml_exit_status, hosts_up, hosts_down, hosts_total,
            mac_backed_assets, identity_coverage, is_accepted_baseline
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            f"/tmp/{scan_id}/manifest.json",
            "192.168.5.0/24",
            "192.168.5.0/24",
            "NetSniper v1.8.0",
            "test",
            created_at,
            created_at,
            "COMPLETE",
            "ACCEPTED",
            "test accepted",
            "success",
            1,
            0,
            1,
            1,
            1.0,
            1,
        ),
    )

def insert_asset(scan_id, ip):
    connection.execute(
        """
        INSERT INTO asset_observations (
            scan_id, asset_key, identity_class, identity_confidence, identity_source,
            ip_address, mac_address, vendor, hostname, device_type, severity, score,
            classification_primary_type, classification_confidence, classification_decision,
            classification_siem_action, classification_contradiction_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            asset_key,
            "GLOBAL_MAC",
            "STRONG",
            "MAC",
            ip,
            "aa:bb:cc:dd:ee:ff",
            "Test Vendor",
            "test-device",
            "Workstation",
            "LOW",
            10,
            "Workstation",
            80,
            "classified",
            "display_only",
            0,
        ),
    )

def insert_service(scan_id, port):
    connection.execute(
        """
        INSERT INTO service_observations (
            scan_id, asset_key, protocol, port, state, service_name, product, version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            asset_key,
            "tcp",
            port,
            "open",
            f"service-{port}",
            "test",
            "1.0",
        ),
    )

insert_snapshot("scan-001", "2026-06-23T10:00:00+00:00")
insert_asset("scan-001", "192.168.5.10")
insert_service("scan-001", 80)

insert_snapshot("scan-002", "2026-06-23T11:00:00+00:00")
insert_asset("scan-002", "192.168.5.11")
insert_service("scan-002", 80)
insert_service("scan-002", 23)

deltaaegis.store_events(
    connection,
    "scan-002",
    "scan-001",
    [
        deltaaegis.event(
            "MONITORED_SERVICE_OPENED",
            "MEDIUM",
            asset_key,
            "Synthetic Telnet service opened for investigation center validation.",
            current_value={"protocol": "tcp", "port": 23},
        )
    ],
    events_path,
)

connection.commit()

payload = deltaaegis.dashboard_investigation_center_payload(
    connection,
    limit=10,
    scope="192.168.5.0/24",
)

assert payload["available"] is True, payload
assert payload["item_count"] >= 1, payload

items = payload["items"]
item = next((row for row in items if row["subject_key"] == asset_key), None)

assert item is not None, payload
assert item["priority_score"] > 0, item
assert item["priority_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}, item
assert "CURRENT_RISK" in item["triggers"], item
assert "PORT_BEHAVIOR" in item["triggers"], item
assert "OPEN_ALERT" in item["triggers"], item
assert "RECENT_EVENT" in item["triggers"], item
assert item["open_alerts"] >= 1, item
assert item["recent_events"] >= 1, item
assert item["port_behavior_count"] >= 1, item
assert item["primary_reason"], item
assert item["recommended_action"], item
assert payload["summary"]["with_open_alerts"] >= 1, payload
assert payload["summary"]["with_port_behavior"] >= 1, payload

print("[PASS] synthetic investigation center payload validated")
PY

pass "DeltaAegis v0.16 Investigation Command Center API validation passed"
