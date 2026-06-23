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

grep -q 'def current_port_behavior_risk_by_asset' deltaaegis.py \
    || fail "port behavior risk mapping helper is missing"

grep -q 'def port_behavior_risk_points' deltaaegis.py \
    || fail "port behavior risk scoring helper is missing"

grep -q 'port_behavior_points' deltaaegis.py \
    || fail "current risk records do not include port_behavior_points"

grep -q 'MAC-port behavior detected unexpected high-signal port' deltaaegis.py \
    || fail "unexpected high-signal port risk reason is missing"

grep -q 'Review MAC-port behavior changes' deltaaegis.py \
    || fail "recommended action for MAC-port behavior is missing"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

db="$tmp_dir/deltaaegis.db"

python3 - "$db" <<'PY'
import sys
from pathlib import Path
import deltaaegis

db = Path(sys.argv[1])
connection = deltaaegis.connect(db)

def insert_snapshot(scan_id, created_at):
    sql = (
        "INSERT INTO snapshots ("
        "scan_id, manifest_path, target, network_scope, scanner_version, "
        "scan_profile, created_at, imported_at, bundle_status, quality_status, "
        "quality_reason, xml_exit_status, hosts_up, hosts_down, hosts_total, "
        "mac_backed_assets, identity_coverage, is_accepted_baseline"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    connection.execute(
        sql,
        (
            scan_id, f"/tmp/{scan_id}/manifest.json", "192.168.5.0/24",
            "192.168.5.0/24", "NetSniper v1.8.0", "test",
            created_at, created_at, "COMPLETE", "ACCEPTED", "test accepted",
            "success", 1, 0, 1, 1, 1.0, 1,
        ),
    )

def insert_asset(scan_id, ip, score=10):
    sql = (
        "INSERT INTO asset_observations ("
        "scan_id, asset_key, identity_class, identity_confidence, identity_source, "
        "ip_address, mac_address, vendor, hostname, device_type, severity, score, "
        "classification_primary_type, classification_confidence, classification_decision, "
        "classification_siem_action, classification_contradiction_count"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    connection.execute(
        sql,
        (
            scan_id, "mac:aa:bb:cc:dd:ee:ff", "GLOBAL_MAC", "STRONG", "MAC",
            ip, "aa:bb:cc:dd:ee:ff", "Test Vendor", "test-device",
            "Workstation", "LOW", score, "Workstation", 80,
            "classified", "display_only", 0,
        ),
    )

def insert_service(scan_id, port):
    sql = (
        "INSERT INTO service_observations ("
        "scan_id, asset_key, protocol, port, state, service_name, product, version"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    connection.execute(
        sql,
        (
            scan_id, "mac:aa:bb:cc:dd:ee:ff", "tcp", port, "open",
            f"service-{port}", "test", "1.0",
        ),
    )

insert_snapshot("scan-001", "2026-06-23T10:00:00+00:00")
insert_asset("scan-001", "192.168.5.10")
insert_service("scan-001", 80)

insert_snapshot("scan-002", "2026-06-23T11:00:00+00:00")
insert_asset("scan-002", "192.168.5.11")
insert_service("scan-002", 80)
insert_service("scan-002", 23)

connection.commit()

rows = deltaaegis.build_current_risk_register(
    connection,
    limit=10,
    scope="192.168.5.0/24",
)

assert rows, rows

record = rows[0]
reasons = record.get("reasons", [])
reason_text = "\n".join(reasons)

assert record["subject_key"] == "mac:aa:bb:cc:dd:ee:ff", record
assert record.get("port_behavior_points") == 20, record
assert any(row.get("behavior") == "UNEXPECTED_PORT_OPENED" for row in record.get("port_behavior", [])), record
assert "MAC-port behavior detected unexpected high-signal port tcp/23: +20" in reason_text, reasons
assert any("Review MAC-port behavior changes" in action for action in record.get("recommended_actions", [])), record

print("[PASS] current risk integrates unexpected MAC-port behavior")
PY

pass "DeltaAegis v0.15 MAC-port behavior risk validation passed"
