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

grep -q 'def append_report_port_behavior_section' deltaaegis.py \
    || fail "report port behavior section helper is missing"

grep -q 'report_port_behavior_rows = mac_port_behavior_rows' deltaaegis.py \
    || fail "command_report does not collect MAC-port behavior rows"

grep -q 'append_report_port_behavior_section(lines, report_port_behavior_rows)' deltaaegis.py \
    || fail "command_report does not append MAC-port behavior section"

grep -q 'MAC-Port Behavior Changes' deltaaegis.py \
    || fail "MAC-Port Behavior report heading is missing"

grep -q 'Port behavior API: `/api/port-behavior?limit=25&lookback=5`' deltaaegis.py \
    || fail "dashboard usage report note is missing"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

db="$tmp_dir/deltaaegis.db"
report="$tmp_dir/report.md"

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

def insert_asset(scan_id, ip):
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
            "Workstation", "LOW", 10, "Workstation", 80,
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
print("[PASS] synthetic report database created")
PY

python3 deltaaegis.py \
    --db "$db" \
    --reports-dir "$tmp_dir/reports" \
    report \
    --scope 192.168.5.0/24 \
    --output "$report" \
    > "$tmp_dir/report.out"

test -s "$report" \
    || fail "report file was not created"

grep -q '## MAC-Port Behavior Changes' "$report" \
    || fail "report missing MAC-Port Behavior Changes section"

grep -q 'UNEXPECTED_PORT_OPENED' "$report" \
    || fail "report missing UNEXPECTED_PORT_OPENED row"

grep -q 'tcp/23' "$report" \
    || fail "report missing tcp/23 row"

grep -q 'mac:aa:bb:cc:dd:ee:ff' "$report" \
    || fail "report missing MAC identity"

grep -q 'Port behavior API: `/api/port-behavior?limit=25&lookback=5`' "$report" \
    || fail "report missing Port Behavior API usage note"

pass "DeltaAegis v0.15 MAC-port behavior report validation passed"
