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

grep -q 'def dashboard_port_behavior_payload' deltaaegis.py \
    || fail "dashboard port behavior payload helper is missing"

grep -q 'route == "/api/port-behavior"' deltaaegis.py \
    || fail "/api/port-behavior route is missing"

grep -q 'data-tab-target="port-behavior"' deltaaegis.py \
    || fail "Port Behavior tab button is missing"

grep -q 'data-tab-panel="port-behavior"' deltaaegis.py \
    || fail "Port Behavior tab panel is missing"

grep -q 'id="port-behavior-body"' deltaaegis.py \
    || fail "Port Behavior table body is missing"

grep -q 'function renderPortBehavior' deltaaegis.py \
    || fail "renderPortBehavior function is missing"

grep -q 'api(scopedPath("/api/port-behavior?limit=25&lookback=5"))' deltaaegis.py \
    || fail "dashboard does not fetch /api/port-behavior"

grep -q 'renderPortBehavior(portBehavior)' deltaaegis.py \
    || fail "dashboard does not render port behavior rows"

python3 - <<'PY'
import deltaaegis

html = deltaaegis.dashboard_index_html()

required = [
    "Port Behavior",
    "MAC-Port Behavior",
    "port-behavior-body",
    "function renderPortBehavior",
    "/api/port-behavior?limit=25&lookback=5",
    "Correlates MAC-backed device identity with open-port history",
]

for item in required:
    assert item in html, item

print("[PASS] Dashboard Port Behavior HTML validated")
PY

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

def insert_asset(scan_id, ip):
    sql = (
        "INSERT INTO asset_observations ("
        "scan_id, asset_key, identity_class, identity_confidence, "
        "identity_source, ip_address, mac_address, vendor, hostname, "
        "device_type, severity, score"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    connection.execute(
        sql,
        (
            scan_id, "mac:aa:bb:cc:dd:ee:ff", "GLOBAL_MAC", "STRONG",
            "MAC", ip, "aa:bb:cc:dd:ee:ff", "Test Vendor",
            "test-device", "Printer", "LOW", 10,
        ),
    )

def insert_service(scan_id, port):
    sql = (
        "INSERT INTO service_observations ("
        "scan_id, asset_key, protocol, port, state, "
        "service_name, product, version"
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

rows = deltaaegis.dashboard_port_behavior_payload(
    connection,
    limit=10,
    scope="192.168.5.0/24",
    lookback=5,
)

assert rows, rows
assert any(row["behavior"] == "UNEXPECTED_PORT_OPENED" for row in rows), rows
assert any(row["port_key"] == "tcp/23" for row in rows), rows

print("[PASS] Dashboard Port Behavior payload validated")
PY

pass "DeltaAegis v0.15 dashboard Port Behavior validation passed"
