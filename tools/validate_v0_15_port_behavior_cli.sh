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

grep -q 'def mac_port_behavior_rows' deltaaegis.py \
    || fail "MAC-port behavior row builder is missing"

grep -q 'def command_port_behavior' deltaaegis.py \
    || fail "port-behavior CLI command is missing"

grep -q 'sub.add_parser("port-behavior"' deltaaegis.py \
    || fail "port-behavior parser registration is missing"

grep -q 'if args.command == "port-behavior": return command_port_behavior(args)' deltaaegis.py \
    || fail "port-behavior main dispatch is missing"

grep -q 'UNEXPECTED_PORT_OPENED' deltaaegis.py \
    || fail "unexpected port behavior label is missing"

grep -q 'PORT_FLAPPING' deltaaegis.py \
    || fail "flapping port behavior label is missing"

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
    connection.execute(
        """
        INSERT INTO snapshots (
            scan_id, manifest_path, target, network_scope, scanner_version,
            scan_profile, created_at, imported_at, bundle_status, quality_status,
            quality_reason, xml_exit_status, hosts_up, hosts_down, hosts_total,
            mac_backed_assets, identity_coverage, is_accepted_baseline
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id, f"/tmp/{scan_id}/manifest.json", "192.168.5.0/24",
            "192.168.5.0/24", "NetSniper v1.8.0", "test",
            created_at, created_at, "COMPLETE", "ACCEPTED", "test accepted",
            "success", 2, 0, 2, 1, 1.0, 1,
        ),
    )

def insert_mac_asset(scan_id, ip):
    connection.execute(
        """
        INSERT INTO asset_observations (
            scan_id, asset_key, identity_class, identity_confidence,
            identity_source, ip_address, mac_address, vendor, hostname,
            device_type, severity, score
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id, "mac:aa:bb:cc:dd:ee:ff", "GLOBAL_MAC", "STRONG",
            "MAC", ip, "aa:bb:cc:dd:ee:ff", "Test Vendor",
            "test-device", "Printer", "LOW", 10,
        ),
    )

def insert_ip_only_asset(scan_id):
    connection.execute(
        """
        INSERT INTO asset_observations (
            scan_id, asset_key, identity_class, identity_confidence,
            identity_source, ip_address, device_type, severity, score
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id, "ip:192.168.5.250", "IP_ONLY", "WEAK", "IP_ONLY",
            "192.168.5.250", "Unknown", "LOW", 5,
        ),
    )

def insert_service(scan_id, asset_key, port):
    connection.execute(
        """
        INSERT INTO service_observations (
            scan_id, asset_key, protocol, port, state,
            service_name, product, version
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id, asset_key, "tcp", port, "open",
            f"service-{port}", "test", "1.0",
        ),
    )

insert_snapshot("scan-001", "2026-06-23T10:00:00+00:00")
insert_mac_asset("scan-001", "192.168.5.10")
insert_service("scan-001", "mac:aa:bb:cc:dd:ee:ff", 80)
insert_service("scan-001", "mac:aa:bb:cc:dd:ee:ff", 445)
insert_ip_only_asset("scan-001")
insert_service("scan-001", "ip:192.168.5.250", 23)

insert_snapshot("scan-002", "2026-06-23T11:00:00+00:00")
insert_mac_asset("scan-002", "192.168.5.11")
insert_service("scan-002", "mac:aa:bb:cc:dd:ee:ff", 80)

insert_snapshot("scan-003", "2026-06-23T12:00:00+00:00")
insert_mac_asset("scan-003", "192.168.5.12")
insert_service("scan-003", "mac:aa:bb:cc:dd:ee:ff", 80)
insert_service("scan-003", "mac:aa:bb:cc:dd:ee:ff", 23)
insert_service("scan-003", "mac:aa:bb:cc:dd:ee:ff", 445)

connection.commit()

rows = deltaaegis.mac_port_behavior_rows(
    connection,
    limit=20,
    scope="192.168.5.0/24",
    lookback=5,
)

behaviors = {(row["behavior"], row["port_key"]) for row in rows}

assert ("UNEXPECTED_PORT_OPENED", "tcp/23") in behaviors, rows
assert ("PORT_FLAPPING", "tcp/445") in behaviors, rows

unexpected = [
    row for row in rows
    if row["behavior"] == "UNEXPECTED_PORT_OPENED"
    and row["port_key"] == "tcp/23"
][0]

assert unexpected["severity"] == "HIGH", unexpected
assert unexpected["mac_identity"] == "mac:aa:bb:cc:dd:ee:ff", unexpected
assert "not observed" in unexpected["reason"], unexpected
assert all(row["mac_identity"] != "ip:192.168.5.250" for row in rows), rows

print("[PASS] synthetic MAC-port behavior detection validated")
PY

python3 deltaaegis.py --db "$db" port-behavior --scope 192.168.5.0/24 --lookback 5 \
    > "$tmp_dir/port-behavior.out"

grep -q 'UNEXPECTED_PORT_OPENED' "$tmp_dir/port-behavior.out" \
    || fail "CLI output did not include UNEXPECTED_PORT_OPENED"

grep -q 'PORT_FLAPPING' "$tmp_dir/port-behavior.out" \
    || fail "CLI output did not include PORT_FLAPPING"

grep -q 'tcp/23' "$tmp_dir/port-behavior.out" \
    || fail "CLI output did not include tcp/23"

grep -q 'mac:aa:bb:cc:dd:ee:ff' "$tmp_dir/port-behavior.out" \
    || fail "CLI output did not include MAC identity"

pass "DeltaAegis v0.15 MAC-port behavior CLI validation passed"
