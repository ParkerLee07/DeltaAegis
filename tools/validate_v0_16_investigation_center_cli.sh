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

./tools/validate_v0_16_investigation_center_api.sh \
    || fail "v0.16 investigation center API validator failed"

grep -q 'def command_investigation_center' deltaaegis.py \
    || fail "investigation-center CLI command function is missing"

grep -q 'def print_investigation_center_rows' deltaaegis.py \
    || fail "investigation-center CLI printer is missing"

grep -q 'sub.add_parser("investigation-center"' deltaaegis.py \
    || fail "investigation-center parser entry is missing"

grep -q 'args.command == "investigation-center"' deltaaegis.py \
    || fail "investigation-center command dispatch is missing"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

db="$tmp_dir/deltaaegis.db"
events="$tmp_dir/events.jsonl"
out="$tmp_dir/investigation-center.out"

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
            "Synthetic Telnet service opened for investigation center CLI validation.",
            current_value={"protocol": "tcp", "port": 23},
        )
    ],
    events_path,
)

connection.commit()
connection.close()
PY

python3 deltaaegis.py \
    --db "$db" \
    --events "$events" \
    investigation-center \
    --scope 192.168.5.0/24 \
    --limit 10 \
    > "$out"

grep -q 'DeltaAegis Investigation Command Center' "$out" \
    || fail "CLI output missing command center heading"

grep -q 'mac:aa:bb:cc:dd:ee:ff' "$out" \
    || fail "CLI output missing synthetic subject"

grep -q 'PORT_BEHAVIOR' "$out" \
    || fail "CLI output missing PORT_BEHAVIOR trigger"

grep -q 'OPEN_ALERT' "$out" \
    || fail "CLI output missing OPEN_ALERT trigger"

grep -q 'RECENT_EVENT' "$out" \
    || fail "CLI output missing RECENT_EVENT trigger"

grep -q 'Action:' "$out" \
    || fail "CLI output missing recommended action"

pass "DeltaAegis v0.16 investigation-center CLI validation passed"
