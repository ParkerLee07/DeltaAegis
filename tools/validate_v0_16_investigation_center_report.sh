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

./tools/validate_v0_16_investigation_center_cli.sh \
    || fail "v0.16 investigation center CLI validator failed"

grep -q 'def append_report_investigation_center_section' deltaaegis.py \
    || fail "report Investigation Command Center section helper is missing"

grep -q 'report_investigation_center_rows = investigation_center_rows' deltaaegis.py \
    || fail "report command does not build investigation center rows"

grep -q 'append_report_investigation_center_section(lines, report_investigation_center_rows)' deltaaegis.py \
    || fail "report command does not append investigation center section"

grep -q 'Investigation Center API: `/api/investigation-center?limit=25`' deltaaegis.py \
    || fail "dashboard/API usage notes do not mention investigation center API"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

db="$tmp_dir/deltaaegis.db"
events="$tmp_dir/events.jsonl"
report="$tmp_dir/report.md"

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
            "HIGH",
            20,
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
            "Synthetic Telnet service opened for investigation center report validation.",
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
    --reports-dir "$tmp_dir/reports" \
    report \
    --scope 192.168.5.0/24 \
    --risk-limit 10 \
    --asset-limit 10 \
    --output "$report" \
    >/dev/null

grep -q '## Investigation Command Center' "$report" \
    || fail "report missing Investigation Command Center section"

grep -q 'mac:aa:bb:cc:dd:ee:ff' "$report" \
    || fail "report missing synthetic investigation subject"

grep -q 'PORT_BEHAVIOR' "$report" \
    || fail "report missing PORT_BEHAVIOR trigger"

grep -q 'OPEN_ALERT' "$report" \
    || fail "report missing OPEN_ALERT trigger"

grep -q 'RECENT_EVENT' "$report" \
    || fail "report missing RECENT_EVENT trigger"

grep -q 'Recommended Action' "$report" \
    || fail "report missing recommended action column"

grep -q 'Investigation Center API: `/api/investigation-center?limit=25`' "$report" \
    || fail "report missing Investigation Center API usage note"

pass "DeltaAegis v0.16 Investigation Command Center report validation passed"
