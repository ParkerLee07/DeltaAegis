#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

fixture="examples/trueaegis-fixtures/basic-validation/validation_results.json"

grep -Fq 'CREATE TABLE IF NOT EXISTS validation_correlations' deltaaegis.py
grep -Fq 'def refresh_trueaegis_validation_correlations' deltaaegis.py
grep -Fq 'def dashboard_validation_correlations_payload' deltaaegis.py
grep -Fq 'trueaegis_validation_service_protocol' deltaaegis.py

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

db="$tmpdir/deltaaegis-v034-correlation.db"

python3 - "$db" "$fixture" <<'PY'
from pathlib import Path
import sys
import deltaaegis

db = Path(sys.argv[1])
fixture = Path(sys.argv[2])

connection = deltaaegis.connect(db)
now = deltaaegis.utc_now()
scan_id = "v034-correlation-scan"
scope = "192.168.4.0/24"

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
        "/tmp/v034-correlation-manifest.json",
        scope,
        scope,
        "netsniper-test",
        "balanced",
        now,
        now,
        "COMPLETE",
        "ACCEPTED",
        "synthetic v0.34 correlation fixture",
        "success",
        5,
        0,
        5,
        5,
        1.0,
        1,
    ),
)

services = [
    ("asset-router", "192.168.4.1", 80, "http"),
    ("asset-linux", "192.168.4.10", 22, "ssh"),
    ("asset-linux", "192.168.4.10", 445, "microsoft-ds"),
    ("asset-portainer", "192.168.4.107", 9000, "http-alt"),
    ("asset-printer", "192.168.4.124", 631, "ipp"),
]

seen_assets = set()

for asset_key, host, port, service_name in services:
    if asset_key not in seen_assets:
        connection.execute(
            """
            INSERT INTO asset_observations (
                scan_id, asset_key, identity_confidence, identity_source,
                ip_address, mac_address, vendor, hostname, device_type,
                severity, score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                asset_key,
                "HIGH",
                "synthetic",
                host,
                f"02:00:00:00:00:{len(seen_assets)+1:02x}",
                "Synthetic",
                asset_key,
                "Synthetic Host",
                "INFO",
                0,
            ),
        )
        seen_assets.add(asset_key)

    connection.execute(
        """
        INSERT INTO service_observations (
            scan_id, asset_key, protocol, port, state,
            service_name, product, version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            asset_key,
            "tcp",
            port,
            "open",
            service_name,
            "Synthetic",
            "1.0",
        ),
    )

import_result = deltaaegis.import_trueaegis_validation_results(connection, fixture)
summary = deltaaegis.refresh_trueaegis_validation_correlations(connection)
connection.commit()

assert import_result["result_count"] == 5, import_result
assert summary["latest_snapshot_count"] == 1, summary
assert summary["current_service_count"] == 5, summary
assert summary["observation_count"] == 5, summary
assert summary["correlation_count"] == 5, summary
assert summary["correlated_observation_count"] == 5, summary
assert summary["unmatched_observation_count"] == 0, summary

rows = [
    dict(row)
    for row in connection.execute(
        "SELECT * FROM validation_correlations ORDER BY host ASC, port ASC"
    )
]

assert len(rows) == 5, rows

statuses = {row["validation_status"] for row in rows}
assert statuses == {
    "CONFIRMED",
    "REACHABLE",
    "PROTECTED",
    "PROTOCOL_MISMATCH",
    "NOT_REACHABLE",
}, statuses

protected = [row for row in rows if row["validation_status"] == "PROTECTED"][0]
assert protected["host"] == "192.168.4.10", protected
assert protected["port"] == 445, protected
assert protected["service_protocol"] == "tcp", protected
assert protected["finding_id"] == "SMB_EXPOSED", protected
assert protected["validated"] == 1, protected
assert protected["confidence"] == "HIGH", protected

payload = deltaaegis.dashboard_validation_correlations_payload(connection, limit=25)
assert payload["schema_version"] == "deltaaegis-trueaegis-validation-correlations-v1"
assert payload["summary"]["correlation_count"] == 5, payload
assert payload["summary"]["asset_count"] == 4, payload
assert payload["count"] == 5, payload

filtered = deltaaegis.dashboard_validation_correlations_payload(
    connection,
    status="PROTECTED",
    limit=25,
)
assert filtered["count"] == 1, filtered
assert filtered["correlations"][0]["validation_status"] == "PROTECTED", filtered
assert filtered["correlations"][0]["validated"] is True, filtered

print("[PASS] v0.34 validation correlation storage checks passed")
PY

echo "[PASS] DeltaAegis v0.34 validation correlation storage validation passed"
