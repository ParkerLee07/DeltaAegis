#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

tools/validate_v0_34_validation_correlation_dashboard.sh
tools/validate_v0_34_validation_correlation_storage.sh

grep -Fq 'validation_correlations = []' deltaaegis.py
grep -Fq '"validation_correlations": validation_correlations' deltaaegis.py
grep -Fq '"validation_correlation_count": len(validation_correlations)' deltaaegis.py
grep -Fq 'TrueAegis Validation Correlations' deltaaegis.py

fixture="examples/trueaegis-fixtures/basic-validation/validation_results.json"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

db="$tmpdir/deltaaegis-v034-asset-detail.db"

python3 - "$db" "$fixture" <<'PY'
from pathlib import Path
import sys
import deltaaegis

db = Path(sys.argv[1])
fixture = Path(sys.argv[2])

connection = deltaaegis.connect(db)
now = deltaaegis.utc_now()
scan_id = "v034-asset-detail-scan"
scope = "192.168.4.0/24"
asset_key = "asset-linux"

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
        "/tmp/v034-asset-detail-manifest.json",
        scope,
        scope,
        "netsniper-test",
        "balanced",
        now,
        now,
        "COMPLETE",
        "ACCEPTED",
        "synthetic v0.34 asset-detail fixture",
        "success",
        1,
        0,
        1,
        1,
        1.0,
        1,
    ),
)

connection.execute(
    """
    INSERT INTO asset_lifecycle (
        network_scope,
        asset_key,
        identity_class,
        state,
        missing_count,
        current_ip,
        mac_address,
        vendor,
        hostname,
        first_seen_scan_id,
        last_seen_scan_id,
        first_seen_at,
        last_seen_at,
        removed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
    (
        scope,
        asset_key,
        "GLOBAL_MAC",
        "ACTIVE",
        0,
        "192.168.4.10",
        "02:00:00:00:00:10",
        "Synthetic",
        "asset-linux",
        scan_id,
        scan_id,
        now,
        now,
        None,
    ),
)

connection.execute(
    """
    INSERT INTO asset_observations (
        scan_id,
        asset_key,
        identity_confidence,
        identity_source,
        ip_address,
        mac_address,
        vendor,
        hostname,
        device_type,
        severity,
        score
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
    (
        scan_id,
        asset_key,
        "HIGH",
        "synthetic",
        "192.168.4.10",
        "02:00:00:00:00:10",
        "Synthetic",
        "asset-linux",
        "Linux Host",
        "INFO",
        0,
    ),
)

for port, service_name in [(22, "ssh"), (445, "microsoft-ds")]:
    connection.execute(
        """
        INSERT INTO service_observations (
            scan_id,
            asset_key,
            protocol,
            port,
            state,
            service_name,
            product,
            version
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

result = deltaaegis.import_trueaegis_validation_results(connection, fixture)
summary = deltaaegis.refresh_trueaegis_validation_correlations(connection)
connection.commit()

assert result["result_count"] == 5, result
assert summary["correlation_count"] == 2, summary

payload = deltaaegis.dashboard_asset_detail_payload(
    connection,
    asset_key,
    scope=scope,
    limit=20,
)

assert payload["found"] is True, payload
assert len(payload["services"]) == 2, payload
assert len(payload["validation_correlations"]) == 2, payload

statuses = {
    row["validation_status"]
    for row in payload["validation_correlations"]
}
assert statuses == {"REACHABLE", "PROTECTED"}, statuses

ports = {
    int(row["port"])
    for row in payload["validation_correlations"]
}
assert ports == {22, 445}, ports

review = payload["investigation"]["review_context"]
assert review["validation_correlation_count"] == 2, review

protected = [
    row
    for row in payload["validation_correlations"]
    if row["validation_status"] == "PROTECTED"
][0]
assert protected["finding_id"] == "SMB_EXPOSED", protected
assert protected["validated"] is True, protected
assert protected["safe"] is True, protected

print("[PASS] v0.34 asset detail validation correlation checks passed")
PY

echo "[PASS] DeltaAegis v0.34 asset detail validation correlation validation passed"
