#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

tools/validate_v0_34_asset_detail_validation_correlation.sh
tools/validate_v0_34_validation_correlation_dashboard.sh
tools/validate_v0_34_validation_correlation_storage.sh

grep -Fq 'def report_trueaegis_validation_correlation_summary' deltaaegis.py
grep -Fq 'def report_trueaegis_validation_correlation_rows' deltaaegis.py
grep -Fq 'def append_report_trueaegis_validation_correlation_section' deltaaegis.py
grep -Fq '## TrueAegis Validation Correlations' deltaaegis.py
grep -Fq 'append_report_trueaegis_validation_correlation_section' deltaaegis.py

fixture="examples/trueaegis-fixtures/basic-validation/validation_results.json"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

db="$tmpdir/deltaaegis-v034-report-correlation.db"

python3 - "$db" "$fixture" <<'PY'
from pathlib import Path
import sys
import deltaaegis

db = Path(sys.argv[1])
fixture = Path(sys.argv[2])

connection = deltaaegis.connect(db)
now = deltaaegis.utc_now()
scan_id = "v034-report-correlation-scan"
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
        "/tmp/v034-report-correlation-manifest.json",
        scope,
        scope,
        "netsniper-test",
        "balanced",
        now,
        now,
        "COMPLETE",
        "ACCEPTED",
        "synthetic v0.34 report correlation fixture",
        "success",
        2,
        0,
        2,
        2,
        1.0,
        1,
    ),
)

services = [
    ("asset-router", "192.168.4.1", 80, "http"),
    ("asset-linux", "192.168.4.10", 22, "ssh"),
    ("asset-linux", "192.168.4.10", 445, "microsoft-ds"),
]

seen_assets = set()

for asset_key, host, port, service_name in services:
    if asset_key not in seen_assets:
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
assert summary["correlation_count"] == 3, summary

report_summary = deltaaegis.report_trueaegis_validation_correlation_summary(connection)
report_rows = deltaaegis.report_trueaegis_validation_correlation_rows(connection, limit=10)
lines = []

deltaaegis.append_report_trueaegis_validation_correlation_section(
    lines,
    report_summary,
    report_rows,
)

body = "\n".join(lines)

assert report_summary["correlation_count"] == 3, report_summary
assert report_summary["asset_count"] == 2, report_summary
assert len(report_rows) == 3, report_rows
assert "## TrueAegis Validation Correlations" in body, body
assert "PROTECTED" in body, body
assert "SMB_EXPOSED" in body, body
assert "do not alter DeltaAegis risk scoring" in body, body

print("[PASS] v0.34 report validation correlation checks passed")
PY

echo "[PASS] DeltaAegis v0.34 report validation correlation validation passed"
