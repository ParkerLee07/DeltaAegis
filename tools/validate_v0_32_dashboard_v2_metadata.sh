#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

python3 - <<'PY_VALIDATE'
import tempfile
from pathlib import Path

import deltaaegis

source = Path("deltaaegis.py").read_text(encoding="utf-8")

required_source_markers = [
    '"manifest_schema_version"',
    '"requested_profile"',
    '"effective_profile"',
    '"profile_contract"',
    '"profile_runtime_budget_seconds"',
    '"profile_host_timeout_seconds"',
    '"profile_duration_seconds"',
    '"profile_budget_exceeded"',
    '"bundle_quality_schema_version"',
    '"bundle_deltaaegis_ready"',
    "Requested profile",
    "Effective profile",
    "Runtime budget",
    "DeltaAegis ready",
]

missing_markers = [marker for marker in required_source_markers if marker not in source]
if missing_markers:
    raise AssertionError(f"Missing dashboard/API v0.32 markers: {missing_markers}")

fixture_base = Path.home() / "NetSniper" / "examples" / "deltaaegis-fixtures"
manifest_path = fixture_base / "balanced-complete" / "manifest.json"

if not manifest_path.is_file():
    raise SystemExit(f"Missing NetSniper v2 balanced fixture: {manifest_path}")

with tempfile.TemporaryDirectory() as tmpdir:
    tmp = Path(tmpdir)
    connection = deltaaegis.connect(tmp / "dashboard-v2.db")

    result = deltaaegis.ingest_manifest(
        connection,
        manifest_path,
        tmp / "events.jsonl",
    )

    if "IMPORT" not in result:
        raise AssertionError(f"balanced-complete did not import: {result}")

    payload = deltaaegis.dashboard_scan_context_payload(connection)
    latest = payload.get("latest_scan") or {}

    expected = {
        "manifest_schema_version": "netsniper-run-v3",
        "scan_profile": "balanced",
        "requested_profile": "balanced",
        "effective_profile": "balanced",
        "bundle_quality_schema_version": "netsniper-bundle-quality-v1",
        "bundle_deltaaegis_ready": 1,
        "bundle_deltaaegis_ready_label": "Ready",
    }

    for key, value in expected.items():
        if latest.get(key) != value:
            raise AssertionError(f"latest_scan {key} mismatch: {latest.get(key)!r} != {value!r}")

    if latest.get("telemetry_contract") != "netsniper-run-v3":
        raise AssertionError(f"telemetry_contract was not normalized: {latest.get('telemetry_contract')!r}")

    for key in (
        "profile_runtime_budget_seconds",
        "profile_host_timeout_seconds",
        "profile_duration_seconds",
    ):
        if key not in latest:
            raise AssertionError(f"latest_scan missing {key}")

    html = deltaaegis.dashboard_index_html()
    for label in (
        "Requested profile",
        "Effective profile",
        "Runtime budget",
        "DeltaAegis ready",
    ):
        if label not in html:
            raise AssertionError(f"dashboard HTML missing label: {label}")

print("[PASS] DeltaAegis v0.32 dashboard/API NetSniper v2 metadata checks passed")
PY_VALIDATE
