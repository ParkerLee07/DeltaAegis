#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

python3 - <<'PY_VALIDATE'
import tempfile
from pathlib import Path
import deltaaegis

fixture_base = Path.home() / "NetSniper" / "examples" / "deltaaegis-fixtures"
required = ["quick-complete", "balanced-complete", "accurate-complete", "failed-quality"]

missing = [name for name in required if not (fixture_base / name / "manifest.json").is_file()]
if missing:
    raise SystemExit(f"Missing NetSniper v2 fixture manifest(s): {missing}")

assert "netsniper-run-v3" in deltaaegis.NETSNIPER_SUPPORTED_SCHEMAS
assert "netsniper-run-v3" in deltaaegis.NETSNIPER_PROFILE_AWARE_SCHEMAS

with tempfile.TemporaryDirectory() as tmpdir:
    tmp = Path(tmpdir)

    for fixture_name in ["quick-complete", "balanced-complete", "accurate-complete"]:
        manifest_path = fixture_base / fixture_name / "manifest.json"
        connection = deltaaegis.connect(tmp / f"{fixture_name}.db")
        result = deltaaegis.ingest_manifest(
            connection,
            manifest_path,
            tmp / f"{fixture_name}.jsonl",
        )

        if "IMPORT" not in result:
            raise AssertionError(f"{fixture_name} did not import: {result}")

        row = connection.execute(
            """
            SELECT
                quality_status,
                manifest_schema_version,
                scan_profile,
                requested_profile,
                effective_profile,
                profile_fingerprint,
                bundle_quality_schema_version,
                bundle_deltaaegis_ready,
                bundle_quality_json
            FROM snapshots
            LIMIT 1
            """
        ).fetchone()

        if row is None:
            raise AssertionError(f"{fixture_name} did not create a snapshot row")

        expected_profile = fixture_name.split("-", 1)[0]
        expected = {
            "quality_status": "ACCEPTED",
            "manifest_schema_version": "netsniper-run-v3",
            "scan_profile": expected_profile,
            "requested_profile": expected_profile,
            "effective_profile": expected_profile,
            "bundle_quality_schema_version": "netsniper-bundle-quality-v1",
            "bundle_deltaaegis_ready": 1,
        }

        for key, value in expected.items():
            if row[key] != value:
                raise AssertionError(
                    f"{fixture_name} {key} mismatch: {row[key]!r} != {value!r}"
                )

        if not row["profile_fingerprint"]:
            raise AssertionError(f"{fixture_name} missing profile fingerprint")

        if "deltaaegis_ready" not in (row["bundle_quality_json"] or ""):
            raise AssertionError(f"{fixture_name} did not store bundle_quality_json")

    failed_manifest = fixture_base / "failed-quality" / "manifest.json"
    connection = deltaaegis.connect(tmp / "failed-quality.db")

    try:
        deltaaegis.ingest_manifest(connection, failed_manifest, tmp / "failed-quality.jsonl")
    except deltaaegis.DeltaAegisError as exc:
        message = str(exc).lower()
        accepted_rejection_reasons = (
            "deltaaegis_ready=false",
            "not deltaaegis-ready",
            "bundle is not finalized",
            "bundle status is not complete",
        )
        if not any(reason in message for reason in accepted_rejection_reasons):
            raise AssertionError(f"failed-quality rejected for the wrong reason: {exc}")
    else:
        raise AssertionError("failed-quality fixture was not rejected")

print("[PASS] DeltaAegis v0.32 NetSniper v2 ingest/storage compatibility checks passed")
PY_VALIDATE
