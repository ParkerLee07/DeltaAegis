#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

echo "[INFO] Running DeltaAegis v0.33 release validation..."

./tools/validate_v0_33_trueaegis_storage.sh \
    || fail "v0.33 TrueAegis storage validator failed"

./tools/validate_v0_33_validation_dashboard.sh \
    || fail "v0.33 validation dashboard/API validator failed"

./tools/validate_v0_33_report_validation.sh \
    || fail "v0.33 report validation evidence validator failed"

./tools/validate_v0_33_release_metadata.sh \
    || fail "v0.33 release metadata validator failed"

# v0.32 functional compatibility checks retained without the old v0.32 metadata gate.
./tools/validate_v0_32_netsniper_v2_ingest.sh \
    || fail "v0.32 NetSniper v2 ingest/storage compatibility regression failed"

./tools/validate_v0_32_dashboard_v2_metadata.sh \
    || fail "v0.32 dashboard/API NetSniper v2 metadata regression failed"

# Metadata-safe v0.31 scheduled scan regressions.
./tools/validate_v0_31_scan_schedule_backend.sh \
    || fail "v0.31 scan schedule backend regression failed"

./tools/validate_v0_31_scan_result_capture.sh \
    || fail "v0.31 scan result capture regression failed"

python3 -m pytest tests/test_deltaaegis_v02.py \
    || fail "DeltaAegis pytest regression suite failed"

pass "DeltaAegis v0.33 release validation passed"
