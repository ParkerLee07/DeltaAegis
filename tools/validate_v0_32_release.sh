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

echo "[INFO] Running DeltaAegis v0.32 release validation..."

./tools/validate_v0_32_netsniper_v2_ingest.sh \
    || fail "v0.32 NetSniper v2 ingest/storage validator failed"

./tools/validate_v0_32_dashboard_v2_metadata.sh \
    || fail "v0.32 dashboard/API v2 metadata validator failed"

./tools/validate_v0_32_release_metadata.sh \
    || fail "v0.32 release metadata validator failed"

# Metadata-safe regression checks retained from v0.31 scheduled scan support.
./tools/validate_v0_31_scan_schedule_backend.sh \
    || fail "v0.31 scan schedule backend regression failed"

./tools/validate_v0_31_scan_result_capture.sh \
    || fail "v0.31 scan result capture regression failed"

python3 -m pytest tests/test_deltaaegis_v02.py \
    || fail "DeltaAegis pytest regression suite failed"

pass "DeltaAegis v0.32 release validation passed"
