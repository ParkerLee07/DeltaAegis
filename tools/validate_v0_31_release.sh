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

echo "[INFO] Running DeltaAegis v0.31 release validation..."

./tools/validate_v0_31_scan_schedule_backend.sh \
    || fail "v0.31 scan schedule backend validator failed"

./tools/validate_v0_31_schedule_runner.sh \
    || fail "v0.31 due schedule runner validator failed"

./tools/validate_v0_31_dashboard_schedule_api.sh \
    || fail "v0.31 dashboard schedule API validator failed"

./tools/validate_v0_31_dashboard_schedule_ui.sh \
    || fail "v0.31 dashboard schedule UI validator failed"

./tools/validate_v0_31_hourly_monitoring.sh \
    || fail "v0.31 hourly monitoring validator failed"

./tools/validate_v0_31_dashboard_schedule_worker.sh \
    || fail "v0.31 dashboard schedule worker validator failed"

./tools/validate_v0_31_schedule_failure_persistence.sh \
    || fail "v0.31 scheduled scan failure persistence validator failed"

./tools/validate_v0_31_scan_result_capture.sh \
    || fail "v0.31 scan result capture validator failed"

./tools/validate_v0_31_release_metadata.sh \
    || fail "v0.31 release metadata validator failed"

# Metadata-safe v0.30 regression checks. Do not call
# validate_v0_30_release.sh here because it correctly expects README current
# release metadata to remain v0.30.0.
./tools/validate_v0_30_scan_profile_backend.sh \
    || fail "v0.30 scan profile backend regression failed"

./tools/validate_v0_30_dashboard_scan_profile_ui.sh \
    || fail "v0.30 dashboard scan profile UI regression failed"

# Metadata-safe v0.29 guarded scan regressions retained through v0.31.
./tools/validate_v0_29_scan_start_foundation.sh \
    || fail "v0.29 scan-start foundation regression failed"

./tools/validate_v0_29_dashboard_scan_start_background.sh \
    || fail "v0.29 dashboard scan-start background regression failed"

./tools/validate_v0_29_netsniper_scan_ui.sh \
    || fail "v0.29 NetSniper scan UI regression failed"

pass "DeltaAegis v0.31 release validation passed"
