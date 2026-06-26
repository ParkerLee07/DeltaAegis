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

echo "[INFO] Running DeltaAegis v0.30 release validation..."

./tools/validate_v0_30_scan_profile_backend.sh \
    || fail "v0.30 scan profile backend validator failed"

./tools/validate_v0_30_dashboard_scan_profile_ui.sh \
    || fail "v0.30 dashboard scan profile UI validator failed"

./tools/validate_v0_30_release_metadata.sh \
    || fail "v0.30 release metadata validator failed"

# Metadata-safe v0.29 regression checks.
# Do not call validate_v0_29_release.sh here because it correctly expects
# README current-release metadata to remain v0.29.0.
./tools/validate_v0_29_scan_start_foundation.sh \
    || fail "v0.29 scan-start foundation regression failed"

./tools/validate_v0_29_dashboard_scan_start_background.sh \
    || fail "v0.29 dashboard scan-start background regression failed"

./tools/validate_v0_29_netsniper_scan_ui.sh \
    || fail "v0.29 NetSniper scan UI regression failed"

pass "DeltaAegis v0.30 release validation passed"
