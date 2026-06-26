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

echo "[INFO] Running DeltaAegis v0.29 release validation..."

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

./tools/validate_v0_29_scan_start_foundation.sh \
    || fail "v0.29 scan-start foundation validator failed"

./tools/validate_v0_29_dashboard_scan_start_background.sh \
    || fail "v0.29 dashboard scan-start background validator failed"

./tools/validate_v0_29_netsniper_scan_ui.sh \
    || fail "v0.29 NetSniper scan UI validator failed"

./tools/validate_v0_29_release_metadata.sh \
    || fail "v0.29 release metadata validator failed"

# Preserve the v0.28 dashboard NetSniper behavior without requiring old
# "Current Release — v0.28.1" README metadata after v0.29 becomes current.
./tools/validate_v0_28_netsniper_status_tab.sh \
    || fail "v0.28 NetSniper status tab compatibility validator failed"

./tools/validate_v0_28_netsniper_navigation.sh \
    || fail "v0.28 NetSniper navigation compatibility validator failed"

./tools/validate_v0_28_netsniper_import_latest.sh /home/parker/NetSniper/runs/20260623-123007 \
    || fail "v0.28 NetSniper import-latest compatibility validator failed"

./tools/validate_v0_28_dashboard_db_defaults.sh \
    || fail "v0.28 dashboard DB default compatibility validator failed"

pass "DeltaAegis v0.29 release validation passed"
