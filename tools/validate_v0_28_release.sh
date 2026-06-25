#!/usr/bin/env bash
set -euo pipefail

NETSNIPER_RUN_DIR="${1:-/home/parker/NetSniper/runs/20260623-123007}"

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

echo "[INFO] Running fast v0.28 feature validators..."
./tools/validate_v0_28_netsniper_status_tab.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.28 NetSniper status tab validator failed"

./tools/validate_v0_28_netsniper_navigation.sh \
    || fail "v0.28 NetSniper navigation validator failed"

./tools/validate_v0_28_netsniper_import_latest.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.28 NetSniper import-latest validator failed"

grep -q '"/api/netsniper/import-latest", "workflow.write"' deltaaegis.py \
    || fail "NetSniper import-latest endpoint is not mapped to workflow.write"

grep -q 'Raw shell command execution is intentionally not exposed' deltaaegis.py \
    || fail "NetSniper page does not document the no-raw-shell boundary"

grep -q 'DELTAAEGIS_NETSNIPER_ROOT' deltaaegis.py \
    || fail "NetSniper root override support is missing"

if [[ ! -x "./tools/validate_v0_27_2_release.sh" ]]; then
    fail "inherited v0.27.2 release validator is missing"
fi

echo "[INFO] Running inherited v0.27.2 compatibility/security release gate..."
./tools/validate_v0_27_2_release.sh "$NETSNIPER_RUN_DIR" \
    || fail "inherited v0.27.2 release gate failed"

pass "DeltaAegis v0.28 release validation passed"
