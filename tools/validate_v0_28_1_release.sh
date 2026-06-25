#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

if [[ $# -lt 1 ]]; then
    fail "Usage: $0 /path/to/known/NetSniper/run-or-runs-fixture"
fi

fixture_path="$1"

cd "$(dirname "$0")/.." || exit 1

echo "[INFO] Running v0.28.1 release validation..."

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

./tools/validate_v0_28_netsniper_status_tab.sh \
    || fail "v0.28 NetSniper status tab validator failed"

./tools/validate_v0_28_netsniper_navigation.sh \
    || fail "v0.28 NetSniper navigation validator failed"

./tools/validate_v0_28_netsniper_import_latest.sh "$fixture_path" \
    || fail "v0.28 NetSniper import-latest validator failed"

./tools/validate_v0_28_dashboard_db_defaults.sh \
    || fail "v0.28 dashboard DB defaults validator failed"

./tools/validate_v0_28_1_docs_uninstall.sh \
    || fail "v0.28.1 docs/uninstall validator failed"

./tools/validate_v0_28_1_release_metadata.sh \
    || fail "v0.28.1 release metadata validator failed"

pass "DeltaAegis v0.28.1 release validation passed"
