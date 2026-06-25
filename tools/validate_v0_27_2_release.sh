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

python3 -m py_compile deltaaegis.py || fail "deltaaegis.py does not compile"

./tools/validate_v0_27_2_setup_page_cleanup.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.27.2 setup page cleanup gate failed"

pass "DeltaAegis v0.27.2 release validation passed"
