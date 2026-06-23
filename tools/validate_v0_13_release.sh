#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BUNDLE_DIR="${1:-/home/parker/NetSniper/runs/20260623-123007}"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

[ -d "$BUNDLE_DIR" ] || fail "Bundle directory not found: $BUNDLE_DIR"

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

grep -q 'DeltaAegis v0.13.0 — Current-State SIEM Dashboard' README.md \
    || fail "README does not identify v0.13.0 as current release"

grep -q 'v0.13.0 — Current-State SIEM Dashboard' CHANGELOG.md \
    || fail "CHANGELOG does not mention v0.13.0"

grep -q '/api/current-state' README.md \
    || fail "README does not mention /api/current-state"

grep -q '/api/current-risk' README.md \
    || fail "README does not mention /api/current-risk"

grep -q 'Historical Risk Context' README.md \
    || fail "README does not mention Historical Risk Context"

grep -q 'def dashboard_current_state_payload' deltaaegis.py \
    || fail "current-state dashboard payload function missing"

grep -q 'def dashboard_current_risk_payload' deltaaegis.py \
    || fail "current-risk dashboard payload function missing"

grep -q 'route == "/api/current-state"' deltaaegis.py \
    || fail "/api/current-state route missing"

grep -q 'route == "/api/current-risk"' deltaaegis.py \
    || fail "/api/current-risk route missing"

for validator in \
    tools/validate_v0_13_full_inventory_ingest.sh \
    tools/validate_v0_13_current_state_payload.sh \
    tools/validate_v0_13_current_state_dashboard_ui.sh \
    tools/validate_v0_13_current_risk.sh
do
    [ -x "$validator" ] || fail "Missing or non-executable validator: $validator"
done

./tools/validate_v0_13_full_inventory_ingest.sh "$BUNDLE_DIR"
./tools/validate_v0_13_current_state_payload.sh "$BUNDLE_DIR"
./tools/validate_v0_13_current_state_dashboard_ui.sh
./tools/validate_v0_13_current_risk.sh "$BUNDLE_DIR"

pass "DeltaAegis v0.13 release validation passed"
