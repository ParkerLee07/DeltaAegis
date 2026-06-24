#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

NETSNIPER_RUN_DIR="${1:-/home/parker/NetSniper/runs/20260623-123007}"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

./tools/validate_v0_25_operator_session_page.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.25 operator session page validation failed"

./tools/validate_v0_25_dashboard_operator_link.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.25 dashboard operator link validation failed"

./tools/validate_v0_25_operator_session_actions.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.25 operator session actions validation failed"

./tools/validate_v0_25_backward_compatibility.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.25 backward compatibility validation failed"

./tools/validate_v0_25_release_metadata.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.25 release metadata validation failed"

pass "DeltaAegis v0.25 release validation passed"
