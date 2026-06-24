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

./tools/validate_v0_24_session_model.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.24 session model validation failed"

./tools/validate_v0_24_login_logout_routes.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.24 login/logout route validation failed"

./tools/validate_v0_24_api_session.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.24 /api/session validation failed"

./tools/validate_v0_24_backward_compatibility.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.24 backward compatibility validation failed"

./tools/validate_v0_24_release_metadata.sh \
    || fail "v0.24 release metadata validation failed"

pass "DeltaAegis v0.24 release validation passed"
