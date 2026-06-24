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

./tools/validate_v0_23_access_model.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.23 access model validation failed"

./tools/validate_v0_23_access_cli_tokens.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.23 access CLI/API token validation failed"

./tools/validate_v0_23_dashboard_db_token_auth.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.23 dashboard DB-token auth validation failed"

./tools/validate_v0_23_access_audit_visibility.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.23 access audit visibility validation failed"

./tools/validate_v0_23_release_metadata.sh \
    || fail "v0.23 release metadata validation failed"

./tools/validate_v0_23_backward_compatibility.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.23 backward compatibility validation failed"

pass "DeltaAegis v0.23 release validation passed"
