#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

NETSNIPER_RUN="${1:-/home/parker/NetSniper/runs/20260623-123007}"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

pytest -q \
    || fail "pytest suite failed"

./tools/validate_v0_18_ticket_state_model.sh \
    || fail "v0.18 ticket state model validation failed"

./tools/validate_v0_18_ticket_history.sh \
    || fail "v0.18 ticket history validation failed"

./tools/validate_v0_18_workflow_visibility.sh \
    || fail "v0.18 workflow visibility validation failed"

./tools/validate_v0_18_ticket_workflow_dashboard_actions.sh \
    || fail "v0.18 ticket workflow dashboard actions validation failed"

./tools/validate_v0_18_ticket_noop_guard.sh \
    || fail "v0.18 ticket no-op guard validation failed"

if [[ -x ./tools/validate_v0_17_release.sh ]]; then
    if [[ ! -d "$NETSNIPER_RUN" ]]; then
        fail "NetSniper regression run directory not found: $NETSNIPER_RUN"
    fi

    ./tools/validate_v0_17_release.sh "$NETSNIPER_RUN" \
        || fail "v0.17 release regression failed"
fi

pass "DeltaAegis v0.18 release validation passed"
