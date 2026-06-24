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

# The dashboard-actions validator already walks the v0.18 dependency chain:
# workflow visibility -> ticket history -> ticket state model.
# Calling every v0.18 validator separately here re-runs the same v0.17/v0.16/v0.15/v0.14/v0.13/v0.12 regressions many times.
./tools/validate_v0_18_ticket_workflow_dashboard_actions.sh \
    || fail "v0.18 ticket workflow dashboard actions validation failed"

# Keep the no-op guard separate because it validates a distinct anti-noise behavior.
./tools/validate_v0_18_ticket_noop_guard.sh \
    || fail "v0.18 ticket no-op guard validation failed"

# Run the previous release regression once, not once per nested checkpoint.
if [[ -x ./tools/validate_v0_17_release.sh ]]; then
    if [[ ! -d "$NETSNIPER_RUN" ]]; then
        fail "NetSniper regression run directory not found: $NETSNIPER_RUN"
    fi

    ./tools/validate_v0_17_release.sh "$NETSNIPER_RUN" \
        || fail "v0.17 release regression failed"
fi

pass "DeltaAegis v0.18 release validation passed"
