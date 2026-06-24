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

./tools/validate_v0_19_backend_filters.sh \
    || fail "v0.19 backend filters failed"

./tools/validate_v0_19_dashboard_filters.sh \
    || fail "v0.19 dashboard filters failed"

./tools/validate_v0_19_workflow_counters.sh \
    || fail "v0.19 workflow counters failed"

./tools/validate_v0_19_operator_views.sh \
    || fail "v0.19 operator views failed"

./tools/validate_v0_18_release.sh "$NETSNIPER_RUN" \
    || fail "v0.18 regression failed"

pass "DeltaAegis v0.19 release validation passed"
