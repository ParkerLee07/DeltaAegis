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

./tools/validate_readme_current.sh \
    || fail "README current-release metadata validation failed"

grep -q 'v0.19.0 — Workflow Filters and Operator Views' CHANGELOG.md \
    || fail "CHANGELOG does not mention v0.19.0"

grep -q 'DeltaAegis v0.19.0' deltaaegis.py \
    || fail "deltaaegis.py metadata does not mention v0.19.0"

./tools/validate_v0_19_backend_filters.sh \
    || fail "v0.19 backend filters failed"

./tools/validate_v0_19_dashboard_filters.sh \
    || fail "v0.19 dashboard filters failed"

./tools/validate_v0_19_workflow_counters.sh \
    || fail "v0.19 workflow counters failed"

./tools/validate_v0_19_operator_views.sh \
    || fail "v0.19 operator views failed"

pass "DeltaAegis v0.19 release validation passed"
