#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

grep -Fq 'DeltaAegis v0.25.0' deltaaegis.py \
    || fail "deltaaegis.py does not advertise v0.25.0"

grep -Fq 'Dashboard Session UX' deltaaegis.py \
    || fail "deltaaegis.py does not advertise Dashboard Session UX"

grep -Fq 'Current Release — v0.25.0' README.md \
    || fail "README.md missing v0.25.0 current release block"

grep -Fq 'DeltaAegis v0.25.0 — Dashboard Session UX' CHANGELOG.md \
    || fail "CHANGELOG.md missing v0.25.0 changelog entry"

for script in \
    tools/validate_v0_25_operator_session_page.sh \
    tools/validate_v0_25_dashboard_operator_link.sh \
    tools/validate_v0_25_operator_session_actions.sh \
    tools/validate_v0_25_backward_compatibility.sh \
    tools/validate_v0_25_release_metadata.sh \
    tools/validate_v0_25_release.sh
do
    test -x "$script" || fail "$script is missing or not executable"
done

pass "DeltaAegis v0.25 release metadata validation passed"
