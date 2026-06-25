#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

help_text="$(python3 deltaaegis.py --help)"

printf '%s\n' "$help_text" | grep -Fq 'DeltaAegis v0.28.0' \
    || fail "CLI help does not advertise v0.28.0"

grep -Fq '## Current Release — v0.28.0' README.md \
    || fail "README does not advertise Current Release v0.28.0"

grep -Fq 'DeltaAegis v0.28.0 — Dashboard NetSniper Import Setup' README.md \
    || fail "README missing v0.28 release title"

grep -Fq 'Current feature baseline: **DeltaAegis v0.28.0 — Dashboard NetSniper Import Setup**.' README.md \
    || fail "README missing v0.28 current feature baseline"

grep -Fq 'v0.28 NetSniper Import' deltaaegis.py \
    || fail "dashboard release pill does not advertise v0.28"

grep -Fq 'DeltaAegis v0.28.0: Dashboard NetSniper Import Setup' deltaaegis.py \
    || fail "module docstring does not advertise v0.28"

if grep -Fq '## Current Release — v0.26.0' README.md; then
    fail "README still advertises v0.26.0 as the current release"
fi

current_section="$(sed -n '/## Current Release/,/^## /p' README.md)"
if printf '%s\n' "$current_section" | grep -Fq 'v0.24.0'; then
    fail "README current release section still contains stale v0.24.0 metadata"
fi

pass "DeltaAegis v0.28 release metadata validation passed"
