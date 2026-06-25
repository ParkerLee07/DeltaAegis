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

grep -Fq 'Current Release — v0.28.1' README.md \
    || fail "README does not advertise v0.28.1 as current release"

grep -Fq 'DeltaAegis v0.28.1 — README and Uninstall Cleanup' README.md \
    || fail "README does not advertise v0.28.1 release title"

grep -Fq 'Current feature baseline: **DeltaAegis v0.28.0 — Dashboard NetSniper Import Setup**.' README.md \
    || fail "README does not preserve v0.28.0 feature baseline"

grep -Fq 'data/deltaaegis.db' README.md \
    || fail "README does not document installed dashboard database path"

grep -Fq 'does not expose arbitrary shell command execution' README.md \
    || fail "README does not document no-raw-shell dashboard boundary"

grep -Fq 'v0.28 NetSniper Import' deltaaegis.py \
    || fail "dashboard release pill no longer advertises v0.28 NetSniper Import"

grep -Fq 'DeltaAegis v0.28.0' <(python3 deltaaegis.py --help) \
    || fail "CLI help no longer advertises v0.28 feature baseline"

pass "DeltaAegis v0.28.1 release metadata validation passed"
