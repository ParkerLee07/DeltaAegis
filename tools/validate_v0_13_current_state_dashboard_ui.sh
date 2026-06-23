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

grep -q '<div id="current-state"></div>' deltaaegis.py \
    || fail "Current-state overview container is missing"

grep -q 'function renderCurrentState(state)' deltaaegis.py \
    || fail "renderCurrentState function is missing"

grep -q 'api(scopedPath("/api/current-state"))' deltaaegis.py \
    || fail "Dashboard does not fetch /api/current-state"

grep -Fq 'const [scopes, summary, scanContext, currentState, assets, risk, events, alerts, annotations]' deltaaegis.py \
    || fail "Dashboard Promise unpack does not include currentState in the correct position"

grep -q 'renderCurrentState(currentState)' deltaaegis.py \
    || fail "Dashboard does not render currentState"

grep -q 'Current Network State' deltaaegis.py \
    || fail "Current Network State section is missing"

grep -q 'Current Assets' deltaaegis.py \
    || fail "Current Assets card is missing"

grep -q 'Intelligence Hosts' deltaaegis.py \
    || fail "Intelligence Hosts card is missing"

grep -q 'Discovery / No Open Service' deltaaegis.py \
    || fail "Discovery/no-open-service card is missing"

grep -q 'False Confidence' deltaaegis.py \
    || fail "False Confidence current-state card is missing"

pass "DeltaAegis v0.13 current-state dashboard UI validation passed"
