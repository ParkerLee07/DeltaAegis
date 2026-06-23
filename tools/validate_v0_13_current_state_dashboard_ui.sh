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

grep -q 'route == "/api/current-state"' deltaaegis.py \
    || fail "/api/current-state route is missing"

grep -q 'def dashboard_current_state_payload' deltaaegis.py \
    || fail "dashboard_current_state_payload is missing"

grep -q 'function renderCurrentState' deltaaegis.py \
    || fail "renderCurrentState function is missing"

grep -q 'id="current-state"' deltaaegis.py \
    || fail "Current-state dashboard container is missing"

python3 - <<'PY'
import re
import deltaaegis

html = deltaaegis.dashboard_index_html()

required = [
    "Current Network State",
    'id="current-state"',
    "function renderCurrentState",
    'api(scopedPath("/api/current-state"))',
    "renderCurrentState(currentState)",
]

for item in required:
    assert item in html, item

match = re.search(
    r"const\s*\[([^\]]+)\]\s*=\s*await\s*Promise\.all\s*\(",
    html,
    re.S,
)

assert match, "Dashboard Promise unpack not found"

names = [
    name.strip()
    for name in match.group(1).replace("\n", " ").split(",")
    if name.strip()
]

assert "currentState" in names, names

print("[PASS] Dashboard Promise unpack includes currentState in a supported position")
PY

pass "DeltaAegis v0.13 current-state dashboard UI validation passed"
