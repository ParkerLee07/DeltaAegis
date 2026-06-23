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

./tools/validate_v0_16_investigation_center_api.sh \
    || fail "v0.16 investigation center API validator failed"

grep -q 'data-tab-target="command-center"' deltaaegis.py \
    || fail "Command Center tab button is missing"

grep -q 'data-tab-panel="command-center"' deltaaegis.py \
    || fail "Command Center tab panel is missing"

grep -q 'id="investigation-center-body"' deltaaegis.py \
    || fail "Command Center table body is missing"

grep -q 'function renderInvestigationCenter(payload)' deltaaegis.py \
    || fail "Command Center renderer is missing"

grep -q '/api/investigation-center?limit=25' deltaaegis.py \
    || fail "dashboard does not fetch investigation center API"

grep -q 'renderInvestigationCenter(investigationCenter)' deltaaegis.py \
    || fail "dashboard does not render investigation center payload"

python3 - <<'PY'
from pathlib import Path
import re
import deltaaegis

text = Path("deltaaegis.py").read_text(encoding="utf-8")
html = deltaaegis.dashboard_index_html()

match = re.search(
    r"const\s+DASHBOARD_TABS\s*=\s*\[([\s\S]*?)\];",
    text,
)

assert match, "DASHBOARD_TABS block not found"

tabs = match.group(1)

for required in ['"command-center"', '"port-behavior"', '"scan-jobs"']:
    assert required in tabs, f"DASHBOARD_TABS missing {required}"

for required in [
    'data-tab-target="command-center"',
    'data-tab-panel="command-center"',
    'id="investigation-center-summary"',
    'id="investigation-center-body"',
    'renderInvestigationCenter',
    '/api/investigation-center?limit=25',
]:
    assert required in html, f"dashboard HTML missing {required}"

print("[PASS] Dashboard Command Center HTML and tab allowlist validated")
PY

pass "DeltaAegis v0.16 dashboard Command Center validation passed"
