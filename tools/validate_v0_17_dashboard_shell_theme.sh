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

./tools/validate_v0_16_command_center_dashboard.sh \
    || fail "v0.16 Command Center dashboard validator failed"

grep -q 'v0.17 Executive SIEM Dashboard Refresh' deltaaegis.py \
    || fail "v0.17 dashboard shell CSS marker is missing"

grep -q 'dashboard-shell-refresh-v017' deltaaegis.py \
    || fail "dashboard body shell class is missing"

grep -q 'Executive Security Overview' deltaaegis.py \
    || fail "executive dashboard header title is missing"

grep -q 'executive-header' deltaaegis.py \
    || fail "executive header class is missing"

grep -q 'dashboard-main' deltaaegis.py \
    || fail "dashboard main shell class is missing"

grep -q 'executive-tabs' deltaaegis.py \
    || fail "executive tabs class is missing"

grep -q 'executive-overview' deltaaegis.py \
    || fail "executive overview section is missing"

grep -q 'metric-card' deltaaegis.py \
    || fail "metric-card styling/markup is missing"

grep -q 'metric-value' deltaaegis.py \
    || fail "metric-value styling/markup is missing"

python3 - <<'PY'
from pathlib import Path
import re
import deltaaegis

text = Path("deltaaegis.py").read_text(encoding="utf-8")
html = deltaaegis.dashboard_index_html()

required_html = [
    "DeltaAegis Executive SIEM Dashboard",
    'class="dashboard-shell-refresh-v017"',
    'class="executive-header"',
    'class="dashboard-main"',
    'class="dashboard-tabs executive-tabs"',
    'class="executive-overview"',
    'data-tab-target="command-center"',
    'data-tab-panel="command-center"',
    'id="investigation-center-body"',
    "/api/investigation-center?limit=25",
    "metric-card",
    "metric-value",
]

for needle in required_html:
    assert needle in html, f"dashboard HTML missing {needle}"

match = re.search(
    r"const\s+DASHBOARD_TABS\s*=\s*\[([\s\S]*?)\];",
    text,
)
assert match, "DASHBOARD_TABS block not found"

tabs = match.group(1)

for tab in [
    '"overview"',
    '"command-center"',
    '"risk"',
    '"port-behavior"',
    '"assets"',
    '"events"',
    '"alerts"',
    '"scan-jobs"',
]:
    assert tab in tabs, f"DASHBOARD_TABS missing {tab}"

print("[PASS] v0.17 executive shell HTML and tab contract validated")
PY

pass "DeltaAegis v0.17 dashboard shell/theme validation passed"
