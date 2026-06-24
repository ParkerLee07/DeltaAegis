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

./tools/validate_v0_17_dashboard_shell_theme.sh \
    || fail "v0.17 dashboard shell/theme validator failed"

./tools/validate_v0_16_command_center_dashboard.sh \
    || fail "v0.16 Command Center dashboard validator failed"

grep -q 'v0.17 SIEM-style executive chart panels' deltaaegis.py \
    || fail "v0.17 SIEM chart CSS marker is missing"

grep -q 'siem-analytics-grid' deltaaegis.py \
    || fail "SIEM analytics grid is missing"

grep -q 'chart-event-categories' deltaaegis.py \
    || fail "event categories chart container is missing"

grep -q 'chart-risk-levels' deltaaegis.py \
    || fail "risk levels chart container is missing"

grep -q 'chart-classification-mix' deltaaegis.py \
    || fail "classification mix chart container is missing"

grep -q 'chart-port-behavior' deltaaegis.py \
    || fail "port behavior chart container is missing"

grep -q 'function renderHorizontalBars' deltaaegis.py \
    || fail "horizontal bar chart renderer is missing"

grep -q 'function renderDistributionPanel' deltaaegis.py \
    || fail "distribution chart renderer is missing"

grep -q 'function renderExecutiveCharts' deltaaegis.py \
    || fail "executive chart renderer is missing"

grep -q 'renderExecutiveCharts(summary, currentRisk, portBehavior, investigationCenter, assets, events, alerts)' deltaaegis.py \
    || fail "dashboard load does not render executive charts"

python3 - <<'PY'
import deltaaegis

html = deltaaegis.dashboard_index_html()

required = [
    "Executive",
    "Tickets",
    "Risk Analysis",
    "Network Activity",
    "Taxonomy",
    "Security Events",
    "Alarms",
    "Data Sources",
    "Security Events: Top Categories",
    "Risk Analysis: Priority Distribution",
    "Taxonomy: Asset Classification Mix",
    "Network Activity: MAC-Port Behavior",
    "chart-event-categories",
    "chart-risk-levels",
    "chart-classification-mix",
    "chart-port-behavior",
    "renderExecutiveCharts",
]

for needle in required:
    assert needle in html, f"dashboard HTML missing {needle}"

stable_targets = [
    'data-tab-target="overview"',
    'data-tab-target="command-center"',
    'data-tab-target="risk"',
    'data-tab-target="port-behavior"',
    'data-tab-target="assets"',
    'data-tab-target="events"',
    'data-tab-target="alerts"',
    'data-tab-target="scan-jobs"',
]

for needle in stable_targets:
    assert needle in html, f"dashboard internal tab target changed or missing: {needle}"

print("[PASS] v0.17 SIEM charts and naming contract validated")
PY

pass "DeltaAegis v0.17 SIEM charts validation passed"
