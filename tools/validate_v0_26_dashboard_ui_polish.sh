#!/usr/bin/env bash
set -euo pipefail

NETSNIPER_RUN_DIR="${1:-/home/parker/NetSniper/runs/20260623-123007}"

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

[[ -d "$NETSNIPER_RUN_DIR" ]] || fail "NetSniper run directory missing: $NETSNIPER_RUN_DIR"

python3 -m py_compile deltaaegis.py || fail "deltaaegis.py does not compile"

python3 - <<'PYHTML'
from pathlib import Path
import re
import deltaaegis as da

source = Path("deltaaegis.py").read_text(encoding="utf-8")
readme = Path("README.md").read_text(encoding="utf-8")
operator_html = da.dashboard_operator_session_shell_html()

for needle in [
    'id="deltaaegis-operator-floating-button"',
    'id="deltaaegis-v026-dashboard-polish-style"',
    'id="deltaaegis-v026-dashboard-polish-script"',
    'a[href="/operator"]:not(#deltaaegis-operator-floating-button)',
    "hideDashboardAccessAuditTrail",
    "removeLegacyOperatorLinks",
]:
    assert needle in source, f"missing dashboard UI polish marker: {needle}"

for needle in [
    'id="deltaaegis-admin-control-panel-link"',
    'id="deltaaegis-operator-audit-layout-fix"',
    "Access Audit Trail",
    "operator-access-audit-body",
    "table-layout: fixed",
    "overflow-wrap: anywhere",
    "word-break: break-word",
]:
    assert needle in operator_html, f"missing operator layout marker: {needle}"

assert '\\n        <a href="/">Back to dashboard</a>' not in operator_html, "literal backslash-n still visible before Back to dashboard"

bad_operator_links = re.findall(
    r'<a\\b(?=[^>]*href="/operator")(?![^>]*id="deltaaegis-operator-floating-button")[^>]*>\\s*Operator\\s*</a>',
    source,
    flags=re.DOTALL,
)
assert not bad_operator_links, f"non-floating dashboard Operator link remains: {bad_operator_links[:1]}"

for stale in [
    "RELEASE v0.19 Filters",
    "Release v0.19 Filters",
    "v0.19 Filters",
    "V0.19 Filters",
    "v0.19 filters",
]:
    assert stale not in source, f"stale release wording remains in deltaaegis.py: {stale}"
    assert stale not in readme, f"stale release wording remains in README.md: {stale}"

for forbidden in [
    "deltaaegis-operator-link-style",
    "operator-session-link",
    "renderAccessAudit(accessAudit)",
    'api(scopedPath("/api/access-audit?limit=20"))',
]:
    assert forbidden not in source, f"main dashboard still contains removed legacy/audit marker: {forbidden}"

print("[PASS] rendered/source v0.26 dashboard UI polish markers validated")
PYHTML

./tools/validate_v0_26_operator_audit_navigation_polish.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.26 operator audit/navigation polish compatibility gate failed"

pass "DeltaAegis v0.26 dashboard UI polish validation passed"
