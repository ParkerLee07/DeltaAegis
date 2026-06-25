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
import deltaaegis as da

operator_html = da.dashboard_operator_session_shell_html()
source = Path("deltaaegis.py").read_text(encoding="utf-8")

for needle in [
    'id="deltaaegis-admin-control-panel-link"',
    'href="/operator/users"',
    "Admin control panel",
    "Access Audit Trail",
    "operator-access-audit-refresh",
    "operator-access-audit-status",
    "operator-access-audit-body",
    'fetch("/api/access-audit?limit=50"',
    "loadOperatorAccessAuditTrail",
]:
    assert needle in operator_html, f"missing operator audit/navigation marker: {needle}"

for needle in [
    "def dashboard_inject_operator_floating_button",
    'id="deltaaegis-operator-floating-button"',
    'href="/operator"',
    "bottom: 20px",
    "right: 20px",
    "dashboard_inject_operator_floating_button",
]:
    assert needle in source, f"missing bottom-right operator button marker: {needle}"

for stale in [
    "RELEASE v0.19 filters",
    "Release v0.19 filters",
    "v0.19 filters",
]:
    assert stale not in source, f"stale v0.19 filter wording remains in deltaaegis.py: {stale}"

readme = Path("README.md").read_text(encoding="utf-8")
for stale in [
    "RELEASE v0.19 filters",
    "Release v0.19 filters",
    "v0.19 filters",
]:
    assert stale not in readme, f"stale v0.19 filter wording remains in README.md: {stale}"

print("[PASS] rendered operator audit/navigation polish markers validated")
PYHTML

./tools/validate_v0_26_user_audit_visibility.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.26 user audit visibility compatibility gate failed"

pass "DeltaAegis v0.26 operator audit/navigation polish validation passed"
