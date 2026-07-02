#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

python3 - <<'PY'
from pathlib import Path
import importlib.util
import sys

module_path = Path("deltaaegis.py")
text = module_path.read_text(encoding="utf-8")

required = [
    '("GET", "/operator/reset", "admin.telemetry.cleanup")',
    'if route == "/operator/reset":',
    'dashboard_operator_reset_shell_html()',
    'id="deltaaegis-telemetry-reset-link"',
    'href="/operator/reset"',
    'id="deltaaegis-telemetry-cleanup-panel"',
    'id="telemetry-cleanup-confirmation"',
    'id="telemetry-cleanup-clear-all"',
    'fetch("/api/telemetry-cleanup/preview"',
    'fetch("/api/telemetry-cleanup/clear-all"',
    'Type DELETE TELEMETRY exactly',
    '_deltaaegis_operator_session_shell_html_v036_reset_link_base',
]

for needle in required:
    if needle not in text:
        raise SystemExit(f"[FAIL] missing operator reset route/page requirement: {needle}")

route_index = text.find('if route == "/operator/reset":')
route_end = text.find('if route == "/netsniper":', route_index)
if route_index < 0 or route_end < 0:
    raise SystemExit("[FAIL] could not bound operator reset route block")
route_block = text[route_index:route_end]

for needle in [
    'self.require_permission("admin.telemetry.cleanup")',
    'dashboard_html_response(self, dashboard_operator_reset_shell_html())',
    'return',
]:
    if needle not in route_block:
        raise SystemExit(f"[FAIL] operator reset route missing guardrail: {needle}")

spec = importlib.util.spec_from_file_location("deltaaegis_under_test", module_path)
delta = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = delta
spec.loader.exec_module(delta)

operator_html = delta.dashboard_operator_session_shell_html()
reset_html = delta.dashboard_operator_reset_shell_html()

if 'href="/operator/reset"' not in operator_html:
    raise SystemExit("[FAIL] operator page does not link to /operator/reset")

if 'id="deltaaegis-telemetry-cleanup-panel"' in operator_html:
    raise SystemExit("[FAIL] telemetry reset panel still renders on main /operator page")

for needle in [
    'DeltaAegis Telemetry Reset',
    'id="deltaaegis-telemetry-cleanup-panel"',
    'id="telemetry-cleanup-confirmation"',
    'id="telemetry-cleanup-clear-all"',
    'DELETE TELEMETRY',
    '/api/telemetry-cleanup/preview',
    '/api/telemetry-cleanup/clear-all',
]:
    if needle not in reset_html:
        raise SystemExit(f"[FAIL] reset page HTML missing requirement: {needle}")

print("[PASS] v0.36 operator telemetry reset page python checks passed")
PY

time tools/validate_v0_36_telemetry_cleanup.sh
time tools/validate_v0_36_telemetry_cleanup_dashboard_api.sh

echo "[PASS] DeltaAegis v0.36 operator telemetry reset page validation passed"
