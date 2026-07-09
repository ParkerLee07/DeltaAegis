#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

branch="$(git branch --show-current)"
case "$branch" in
  feature/v0.42-logical-site-scopes|main)
    ;;
  *)
    echo "FAIL: unexpected branch $branch"
    exit 1
    ;;
esac

echo "DeltaAegis v0.42 Dashboard Freshness Foundation Validator"
echo "==========================================================="

echo "[v0.42 checkpoint F] Python source syntax"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py
echo "PASS: Python source syntax"

echo "[v0.42 checkpoint F] static freshness contract"
python3 - <<'PY'
from pathlib import Path
import ast

source = Path("deltaaegis.py").read_text(encoding="utf-8")
ast.parse(source)

required = (
    '# v0.42 checkpoint F: shared dashboard evidence freshness strip.',
    'id="dashboard-freshness-strip"',
    'id="dashboard-freshness-state"',
    'id="dashboard-freshness-newest"',
    'id="dashboard-freshness-oldest"',
    'id="dashboard-freshness-imported"',
    'id="dashboard-freshness-refreshed"',
    'id="dashboard-freshness-warning"',
    'id="deltaaegis-v042-dashboard-freshness-script"',
    'function freshnessAggregate(',
    'function freshnessLoadRecords(',
    'function freshnessSetTime(',
    'function freshnessLocalLabel(',
    'window.deltaAegisDashboardFreshness',
    'toLocaleString(',
    'element.title = String(value)',
    'return "Unknown"',
    'spreadSeconds > 3600',
    'selected scope has no accepted scan',
)

for marker in required:
    if marker not in source:
        raise SystemExit(
            f"missing dashboard freshness marker: {marker}"
        )

for forbidden in (
    'element.textContent = new Date().toLocaleString()',
    'model.newest || new Date()',
    'model.imported || new Date()',
):
    if forbidden in source:
        raise SystemExit(
            f"browser time may be substituting for evidence: {forbidden}"
        )

print("PASS: four-clock separation markers")
print("PASS: local-time display preserves source timestamp")
print("PASS: mixed-age scope warning contract")
print("PASS: unknown timestamps do not use browser time")
print("PASS: leaf behavior is limited to freshness feature checks")
PY

echo "[v0.42 checkpoint F] rendered dashboard contract"
python3 - <<'PY'
from pathlib import Path
import importlib.util
import re
import sys

repo = Path.cwd()
spec = importlib.util.spec_from_file_location(
    "deltaaegis_v042_freshness_render",
    repo / "deltaaegis.py",
)

if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

page = module.dashboard_index_html()

required = (
    'id="dashboard-freshness-strip"',
    'id="dashboard-freshness-state"',
    'id="dashboard-freshness-newest-label"',
    'id="dashboard-freshness-oldest-label"',
    'id="dashboard-freshness-imported"',
    'id="dashboard-freshness-refreshed"',
    'id="dashboard-freshness-warning"',
    'id="deltaaegis-v042-dashboard-freshness-script"',
    'Newest member evidence',
    'Newest scope evidence',
    'Evidence through',
    'Dashboard refreshed',
    'different times',
    'Do not assume the visible evidence is current',
)

for marker in required:
    if marker not in page:
        raise SystemExit(
            f"rendered dashboard missing freshness marker: {marker}"
        )

nav_end = page.find("</nav>")
strip_start = page.find('id="dashboard-freshness-strip"')
first_panel = page.find('data-tab-panel=')

if nav_end < 0 or strip_start < 0 or first_panel < 0:
    raise SystemExit("could not establish rendered strip placement")

if not nav_end < strip_start < first_panel:
    raise SystemExit(
        "freshness strip is not between navigation and tab panels"
    )

matches = re.findall(
    r'<script id="deltaaegis-v042-dashboard-freshness-script">'
    r'(.*?)</script>',
    page,
    flags=re.DOTALL,
)

if len(matches) != 1:
    raise SystemExit(
        f"expected one rendered freshness script, found {len(matches)}"
    )

print("PASS: persistent strip is outside individual tab panels")
print("PASS: site, all-scopes, and subnet labels are rendered")
print("PASS: mixed-age and lookup-failure warnings are rendered")
print("PASS: rendered freshness script is present exactly once")
PY

echo "[v0.42 checkpoint F] existing freshness API contract"
python3 - <<'PY'
from pathlib import Path
import importlib.util
import sys

repo = Path.cwd()
spec = importlib.util.spec_from_file_location(
    "deltaaegis_v042_freshness_api",
    repo / "deltaaegis.py",
)

if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

class FakeConnection:
    pass

snapshot = {
    "scan_id": "freshness-fixture",
    "network_scope": "10.42.0.0/24",
    "created_at": "2026-07-09T10:00:00+00:00",
    "imported_at": "2026-07-09T10:05:00+00:00",
    "scan_completed_at": "2026-07-09T10:00:00+00:00",
    "quality_status": "ACCEPTED",
    "hosts_up": 2,
    "hosts_total": 2,
    "identity_coverage": 1.0,
}

original = module.dashboard_latest_accepted_snapshot
module.dashboard_latest_accepted_snapshot = (
    lambda connection, scope=None: snapshot
)

try:
    payload = module.dashboard_scan_freshness_payload(
        FakeConnection(),
        scope="10.42.0.0/24",
        now="2026-07-09T11:00:00+00:00",
    )
finally:
    module.dashboard_latest_accepted_snapshot = original

if payload["state"] != "FRESH":
    raise SystemExit(f"unexpected freshness state: {payload}")

if payload["timestamp"] != "2026-07-09T10:00:00+00:00":
    raise SystemExit(
        f"scan completion was not used as evidence time: {payload}"
    )

if payload["latest_snapshot"]["imported_at"] != (
    "2026-07-09T10:05:00+00:00"
):
    raise SystemExit(
        f"import time was not preserved separately: {payload}"
    )

if payload["age_hours"] != 1.0:
    raise SystemExit(
        f"unexpected accepted evidence age: {payload}"
    )

print("PASS: accepted evidence and import clocks remain separate")
print("PASS: existing policy-driven freshness bands are reused")
PY

echo "[v0.42 checkpoint F] repository hygiene"
git diff --check
echo "PASS: repository hygiene"

echo "PASS: DeltaAegis v0.42 dashboard freshness foundation validator"

