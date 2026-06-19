#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/DeltaAegis}" || {
  echo "[-] Could not enter DeltaAegis repo."
  exit 1
}

echo "[*] Running syntax check..."
python3 -m py_compile deltaaegis.py

echo "[*] Running live tests..."
pytest -q

echo "[*] Validating dashboard tabs..."

python3 - <<'PY'
from pathlib import Path
import deltaaegis as da

source = Path("deltaaegis.py").read_text(encoding="utf-8")
html = da.dashboard_index_html()

required_html = [
    "dashboard-tabs",
    'data-tab-target="overview"',
    'data-tab-target="investigations"',
    'data-tab-target="risk"',
    'data-tab-target="assets"',
    'data-tab-target="intelligence"',
    'data-tab-target="events"',
    'data-tab-target="alerts"',
    'data-tab-panel="overview"',
    'data-tab-panel="investigations"',
    'data-tab-panel="risk"',
    'data-tab-panel="assets"',
    'data-tab-panel="events"',
    'data-tab-panel="alerts"',
    "asset-detail-card",
    "asset-inventory-body",
    "risk-body",
    "events-body",
    "alerts-body",
    "annotations",
    "recommendations",
]

missing_html = [item for item in required_html if item not in html]

if missing_html:
    raise SystemExit(f"[-] Dashboard HTML missing tab markers: {missing_html}")

required_source = [
    "function setupDashboardTabs()",
    "function activateDashboardTab(tabName)",
    "function applyDashboardTabState()",
    "activateDashboardTab(\"investigations\");",
    'section.dataset.tabPanel = "intelligence";',
    "applyDashboardTabState();",
]

missing_source = [item for item in required_source if item not in source]

if missing_source:
    raise SystemExit(f"[-] deltaaegis.py missing tab JS markers: {missing_source}")

if html.count("data-tab-target=") < 7:
    raise SystemExit("[-] Expected at least seven dashboard tab buttons.")

if html.count("data-tab-panel=") < 11:
    raise SystemExit("[-] Expected the existing dashboard sections to be assigned to tab panels.")

if "Update Investigation Status" not in html:
    raise SystemExit("[-] Investigation status controls disappeared from dashboard HTML.")

if "/api/investigate-asset" not in html:
    raise SystemExit("[-] Dashboard investigation POST route marker disappeared.")

if "function setupCollapsibleCards_DISABLED_BY_TABS {" in source:
    raise SystemExit("[-] Dashboard contains malformed JavaScript from disabled collapse function.")

load_start = source.find("async function load()")
load_end = source.find("const [scopes", load_start)

if load_start == -1 or load_end == -1:
    raise SystemExit("[-] Could not locate dashboard load() setup block.")

load_block = source[load_start:load_end]

if "setupDashboardTabs();" not in load_block:
    raise SystemExit("[-] load() does not call setupDashboardTabs(), so tab buttons will not bind.")

if "setupCollapsibleCards();" in load_block:
    raise SystemExit("[-] load() still calls setupCollapsibleCards(), which is redundant with tabs.")

load_start = source.find("async function load()")
load_end = source.find("load();", load_start)

if load_start == -1 or load_end == -1:
    raise SystemExit("[-] Could not locate dashboard load() function.")

load_block = source[load_start:load_end]

if "setupDashboardTabs();" not in load_block:
    raise SystemExit("[-] load() does not call setupDashboardTabs(), so tab buttons will not bind.")

print("[+] PASS: dashboard tab shell keeps existing sections and investigation controls.")
PY

echo
echo "[+] PASS: DeltaAegis v0.9 dashboard tabs validation succeeded."
