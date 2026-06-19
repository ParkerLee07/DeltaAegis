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

echo "[*] Running retained dashboard polish validators..."
./tools/validate_v0_8_5_dashboard_column_alignment.sh
./tools/validate_v0_8_5_dashboard_severity_colors.sh

echo "[*] Running v0.9 investigation workflow validators..."
./tools/validate_v0_9_asset_investigation_detail.sh
./tools/validate_v0_9_clickable_investigation_rows.sh
./tools/validate_v0_9_persistent_investigation_status.sh
./tools/validate_v0_9_dashboard_investigation_controls.sh

echo "[*] Validating v0.9 release metadata..."

python3 - <<'PY'
from pathlib import Path
import deltaaegis as da

app = Path("deltaaegis.py").read_text(encoding="utf-8")
readme = Path("README.md").read_text(encoding="utf-8")
changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
html = da.dashboard_index_html()

required_app = [
    "DeltaAegis v0.9.0",
    "investigation workflow",
    "dashboard + investigation status updates",
    "def do_POST(self):",
    "/api/investigate-asset",
    "set_asset_investigation_status",
    "investigate-asset",
]

missing_app = [item for item in required_app if item not in app]

if missing_app:
    raise SystemExit(f"[-] deltaaegis.py missing v0.9 markers: {missing_app}")

required_readme = [
    "DeltaAegis v0.9.0 Investigation Workflow",
    "What v0.9.0 adds",
    "Persistent asset investigation status",
    "Dashboard-side investigation status controls",
    "DeltaAegis v0.9.0 Current Capabilities",
]

missing_readme = [item for item in required_readme if item not in readme]

if missing_readme:
    raise SystemExit(f"[-] README.md missing v0.9 markers: {missing_readme}")

required_changelog = [
    "## v0.9.0 - 2026-06-19",
    "Added asset investigation detail payloads",
    "Added dashboard controls for saving investigation status",
    "tools/validate_v0_9_dashboard_investigation_controls.sh",
]

missing_changelog = [item for item in required_changelog if item not in changelog]

if missing_changelog:
    raise SystemExit(f"[-] CHANGELOG.md missing v0.9 markers: {missing_changelog}")

required_html = [
    "Investigation Summary",
    "Update Investigation Status",
    "save-investigation-status",
    "Status Source",
    "Inferred Status",
]

missing_html = [item for item in required_html if item not in html]

if missing_html:
    raise SystemExit(f"[-] Dashboard HTML missing v0.9 markers: {missing_html}")

print("[+] PASS: DeltaAegis v0.9 release metadata is valid.")
PY

echo
echo "[+] PASS: DeltaAegis v0.9 release validation succeeded."
