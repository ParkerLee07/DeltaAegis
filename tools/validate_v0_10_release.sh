#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${REPO_DIR:-$HOME/DeltaAegis}"
cd "$REPO_DIR" || {
  echo "[-] Could not enter DeltaAegis repo: $REPO_DIR"
  exit 1
}

echo "[*] Running DeltaAegis v0.10 release validation..."

python3 -m py_compile deltaaegis.py

./tools/validate_v0_10_netsniper_v1_6_storage.sh
./tools/validate_v0_10_netsniper_v1_6_risk_policy.sh

echo "[*] Running carried-forward investigation workflow validators..."
./tools/validate_v0_9_asset_investigation_detail.sh
./tools/validate_v0_9_clickable_investigation_rows.sh
./tools/validate_v0_9_persistent_investigation_status.sh
./tools/validate_v0_9_dashboard_investigation_controls.sh
./tools/validate_v0_9_dashboard_tabs.sh

python3 - <<'PY'
from pathlib import Path

app = Path("deltaaegis.py").read_text(encoding="utf-8")
readme = Path("README.md").read_text(encoding="utf-8")
changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")

required_app = [
    "DeltaAegis v0.10.0",
    "NetSniper v1.6 classification storage",
    "calibrated SIEM risk policy",
]

required_readme = [
    "DeltaAegis v0.10.0 — NetSniper v1.6 Intelligence Integration",
    "First-class storage for NetSniper v1.6 classification fields",
    "Risk scoring now respects NetSniper v1.6 `siem_action`",
    "tools/validate_v0_10_release.sh",
]

required_changelog = [
    "## v0.10.0 - 2026-06-19",
    "Added first-class storage for NetSniper v1.6 classification fields",
    "Updated classification-aware risk scoring to respect NetSniper v1.6 `siem_action` values",
]

missing = []

for item in required_app:
    if item not in app:
        missing.append(f"deltaaegis.py missing: {item}")

for item in required_readme:
    if item not in readme:
        missing.append(f"README.md missing: {item}")

for item in required_changelog:
    if item not in changelog:
        missing.append(f"CHANGELOG.md missing: {item}")

if missing:
    raise SystemExit("[-] v0.10 release metadata validation failed:\n" + "\n".join(missing))

print("[+] PASS: DeltaAegis v0.10 release metadata is valid.")
PY

echo "[+] PASS: DeltaAegis v0.10 release validation succeeded."
