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

echo "[*] Running asset investigation detail validator..."
./tools/validate_v0_9_asset_investigation_detail.sh

echo "[*] Validating clickable dashboard investigation rows..."

python3 - <<'PY'
from pathlib import Path
import deltaaegis as da

text = Path("deltaaegis.py").read_text(encoding="utf-8")
html = da.dashboard_index_html()

required_source = [
    "function subjectButton(subject)",
    "function bindSubjectLinks(root)",
    "function renderRisk",
    "function renderEvents",
    "function renderAlerts",
    "subjectButton(row.subject_key || \"-\")",
    "bindSubjectLinks(tbody);",
]

missing_source = [item for item in required_source if item not in text]

if missing_source:
    raise SystemExit(f"[-] Missing clickable row source markers: {missing_source}")

if text.count("subjectButton(row.subject_key || \"-\")") < 3:
    raise SystemExit("[-] Expected risk, event, and alert renderers to use subjectButton(row.subject_key).")

if text.count("bindSubjectLinks(tbody);") < 3:
    raise SystemExit("[-] Expected risk, event, and alert renderers to bind subject links after rendering.")

required_html = [
    "data-asset-identifier",
    "loadAssetDetail",
    "subjectButton",
    "bindSubjectLinks",
    "risk-body",
    "events-body",
    "alerts-body",
]

missing_html = [item for item in required_html if item not in html]

if missing_html:
    raise SystemExit(f"[-] Dashboard HTML missing clickable investigation markers: {missing_html}")

print("[+] PASS: risk, event, and alert subjects link to the asset investigation panel.")
PY

echo
echo "[+] PASS: DeltaAegis v0.9 clickable investigation row validation succeeded."
