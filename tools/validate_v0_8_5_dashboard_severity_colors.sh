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

echo "[*] Running dashboard column alignment validator..."
./tools/validate_v0_8_5_dashboard_column_alignment.sh

echo "[*] Validating dashboard severity colors..."

python3 - <<'PY'
import deltaaegis as da

html = da.dashboard_index_html()

required_css = [
    ".severity-critical",
    ".severity-high",
    ".severity-medium",
    ".severity-low",
    ".severity-info",
    "font-weight: 800",
]

required_renderers = [
    'class="severity-${esc(row.level || "").toLowerCase()}"',
    'class="severity-${esc(row.severity || "").toLowerCase()}"',
]

missing = [item for item in required_css + required_renderers if item not in html]

if missing:
    raise SystemExit(f"[-] Dashboard severity color support missing: {missing}")

# Make sure the three visible dashboard tables still exist.
required_sections = [
    "Top Risk Subjects",
    "Recent Delta Events",
    "Recent Alerts",
]

for section in required_sections:
    if section not in html:
        raise SystemExit(f"[-] Dashboard section missing: {section}")

print("[+] PASS: dashboard severity and risk-level colors are defined and renderer classes are present.")
PY

echo
echo "[+] PASS: DeltaAegis v0.8.5 dashboard severity color validation succeeded."
