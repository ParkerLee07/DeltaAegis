#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/DeltaAegis}" || {
  echo "[-] Could not enter DeltaAegis repo."
  exit 1
}

echo "[*] Running syntax check..."
python3 -m py_compile deltaaegis.py

echo "[*] Running tests..."
pytest -q

echo "[*] Running dashboard table validator..."
./tools/validate_v0_8_5_dashboard_tables.sh

echo "[*] Running dashboard column alignment validator..."
./tools/validate_v0_8_5_dashboard_column_alignment.sh

echo "[*] Running dashboard severity color validator..."
./tools/validate_v0_8_5_dashboard_severity_colors.sh

echo "[*] Running docs validator..."
./tools/validate_v0_8_5_docs.sh

echo "[*] Validating v0.8.6 release metadata..."

python3 - <<'PY'
from pathlib import Path
import deltaaegis as da

checks = {
    "README.md": [
        "DeltaAegis v0.8.6",
        "DeltaAegis v0.8.6 Dashboard Polish",
        "Dashboard severity and risk-level colors are restored",
    ],
    "CHANGELOG.md": [
        "## v0.8.6 - 2026-06-18",
        "Fixed dashboard risk, event, and alert tables",
        "Dashboard severity color validator",
    ],
    "deltaaegis.py": [
        "DeltaAegis v0.8.6",
    ],
}

for filename, phrases in checks.items():
    path = Path(filename)

    if not path.is_file():
        raise SystemExit(f"[-] Missing file: {filename}")

    text = path.read_text(encoding="utf-8")
    missing = [phrase for phrase in phrases if phrase not in text]

    if missing:
        raise SystemExit(f"[-] {filename} missing expected phrase(s): {missing}")

html = da.dashboard_index_html()

required_dashboard_text = [
    "Top Risk Subjects",
    "Recent Delta Events",
    "Recent Alerts",
    "Open Alerts",
    "Primary Reason",
    ".severity-critical",
    ".severity-high",
    ".severity-medium",
    ".severity-low",
    ".severity-info",
]

missing_dashboard = [item for item in required_dashboard_text if item not in html]

if missing_dashboard:
    raise SystemExit(f"[-] Dashboard HTML missing expected v0.8.6 text: {missing_dashboard}")

print("[+] PASS: DeltaAegis v0.8.6 release metadata and dashboard polish validators are valid.")
PY

echo
echo "[+] PASS: DeltaAegis v0.8.6 release validation succeeded."
