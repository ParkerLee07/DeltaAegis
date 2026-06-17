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

echo "[*] Running v0.8.5 recommendation polish validator..."
./tools/validate_v0_8_5_recommendation_polish.sh

echo "[*] Validating documentation content..."

python3 - <<'PY'
from pathlib import Path

checks = {
    "README.md": [
        "DeltaAegis v0.8.5 Current Capabilities",
        "NetSniper classification intelligence ingestion",
        "Dashboard intelligence visibility",
        "Classification-aware risk context",
        "Role-aware recommended actions",
        "Recommendation wording polish",
    ],
    "CHANGELOG.md": [
        "## v0.8.5 - 2026-06-17",
        "## v0.8.0 - 2026-06-17",
        "## v0.7.0 - 2026-06-17",
        "Classification-aware risk context",
        "Role-aware recommended actions",
        "NetSniper v1.4 classification intelligence ingestion",
    ],
    "Docs/architecture.md": [
        "v0.8.5 Intelligence Pipeline",
        "classification intelligence storage",
        "classification delta events",
        "Risk and recommendation layer",
        "Role-aware recommended actions",
    ],
}

for filename, phrases in checks.items():
    path = Path(filename)

    if not path.is_file():
        raise SystemExit(f"[-] Missing documentation file: {filename}")

    text = path.read_text(encoding="utf-8")
    missing = [phrase for phrase in phrases if phrase not in text]

    if missing:
        raise SystemExit(f"[-] {filename} missing expected phrase(s): {missing}")

print("[+] PASS: DeltaAegis v0.8.5 documentation content is present.")
PY

echo
echo "[+] PASS: DeltaAegis v0.8.5 documentation validation succeeded."
