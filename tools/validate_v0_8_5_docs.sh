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
        "DeltaAegis v0.8.5",
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

readme = Path("README.md").read_text(encoding="utf-8")
arch = Path("Docs/architecture.md").read_text(encoding="utf-8")
validator = Path("tools/validate_v0_8_5_docs.sh").read_text(encoding="utf-8")

if "DeltaAegis v0.6.0" in readme:
    raise SystemExit("[-] README.md still contains stale DeltaAegis v0.6.0 reference.")

if "DeltaAegis `v0.2` ingests" in arch or "DeltaAegis v0.2 ingests" in arch:
    raise SystemExit("[-] Docs/architecture.md still contains stale v0.2 ingestion reference.")

if validator.count("\n") < 20:
    raise SystemExit("[-] Docs validator appears malformed or one-lined.")

print("[+] PASS: DeltaAegis v0.8.5 documentation content is present and formatted.")
PY

echo
echo "[+] PASS: DeltaAegis v0.8.5 documentation validation succeeded."
