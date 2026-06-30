#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

python3 - <<'PY_CHECK'
from pathlib import Path

files = {
    "deltaaegis.py": Path("deltaaegis.py").read_text(encoding="utf-8"),
    "README.md": Path("README.md").read_text(encoding="utf-8"),
    "CHANGELOG.md": Path("CHANGELOG.md").read_text(encoding="utf-8"),
}

checks = [
    ("deltaaegis.py", "DeltaAegis v0.33.0: TrueAegis integration foundation"),
    ("deltaaegis.py", "DeltaAegis v0.33.0 — TrueAegis Integration Foundation"),
    ("deltaaegis.py", "v0.33 TrueAegis Integration Foundation"),
    ("deltaaegis.py", "def append_report_trueaegis_validation_section"),
    ("deltaaegis.py", "/api/validation-summary"),
    ("deltaaegis.py", "/api/validations"),
    ("README.md", "## Current Release — v0.33.0"),
    ("README.md", "DeltaAegis v0.33.0 — TrueAegis Integration Foundation"),
    ("README.md", "./tools/validate_v0_33_release.sh"),
    ("README.md", "validation-ingest"),
    ("README.md", "/api/validation-summary"),
    ("CHANGELOG.md", "## v0.33.0 — TrueAegis Integration Foundation"),
    ("CHANGELOG.md", "validate_v0_33_trueaegis_storage.sh"),
    ("CHANGELOG.md", "validate_v0_33_validation_dashboard.sh"),
    ("CHANGELOG.md", "validate_v0_33_report_validation.sh"),
    ("CHANGELOG.md", "validate_v0_33_release_metadata.sh"),
    ("CHANGELOG.md", "validate_v0_33_release.sh"),
]

missing = []
for filename, marker in checks:
    if marker not in files[filename]:
        missing.append(f"{filename}: {marker}")

if missing:
    raise SystemExit("missing v0.33 release metadata markers:\n" + "\n".join(missing))

print("[PASS] v0.33 release metadata python checks passed")
PY_CHECK

echo "[PASS] DeltaAegis v0.33 release metadata validation passed"
