#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

printf '%s\n' \
  "DeltaAegis v0.39 Dashboard HTTP Smoke Validator" \
  "================================================"

python3 -m py_compile deltaaegis.py
python3 -m py_compile "$SCRIPT_DIR/validate_v0_39_dashboard_http_smoke.py"

python3 "$SCRIPT_DIR/validate_v0_39_dashboard_http_smoke.py"

git diff --check

printf '%s\n' \
  "PASS: DeltaAegis v0.39 dashboard HTTP smoke validator"
