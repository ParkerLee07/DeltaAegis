#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_DIR="${1:-/home/parker/NetSniper/runs/20260619-134116}"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

cd "$ROOT_DIR"

[[ -f tools/validate_readme_current.sh ]] \
  || fail "Missing README current validator"

grep -q 'v0.12.1 — README Metadata Cleanup' README.md \
  || fail "README does not mention v0.12.1 README Metadata Cleanup"

grep -q 'v0.12.1 — README Metadata Cleanup' CHANGELOG.md \
  || fail "CHANGELOG does not mention v0.12.1 README Metadata Cleanup"

./tools/validate_readme_current.sh

python3 -m py_compile deltaaegis.py
pytest -q

./tools/validate_v0_12_intelligence_drilldown.sh "$BUNDLE_DIR"
./tools/validate_v0_12_dashboard_intelligence_api.sh "$BUNDLE_DIR"
./tools/validate_v0_12_dashboard_intelligence_panel.sh

pass "DeltaAegis v0.12.1 README cleanup validation passed"
