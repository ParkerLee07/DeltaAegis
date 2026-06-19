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

[[ -f "$ROOT_DIR/tools/validate_v0_11_intelligence_artifacts.sh" ]] \
  || fail "Missing v0.11 intelligence artifact validator"

[[ -f "$ROOT_DIR/tools/validate_v0_11_dashboard_intelligence.sh" ]] \
  || fail "Missing v0.11 dashboard intelligence validator"

python3 -m py_compile "$ROOT_DIR/deltaaegis.py"

cd "$ROOT_DIR"

pytest -q

./tools/validate_v0_11_intelligence_artifacts.sh "$BUNDLE_DIR"
./tools/validate_v0_11_dashboard_intelligence.sh "$BUNDLE_DIR"

if [[ -x "$ROOT_DIR/tools/validate_v0_10_release.sh" ]]; then
  ./tools/validate_v0_10_release.sh
fi

grep -q 'v0.11.0' "$ROOT_DIR/CHANGELOG.md" \
  || fail "CHANGELOG.md does not mention v0.11.0"

grep -q 'NetSniper v1.7' "$ROOT_DIR/README.md" \
  || fail "README.md does not mention NetSniper v1.7"

grep -q 'intelligence' "$ROOT_DIR/README.md" \
  || fail "README.md does not mention intelligence command or dashboard intelligence"

pass "DeltaAegis v0.11 release validation passed"
