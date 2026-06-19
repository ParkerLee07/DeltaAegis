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

[[ -f tools/validate_v0_12_intelligence_drilldown.sh ]] \
  || fail "Missing v0.12 intelligence drilldown validator"

[[ -f tools/validate_v0_12_dashboard_intelligence_api.sh ]] \
  || fail "Missing v0.12 dashboard intelligence API validator"

[[ -f tools/validate_v0_12_dashboard_intelligence_panel.sh ]] \
  || fail "Missing v0.12 dashboard intelligence panel validator"

python3 -m py_compile deltaaegis.py
pytest -q

./tools/validate_v0_12_intelligence_drilldown.sh "$BUNDLE_DIR"
./tools/validate_v0_12_dashboard_intelligence_api.sh "$BUNDLE_DIR"
./tools/validate_v0_12_dashboard_intelligence_panel.sh

grep -q 'v0.12.0' CHANGELOG.md \
  || fail "CHANGELOG.md does not mention v0.12.0"

grep -q 'Intelligence Drilldown' README.md \
  || fail "README.md does not mention Intelligence Drilldown"

grep -q 'intelligence-hosts' README.md \
  || fail "README.md does not document intelligence-hosts"

grep -q 'intelligence-host' README.md \
  || fail "README.md does not document intelligence-host"

grep -q 'DeltaAegis v0.12.0 — Intelligence Drilldown' README.md \
  || fail "README.md does not mention the v0.12.0 Intelligence Drilldown baseline"

pass "DeltaAegis v0.12 release validation passed"
