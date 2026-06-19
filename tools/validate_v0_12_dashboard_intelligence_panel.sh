#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

cd "$ROOT_DIR"

[[ -f deltaaegis.py ]] || fail "Missing deltaaegis.py"

grep -q 'function renderIntelligenceHostDetail(payload)' deltaaegis.py \
  || fail "Missing dashboard host evidence renderer"

grep -q 'async function loadIntelligenceHostDetail(identity)' deltaaegis.py \
  || fail "Missing dashboard host evidence loader"

grep -q 'function bindIntelligenceHostLinks(root)' deltaaegis.py \
  || fail "Missing dashboard host link binder"

grep -q 'data-intelligence-host' deltaaegis.py \
  || fail "Missing clickable v1.7 review queue host buttons"

grep -q 'id="intelligence-host-detail"' deltaaegis.py \
  || fail "Missing v1.7 host evidence drilldown panel"

grep -q '/api/intelligence-host?identity=' deltaaegis.py \
  || fail "Dashboard does not call /api/intelligence-host"

grep -q 'bindIntelligenceHostLinks(section)' deltaaegis.py \
  || fail "renderClassificationSummary does not bind intelligence host links"

python3 -m py_compile deltaaegis.py
pytest -q

./tools/validate_v0_12_intelligence_drilldown.sh
./tools/validate_v0_12_dashboard_intelligence_api.sh

pass "DeltaAegis v0.12 dashboard intelligence drilldown panel validated"
