#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

grep -q 'Why This Level?' deltaaegis.py \
    || fail "Risk table header does not explain levels"

grep -q 'function riskLevelDescription' deltaaegis.py \
    || fail "Risk level description helper missing"

grep -q 'function riskExplanationHtml' deltaaegis.py \
    || fail "Risk explanation renderer missing"

grep -q 'class="risk-explanation"' deltaaegis.py \
    || fail "Risk explanation details block missing"

grep -q 'Suggested follow-up' deltaaegis.py \
    || fail "Recommended action explanation missing"

grep -q 'Risk band:' deltaaegis.py \
    || fail "Risk band explanation missing"

grep -q 'recommended_actions' deltaaegis.py \
    || fail "Risk explanations do not use recommended actions"

grep -q 'NetSniper role classification, contradictions, and exposed services' deltaaegis.py \
    || fail "Risk legend does not mention NetSniper classification inputs"

python3 - <<'PY'
import deltaaegis

html = deltaaegis.dashboard_index_html()

required = [
    "Why This Level?",
    "function riskLevelDescription",
    "function riskExplanationHtml",
    "risk-explanation",
    "Suggested follow-up",
    "Risk band:",
    "score 85",
]

for item in required:
    assert item in html, item

print("[PASS] Dashboard risk explanation HTML validated")
PY

pass "DeltaAegis v0.14 risk explanation validation passed"
