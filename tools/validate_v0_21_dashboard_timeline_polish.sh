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

grep -q 'function ticketEvidenceCategoryLabel' deltaaegis.py \
    || fail "ticket evidence category label helper missing"

grep -q 'function ticketEvidenceCategoryClass' deltaaegis.py \
    || fail "ticket evidence category class helper missing"

grep -q 'summary.why_now' deltaaegis.py \
    || fail "dashboard does not render summary.why_now"

grep -q 'ticket-evidence-why-now' deltaaegis.py \
    || fail "dashboard Why Now styling hook missing"

grep -q 'ticket-evidence-category-current-risk' deltaaegis.py \
    || fail "current risk category styling missing"

python3 - <<'PYVALIDATOR'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = [
    '"current_risk": "Current Risk"',
    '"alert": "Alert"',
    '"delta_event": "Delta Event"',
    '"port_behavior": "Port Behavior"',
    '"ticket_history": "Workflow History"',
    '${esc(summary.why_now || "No why-now summary was generated for this ticket.")}',
    '${esc(ticketEvidenceCategoryLabel(item.category))}',
]

for marker in required:
    assert marker in text, marker

assert text.index("function ticketEvidenceCategoryLabel") < text.index("function ticketEvidenceTimelineHtml")
assert text.index("summary.primary_reason") < text.index("summary.why_now") < text.index("summary.recommended_action")

print("[PASS] static v0.21 dashboard timeline polish validated")
PYVALIDATOR

./tools/validate_v0_21_balanced_evidence_timeline.sh \
    || fail "v0.21 balanced timeline validator failed"

./tools/validate_v0_21_why_now_summary.sh \
    || fail "v0.21 why-now summary validator failed"

pass "DeltaAegis v0.21 dashboard timeline polish validation passed"
