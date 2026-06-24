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

./tools/validate_v0_17_siem_charts.sh \
    || fail "v0.17 SIEM charts validator failed"

./tools/validate_v0_16_command_center_dashboard.sh \
    || fail "v0.16 Command Center dashboard validator failed"

grep -q 'v0.17 SIEM-style ticket queue' deltaaegis.py \
    || fail "v0.17 ticket queue CSS marker is missing"

grep -q 'id="investigation-ticket-cards"' deltaaegis.py \
    || fail "ticket card container is missing"

grep -q 'class="siem-ticket-table"' deltaaegis.py \
    || fail "compatibility ticket table class is missing"

grep -q 'const ticketCards = document.getElementById("investigation-ticket-cards")' deltaaegis.py \
    || fail "ticket card JS binding is missing"

grep -q 'siem-ticket-card ticket-' deltaaegis.py \
    || fail "ticket card renderer is missing"

grep -q 'siem-priority-badge' deltaaegis.py \
    || fail "ticket priority badge is missing"

grep -q 'siem-ticket-reason' deltaaegis.py \
    || fail "ticket reason styling/rendering is missing"

grep -q 'siem-ticket-action' deltaaegis.py \
    || fail "ticket action styling/rendering is missing"

grep -q 'bindSubjectLinks(ticketCards)' deltaaegis.py \
    || fail "ticket subject links are not bound"

python3 - <<'PY'
import deltaaegis

html = deltaaegis.dashboard_index_html()

required = [
    'id="investigation-ticket-cards"',
    'class="ticket-cards-grid"',
    'class="siem-ticket-table"',
    'Tickets: Investigation Queue',
    'siem-ticket-card',
    'siem-priority-badge',
    'siem-ticket-meta',
    'siem-ticket-counts',
    'Detailed queue table',
    'id="investigation-center-body"',
]

for needle in required:
    assert needle in html, f"dashboard HTML missing {needle}"

print("[PASS] v0.17 ticket queue HTML contract validated")
PY

pass "DeltaAegis v0.17 ticket queue layout validation passed"
