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

./tools/validate_v0_18_workflow_visibility.sh \
    || fail "v0.18 workflow visibility validation failed"

grep -q '"/api/ticket-status"' deltaaegis.py \
    || fail "/api/ticket-status route is missing"

grep -q 'if route == "/api/ticket-status"' deltaaegis.py \
    || fail "do_POST does not handle /api/ticket-status"

grep -q 'function ticketWorkflowActions' deltaaegis.py \
    || fail "ticketWorkflowActions helper is missing"

grep -q 'function bindTicketWorkflowActions' deltaaegis.py \
    || fail "bindTicketWorkflowActions helper is missing"

grep -q 'data-ticket-status="${esc(status)}"' deltaaegis.py \
    || fail "ticket action buttons do not expose data-ticket-status"

grep -q 'bindTicketWorkflowActions(ticketCards)' deltaaegis.py \
    || fail "ticket workflow buttons are not bound in ticket cards"

grep -q 'ticket_state = set_ticket_state' deltaaegis.py \
    || fail "legacy asset investigation POST does not sync workflow state"

python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

post_start = text.find("def do_POST")
post_end = text.find("server_address =", post_start)
assert post_start != -1 and post_end != -1, "do_POST block not found"
post_body = text[post_start:post_end]

assert 'route not in {"/api/investigate-asset", "/api/ticket-status"}' in post_body
assert 'if route == "/api/ticket-status":' in post_body
assert 'set_ticket_state(' in post_body
assert '"investigation_center": investigation_center' in post_body
assert '"ticket_state": ticket_state' in post_body

render_start = text.find("function renderInvestigationCenter")
render_end = text.find("function renderRisk", render_start)
assert render_start != -1 and render_end != -1, "renderInvestigationCenter block not found"
render_body = text[render_start:render_end]

assert "${ticketWorkflowActions(row)}" in render_body
assert "bindTicketWorkflowActions(ticketCards)" in render_body

print("[PASS] ticket workflow dashboard action contract validated")
PY

pass "DeltaAegis v0.18 ticket workflow dashboard actions validation passed"
