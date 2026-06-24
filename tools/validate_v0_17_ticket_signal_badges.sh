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

./tools/validate_v0_17_ticket_signal_tuning.sh \
    || fail "v0.17 ticket signal tuning validator failed"

./tools/validate_v0_17_ticket_queue_layout.sh \
    || fail "v0.17 ticket queue layout validator failed"

grep -q 'v0.17 ticket signal state labels' deltaaegis.py \
    || fail "ticket signal badge CSS marker is missing"

grep -q 'ticket-signal-actionable' deltaaegis.py \
    || fail "actionable ticket signal style is missing"

grep -q 'ticket-signal-meaningful-change' deltaaegis.py \
    || fail "meaningful-change ticket signal style is missing"

grep -q 'ticket-signal-baseline-context' deltaaegis.py \
    || fail "baseline-context ticket signal style is missing"

grep -q 'function ticketSignalLabel(row)' deltaaegis.py \
    || fail "ticketSignalLabel helper is missing"

grep -q 'function ticketSignalBadge(row)' deltaaegis.py \
    || fail "ticketSignalBadge helper is missing"

grep -q '<th>Signal</th>' deltaaegis.py \
    || fail "ticket table Signal header is missing"

grep -q 'ticketSignalBadge(row)' deltaaegis.py \
    || fail "ticket signal badge is not rendered"

grep -q '\["Meaningful Changes", summary.meaningful_change || 0\]' deltaaegis.py \
    || fail "Meaningful Changes summary card is missing"

grep -q '\["Baseline Context", summary.baseline_context || 0\]' deltaaegis.py \
    || fail "Baseline Context summary card is missing"

python3 - <<'PY'
import deltaaegis

html = deltaaegis.dashboard_index_html()

required = [
    "ticket-signal-badge",
    "ticket-signal-actionable",
    "ticket-signal-meaningful-change",
    "ticket-signal-baseline-context",
    "function ticketSignalLabel",
    "function ticketSignalBadge",
    "<th>Signal</th>",
    "Meaningful Changes",
    "Baseline Context",
]

for needle in required:
    assert needle in html, f"dashboard HTML missing {needle}"

print("[PASS] v0.17 ticket signal badge HTML contract validated")
PY

pass "DeltaAegis v0.17 ticket signal badge validation passed"
