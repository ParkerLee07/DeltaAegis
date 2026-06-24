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

./tools/validate_v0_19_backend_filters.sh \
    || fail "v0.19 backend filter validation failed"

grep -q 'ticket_status = query.get("ticket_status", \["ALL"\])\[0\]' deltaaegis.py \
    || fail "dashboard API route does not read ticket_status"

grep -q 'ticket_signal = query.get("ticket_signal", \["ALL"\])\[0\]' deltaaegis.py \
    || fail "dashboard API route does not read ticket_signal"

grep -q 'ticket_status=ticket_status' deltaaegis.py \
    || fail "dashboard API route does not pass ticket_status to payload"

grep -q 'ticket_signal=ticket_signal' deltaaegis.py \
    || fail "dashboard API route does not pass ticket_signal to payload"

grep -q 'id="ticket-status-filter"' deltaaegis.py \
    || fail "ticket status dashboard filter control missing"

grep -q 'id="ticket-signal-filter"' deltaaegis.py \
    || fail "ticket signal dashboard filter control missing"

grep -q 'id="apply-ticket-filters"' deltaaegis.py \
    || fail "apply ticket filters button missing"

grep -q 'id="clear-ticket-filters"' deltaaegis.py \
    || fail "clear ticket filters button missing"

grep -q 'function investigationCenterFilterPath' deltaaegis.py \
    || fail "filter-aware Investigation Center path helper missing"

grep -q 'function refreshInvestigationCenter' deltaaegis.py \
    || fail "refreshInvestigationCenter helper missing"

grep -q 'function bindInvestigationCenterFilters' deltaaegis.py \
    || fail "bindInvestigationCenterFilters helper missing"

grep -q 'syncInvestigationCenterFilters(payload)' deltaaegis.py \
    || fail "renderInvestigationCenter does not sync active filters"

grep -q 'api(investigationCenterFilterPath())' deltaaegis.py \
    || fail "initial dashboard load does not use filter-aware path"

grep -q 'params.set("ticket_status", status)' deltaaegis.py \
    || fail "ticket_status query parameter is not set by dashboard filter helper"

grep -q 'params.set("ticket_signal", signal)' deltaaegis.py \
    || fail "ticket_signal query parameter is not set by dashboard filter helper"

grep -q 'await refreshInvestigationCenter()' deltaaegis.py \
    || fail "ticket workflow action does not refresh current filtered view"

grep -q 'bindInvestigationCenterFilters();' deltaaegis.py \
    || fail "dashboard filter controls are not bound after initial render"

pass "DeltaAegis v0.19 dashboard filter validation passed"
