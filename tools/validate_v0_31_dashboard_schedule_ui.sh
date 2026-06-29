#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

ok() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

grep -Fq 'id="netsniper-schedule-create-form"' deltaaegis.py \
    || fail "missing scheduled scan create form"

grep -Fq 'id="netsniper-schedules-body"' deltaaegis.py \
    || fail "missing scheduled scan table body"

grep -Fq 'id="netsniper-schedule-result"' deltaaegis.py \
    || fail "missing schedule action result output"

grep -Fq 'id="netsniper-schedules-run-due"' deltaaegis.py \
    || fail "missing run-due dashboard button"

grep -Fq 'function renderNetSniperSchedules(payload)' deltaaegis.py \
    || fail "missing renderNetSniperSchedules JS function"

grep -Fq 'async function loadNetSniperSchedules()' deltaaegis.py \
    || fail "missing loadNetSniperSchedules JS function"

grep -Fq 'async function createNetSniperSchedule(event)' deltaaegis.py \
    || fail "missing createNetSniperSchedule JS function"

grep -Fq 'async function runDueNetSniperSchedules()' deltaaegis.py \
    || fail "missing runDueNetSniperSchedules JS function"

grep -Fq 'async function handleNetSniperScheduleAction(event)' deltaaegis.py \
    || fail "missing handleNetSniperScheduleAction JS function"

grep -Fq 'fetch("/api/netsniper/schedules"' deltaaegis.py \
    || fail "dashboard UI does not load schedules API"

grep -Fq '"/api/netsniper/schedule-create"' deltaaegis.py \
    || fail "dashboard UI does not call schedule-create API"

grep -Fq '"/api/netsniper/schedule-run-due"' deltaaegis.py \
    || fail "dashboard UI does not call schedule-run-due API"

grep -Fq 'data-schedule-action' deltaaegis.py \
    || fail "dashboard schedule row action buttons missing"

grep -Fq 'window.setInterval(loadNetSniperSchedules, 15000)' deltaaegis.py \
    || fail "dashboard schedule refresh interval missing"

if grep -Fq '<option value="deep"' deltaaegis.py; then
    fail "dashboard schedule profile selector exposes deep profile"
fi

ok "DeltaAegis v0.31 dashboard schedule UI validation passed"
