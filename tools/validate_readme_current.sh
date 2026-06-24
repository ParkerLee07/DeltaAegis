#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

grep -q 'DeltaAegis v0.19.0 — Workflow Filters and Operator Views' README.md \
  || fail "README does not identify v0.19.0 as current release"

grep -q 'Current feature baseline: \*\*DeltaAegis v0.19.0 — Workflow Filters and Operator Views\*\*' README.md \
  || fail "README current feature baseline does not identify v0.19.0"

grep -q 'ticket_status' README.md \
  || fail "README does not mention ticket_status filtering"

grep -q 'ticket_signal' README.md \
  || fail "README does not mention ticket_signal filtering"

grep -q 'visible filtered queue' README.md \
  || fail "README does not describe visible filtered queue behavior"

grep -q 'v0.19.0 — Workflow Filters and Operator Views' CHANGELOG.md \
  || fail "CHANGELOG does not mention v0.19.0"

grep -q 'DeltaAegis v0.19.0' deltaaegis.py \
  || fail "deltaaegis.py metadata does not mention v0.19.0"

if sed -n '/## Current Release/,/^## /p' README.md | grep -q '^\*\*DeltaAegis v0.18.0 — Investigation Workflow Actions\*\*$'; then
  fail "README Current Release title still identifies v0.18.0"
fi

if sed -n '/## Current Release/,/^## /p' README.md | grep -q 'Current feature baseline: \*\*DeltaAegis v0.18.0 — Investigation Workflow Actions\*\*'; then
  fail "README Current Release baseline still identifies v0.18.0"
fi

pass "README current-release metadata validated"
