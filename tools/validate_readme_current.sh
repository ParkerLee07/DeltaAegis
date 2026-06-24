#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

grep -q 'DeltaAegis v0.18.0 — Investigation Workflow Actions' README.md \
  || fail "README does not identify v0.18.0 as current release"

grep -q 'Current feature baseline: \*\*DeltaAegis v0.18.0 — Investigation Workflow Actions\*\*' README.md \
  || fail "README current feature baseline does not identify v0.18.0"

grep -q 'Persistent investigation ticket states' README.md \
  || fail "README does not describe persistent investigation ticket states"

grep -q '/api/ticket-status' README.md \
  || fail "README does not mention /api/ticket-status"

grep -q 'v0.18.0 — Investigation Workflow Actions' CHANGELOG.md \
  || fail "CHANGELOG does not mention v0.18.0"

grep -q 'DeltaAegis v0.18.0' deltaaegis.py \
  || fail "deltaaegis.py metadata does not mention v0.18.0"

if sed -n '/## Current Release/,/^## /p' README.md | grep -q 'DeltaAegis v0.17.0 — Executive SIEM Dashboard Refresh'; then
  fail "README Current Release section still identifies v0.17.0"
fi

pass "README current-release metadata validated"
