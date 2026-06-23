#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

[[ -f README.md ]] || fail "README.md missing"

grep -q '^# DeltaAegis$' README.md \
  || fail "README title is missing or malformed"

grep -q 'DeltaAegis v0.13.0 — Current-State SIEM Dashboard' README.md \
  || fail "README does not identify v0.13.0 as current release"

grep -q 'DeltaAegis v0.12.0 — Intelligence Drilldown' README.md \
  || fail "README does not preserve the v0.12.0 feature baseline"

grep -q 'intelligence-hosts' README.md \
  || fail "README does not document intelligence-hosts"

grep -q 'intelligence-host 192.168.4.1' README.md \
  || fail "README does not document intelligence-host drilldown"

grep -q 'Dashboard' README.md \
  || fail "README does not document dashboard"

grep -q 'v0.11.x — Intelligence Review Dashboard' README.md \
  || fail "README does not summarize v0.11.x"

grep -q 'v0.10.0 — NetSniper v1.6 Intelligence Integration' README.md \
  || fail "README does not summarize v0.10.0"

grep -q 'v0.9.0 — Investigation Workflow' README.md \
  || fail "README does not summarize v0.9.0"

if grep -q 'Current release: \*\*DeltaAegis v0.11.0' README.md; then
  fail "README still claims v0.11.0 is current"
fi

if grep -q 'DeltaAegis v0.8.5' README.md; then
  fail "README still contains stale v0.8.5 content"
fi

if grep -q '## DeltaAegis v0.9.0 Investigation Workflow' README.md; then
  fail "README still opens with stale v0.9.0 release block"
fi

if grep -qi 'read-only local dashboard' README.md; then
  fail "README still says dashboard is read-only"
fi

python3 - <<'PY2'
from pathlib import Path

text = Path("README.md").read_text(encoding="utf-8")
lines = text.splitlines()

if len(lines) < 120:
    raise SystemExit("README appears too short after cleanup")

long_lines = [(i + 1, len(line)) for i, line in enumerate(lines) if len(line) > 220]
if long_lines:
    first = long_lines[0]
    raise SystemExit(f"README has overly long line at {first[0]} length {first[1]}")

fences = [i + 1 for i, line in enumerate(lines) if line.strip().startswith("```")]
if len(fences) % 2:
    raise SystemExit(f"README has unbalanced Markdown fences at lines {fences}")

print("[PASS] README formatting sanity checks passed")
PY2

pass "README current-release metadata validated"
