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

grep -q 'DeltaAegis v0.21.0 — Evidence Timeline Intelligence' README.md \
    || fail "README current-release title missing v0.21.0"

grep -q 'Current feature baseline: \*\*DeltaAegis v0.21.0 — Evidence Timeline Intelligence\*\*' README.md \
    || fail "README current feature baseline missing v0.21.0"

grep -q 'Balanced ticket evidence timelines' README.md \
    || fail "README missing v0.21 balanced timeline summary"

grep -q 'Deterministic \*\*Why Now\*\* summaries' README.md \
    || fail "README missing v0.21 Why Now summary"

head -1 CHANGELOG.md | grep -q '## v0.21.0 — Evidence Timeline Intelligence' \
    || fail "CHANGELOG does not start with v0.21.0"

grep -q 'DeltaAegis v0.21.0: Evidence Timeline Intelligence' deltaaegis.py \
    || fail "deltaaegis.py top docstring is not v0.21.0"

grep -q 'DeltaAegis v0.21.0 Evidence Timeline Intelligence' deltaaegis.py \
    || fail "CLI parser metadata is not v0.21.0"

grep -q 'def ticket_evidence_balance_timeline' deltaaegis.py \
    || fail "balanced evidence timeline helper missing"

grep -q 'def ticket_evidence_why_now_summary' deltaaegis.py \
    || fail "why-now summary helper missing"

grep -q 'summary.why_now' deltaaegis.py \
    || fail "dashboard does not render summary.why_now"

for validator in \
    tools/validate_v0_21_balanced_evidence_timeline.sh \
    tools/validate_v0_21_why_now_summary.sh \
    tools/validate_v0_21_dashboard_timeline_polish.sh
do
    [ -x "$validator" ] || fail "missing executable validator: $validator"
done

pass "DeltaAegis v0.21 release metadata validation passed"
