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

head -n 5 deltaaegis.py | grep -q 'v0.22.0' \
    || fail "deltaaegis.py top metadata does not mention v0.22.0"

python3 deltaaegis.py --help | grep -q 'v0.22.0' \
    || fail "CLI help metadata does not mention v0.22.0"

grep -q 'DeltaAegis v0.22.0 — Operator Triage Intelligence' README.md \
    || fail "README missing v0.22.0 current release title"

grep -q 'Current feature baseline: \*\*DeltaAegis v0.22.0 — Operator Triage Intelligence\*\*' README.md \
    || fail "README current feature baseline missing v0.22.0"

head -n 1 CHANGELOG.md | grep -q '## v0.22.0 — Operator Triage Intelligence' \
    || fail "CHANGELOG does not start with v0.22.0"

grep -q './tools/validate_v0_22_triage_state_model.sh' tools/validate_v0_22_release.sh \
    || fail "v0.22 release validator does not run triage state model validator"

grep -q './tools/validate_v0_22_triage_queue_api_cli.sh' tools/validate_v0_22_release.sh \
    || fail "v0.22 release validator does not run triage queue API/CLI validator"

grep -q './tools/validate_v0_22_dashboard_triage_panel.sh' tools/validate_v0_22_release.sh \
    || fail "v0.22 release validator does not run dashboard triage panel validator"

grep -q './tools/validate_v0_22_report_triage_summary.sh' tools/validate_v0_22_release.sh \
    || fail "v0.22 release validator does not run report triage summary validator"

grep -q 'DeltaAegis v0.22 release validation passed' tools/validate_v0_22_release.sh \
    || fail "v0.22 release validator missing pass message"

pass "DeltaAegis v0.22 release metadata validation passed"
