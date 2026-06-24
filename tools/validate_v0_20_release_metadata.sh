#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

NETSNIPER_RUN="${1:-/home/parker/NetSniper/runs/20260623-123007}"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

grep -q 'DeltaAegis v0.20.0 — Ticket Evidence Drilldown' README.md \
    || fail "README current-release title missing v0.20.0"

grep -q 'Current feature baseline: \*\*DeltaAegis v0.20.0 — Ticket Evidence Drilldown\*\*' README.md \
    || fail "README current feature baseline missing v0.20.0"

grep -q '/api/ticket-evidence' README.md \
    || fail "README does not document ticket evidence API"

grep -q '`ticket-evidence` CLI command' README.md \
    || fail "README does not document ticket-evidence CLI"

grep -q 'Ticket Evidence Appendix' README.md \
    || fail "README does not document Ticket Evidence Appendix"

head -1 CHANGELOG.md | grep -q '## v0.20.0 — Ticket Evidence Drilldown' \
    || fail "CHANGELOG does not start with v0.20.0"

grep -q 'tools/validate_v0_20_release.sh' CHANGELOG.md \
    || fail "CHANGELOG does not list v0.20 release validator"

grep -q 'DeltaAegis v0.20.0: Ticket Evidence Drilldown' deltaaegis.py \
    || fail "deltaaegis.py top docstring is not v0.20.0"

grep -q 'DeltaAegis v0.20.0 Ticket Evidence Drilldown' deltaaegis.py \
    || fail "CLI parser metadata is not v0.20.0"

./tools/validate_v0_20_release.sh "$NETSNIPER_RUN" \
    || fail "v0.20 release gate failed after metadata update"

pass "DeltaAegis v0.20 release metadata validation passed"
