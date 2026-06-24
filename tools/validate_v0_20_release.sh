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

pytest -q \
    || fail "pytest regression failed"

./tools/validate_v0_20_ticket_evidence_payload.sh \
    || fail "v0.20 ticket evidence payload validation failed"

./tools/validate_v0_20_dashboard_ticket_evidence.sh \
    || fail "v0.20 dashboard ticket evidence validation failed"

./tools/validate_v0_20_ticket_evidence_cli.sh \
    || fail "v0.20 ticket evidence CLI validation failed"

./tools/validate_v0_20_report_ticket_evidence.sh \
    || fail "v0.20 report ticket evidence validation failed"

./tools/validate_v0_19_release.sh "$NETSNIPER_RUN" \
    || fail "v0.19 release regression failed"

grep -q 'def dashboard_ticket_evidence_payload' deltaaegis.py \
    || fail "v0.20 backend evidence payload missing"

grep -q 'route == "/api/ticket-evidence"' deltaaegis.py \
    || fail "v0.20 dashboard evidence API route missing"

grep -q 'def command_ticket_evidence' deltaaegis.py \
    || fail "v0.20 CLI evidence command missing"

grep -q 'def append_report_ticket_evidence_appendix' deltaaegis.py \
    || fail "v0.20 report evidence appendix missing"

pass "DeltaAegis v0.20 release validation passed"
