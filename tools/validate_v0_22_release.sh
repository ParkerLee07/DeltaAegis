#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

NETSNIPER_RUN_DIR="${1:-/home/parker/NetSniper/runs/20260623-123007}"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

if [ -d tests ]; then
    python3 -m pytest -q \
        || fail "pytest suite failed"
fi

./tools/validate_v0_22_triage_state_model.sh \
    || fail "v0.22 triage state model validator failed"

./tools/validate_v0_22_triage_queue_api_cli.sh \
    || fail "v0.22 triage queue API/CLI validator failed"

./tools/validate_v0_22_dashboard_triage_panel.sh \
    || fail "v0.22 dashboard triage panel validator failed"

./tools/validate_v0_22_report_triage_summary.sh \
    || fail "v0.22 report triage summary validator failed"

./tools/validate_v0_21_balanced_evidence_timeline.sh \
    || fail "v0.21 balanced evidence timeline compatibility failed"

./tools/validate_v0_21_why_now_summary.sh \
    || fail "v0.21 why-now summary compatibility failed"

./tools/validate_v0_21_dashboard_timeline_polish.sh \
    || fail "v0.21 dashboard timeline polish compatibility failed"

./tools/validate_v0_20_ticket_evidence_payload.sh \
    || fail "v0.20 ticket evidence payload compatibility failed"

./tools/validate_v0_20_dashboard_ticket_evidence.sh \
    || fail "v0.20 dashboard ticket evidence compatibility failed"

./tools/validate_v0_20_ticket_evidence_cli.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.20 ticket evidence CLI compatibility failed"

./tools/validate_v0_20_report_ticket_evidence.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.20 report ticket evidence compatibility failed"

./tools/validate_v0_22_release_metadata.sh \
    || fail "v0.22 release metadata validation failed"

pass "DeltaAegis v0.22 release validation passed"
