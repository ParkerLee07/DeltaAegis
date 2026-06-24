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

# Important:
# Do not call validate_v0_22_release.sh here. That validator checks v0.22
# release metadata, which is expected to change once v0.23 metadata is applied.
# Compatibility means v0.22 behavior and UI contracts still pass.

./tools/validate_v0_22_triage_state_model.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.22 triage state model compatibility validation failed"

./tools/validate_v0_22_triage_queue_api_cli.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.22 triage queue API/CLI compatibility validation failed"

./tools/validate_v0_22_dashboard_triage_panel.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.22 dashboard triage panel compatibility validation failed"

./tools/validate_v0_22_report_triage_summary.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.22 report triage summary compatibility validation failed"

pass "DeltaAegis v0.23 backward compatibility validation passed"
