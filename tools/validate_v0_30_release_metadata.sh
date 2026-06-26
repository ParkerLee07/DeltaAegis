#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

grep -Fq 'Current Release — v0.30.0' README.md \
    || fail "README does not advertise v0.30.0 as current release"

grep -Fq 'DeltaAegis v0.30.0 — NetSniper Profile-Aware Scan Jobs' README.md \
    || fail "README missing v0.30.0 release title"

grep -Fq 'deltaaegis scan-start --profile quick|balanced|accurate' README.md \
    || fail "README missing v0.30 CLI profile highlight"

grep -Fq '## v0.30.0 - 2026-06-26' CHANGELOG.md \
    || fail "CHANGELOG missing v0.30.0 entry"

grep -Fq 'v0.30 Profile-Aware Scans' deltaaegis.py \
    || fail "dashboard release badge does not advertise v0.30"

grep -Fq 'tools/validate_v0_30_scan_profile_backend.sh' tools/validate_v0_30_release.sh \
    || fail "v0.30 release gate missing backend validator"

grep -Fq 'tools/validate_v0_30_dashboard_scan_profile_ui.sh' tools/validate_v0_30_release.sh \
    || fail "v0.30 release gate missing dashboard scan profile validator"

grep -Fq 'validate_v0_29_scan_start_foundation.sh' tools/validate_v0_30_release.sh \
    || fail "v0.30 release gate missing v0.29 scan-start foundation regression"

grep -Fq 'validate_v0_29_dashboard_scan_start_background.sh' tools/validate_v0_30_release.sh \
    || fail "v0.30 release gate missing v0.29 dashboard scan-start background regression"

grep -Fq 'validate_v0_29_netsniper_scan_ui.sh' tools/validate_v0_30_release.sh \
    || fail "v0.30 release gate missing v0.29 NetSniper scan UI regression"

pass "DeltaAegis v0.30 release metadata validation passed"
