#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
cd "$(dirname "$0")/.."
fail(){ echo "[FAIL] DeltaAegis v1.0.2 candidate: $*" >&2; exit 1; }
pass(){ echo "[PASS] $*"; }
branch="$(git branch --show-current)"
case "$branch" in hotfix/v1.0.2-scan-orchestration|main) ;; *) fail "unsupported branch: ${branch:-DETACHED}";; esac
before="$(git status --porcelain=v1 --untracked-files=all)"
git diff --check || fail "whitespace errors"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py deltaaegis_core/*.py tools/validate_v1_0_2_scan_orchestration.py
python3 tools/validate_v1_0_2_scan_orchestration.py
DELTAAEGIS_SKIP_RELEASE_AUDIT=1 \
    ./tools/validate_v1_0_stage1_2_gate.sh --allow-dirty
DELTAAEGIS_SKIP_RELEASE_AUDIT=1 DELTAAEGIS_SKIP_RELEASE_METADATA=1 \
    ./tools/validate_v1_0_stage3_5_gate.sh --allow-dirty
python3 tools/validate_v1_0_1_dashboard_lock_hotfix.py --repo .
after="$(git status --porcelain=v1 --untracked-files=all)"
[ "$after" = "$before" ] || fail "validation changed the candidate tree"
git diff --check || fail "post-validation whitespace errors"
pass "DeltaAegis v1.0.2 candidate gate complete"
