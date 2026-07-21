#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

fail(){ echo "[FAIL] $*" >&2; exit 1; }
pass(){ echo "[PASS] $*"; }

echo "DeltaAegis v0.45.0 Release Gate"
echo "================================="

branch="$(git branch --show-current)"
case "$branch" in
  feature/v0.45-telemetry-trust|main) pass "supported branch $branch" ;;
  *) fail "unsupported branch: $branch" ;;
esac

[[ -z "$(git status --porcelain)" ]] || fail "working tree is not clean"
pass "clean working tree"
git diff --check || fail "whitespace errors"

bash -n \
  install.sh uninstall.sh \
  tools/validate_v0_45_checkpoints_1_5_all.sh \
  tools/validate_v0_45_v0_44_compatibility_all.sh \
  tools/validate_v0_45_release_gate.sh || fail "shell syntax"

PYTHONDONTWRITEBYTECODE=1 python3 -W error::SyntaxWarning -m py_compile \
  deltaaegis.py \
  deltaaegis_core/__init__.py \
  deltaaegis_core/auth.py \
  deltaaegis_core/config.py \
  deltaaegis_core/current_state.py \
  deltaaegis_core/db.py \
  deltaaegis_core/ingest.py \
  deltaaegis_core/jobs.py \
  deltaaegis_core/reports.py \
  deltaaegis_core/sites.py \
  deltaaegis_core/telemetry_quality.py \
  deltaaegis_core/web.py \
  tools/audit_v0_44_repository.py \
  tools/deltaaegis_troubleshooter.py \
  tools/validate_v0_45_release_metadata.py \
  tools/validate_v0_45_deep_bug_fixes.py || fail "Python syntax"
pass "shell and Python syntax"

PYTHONDONTWRITEBYTECODE=1 \
python3 tools/validate_v0_45_release_metadata.py || fail "release metadata"

PYTHONDONTWRITEBYTECODE=1 \
python3 tools/validate_v0_45_deep_bug_fixes.py || fail "deep bug-fix regressions"

PYTHONDONTWRITEBYTECODE=1 \
./tools/validate_v0_45_checkpoints_1_5_all.sh || fail "focused v0.45 gate"

PYTHONDONTWRITEBYTECODE=1 \
./tools/validate_v0_45_v0_44_compatibility_all.sh || fail "compatibility gate"

PYTHONDONTWRITEBYTECODE=1 \
python3 -m unittest discover -s tests -p 'test*.py' -v || fail "regression tests"
pass "regression tests"

PYTHONDONTWRITEBYTECODE=1 \
python3 tools/audit_v0_44_repository.py --check || fail "repository audit"
pass "repository audit"

[[ -z "$(git status --porcelain)" ]] || fail "validation mutated repository"
git diff --check || fail "post-validation whitespace errors"
pass "DeltaAegis v0.45.0 release gate complete"
