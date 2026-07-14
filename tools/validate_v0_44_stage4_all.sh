#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

allow_dirty=0
case "${1:-}" in
  "") ;;
  --allow-dirty) allow_dirty=1 ;;
  *) echo "Usage: $0 [--allow-dirty]" >&2; exit 2 ;;
esac

echo "DeltaAegis v0.44 Stage 4 Gate"
echo "================================"

branch="$(git branch --show-current)"
case "$branch" in
  feature/v0.44-module-boundary-extraction|main)
    echo "PASS: supported checkpoint branch $branch"
    ;;
  *)
    echo "ERROR: unsupported v0.44 checkpoint branch: $branch" >&2
    exit 1
    ;;
esac

if [[ "$allow_dirty" -eq 0 ]]; then
  if [[ -n "$(git status --short)" ]]; then
    echo "ERROR: v0.44 stage 4 gate requires a clean working tree" >&2
    git status --short >&2
    exit 1
  fi
  echo "PASS: clean working tree"
else
  echo "NOTICE: dirty-tree check bypassed for installer validation"
fi

git diff --check
python3 -W error::SyntaxWarning -m py_compile \
  deltaaegis.py \
  deltaaegis_core/__init__.py \
  deltaaegis_core/auth.py \
  deltaaegis_core/config.py \
  deltaaegis_core/db.py \
  deltaaegis_core/ingest.py \
  tools/validate_v0_44_stage1_2.py \
  tools/validate_v0_44_stage3_auth.py \
  tools/validate_v0_44_stage4_ingest.py
bash -n \
  install.sh \
  tools/validate_v0_44_stage4_all.sh
echo "PASS: syntax and whitespace"

python3 tools/validate_v0_44_stage1_2.py
python3 tools/validate_v0_44_stage3_auth.py
python3 tools/validate_v0_44_stage4_ingest.py
python3 tools/audit_v0_44_repository.py --check
echo "PASS: deterministic repository audit"

echo "[v0.44 stage 4] predecessor behavior compatibility"
python3 tools/validate_v0_43_v0_42_compatibility.py

echo
echo "PASS: DeltaAegis v0.44 stage 4 gate"
