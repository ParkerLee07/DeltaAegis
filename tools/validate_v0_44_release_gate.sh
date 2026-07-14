#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

allow_dirty=0
case "${1:-}" in
  "") ;;
  --allow-dirty) allow_dirty=1 ;;
  *) echo "Usage: $0 [--allow-dirty]" >&2; exit 2 ;;
esac

echo "DeltaAegis v0.44 Release Gate"
echo "=============================="

branch="$(git branch --show-current)"
case "$branch" in
  feature/v0.44-module-boundary-extraction|main)
    echo "PASS: supported release branch $branch"
    ;;
  *)
    echo "ERROR: v0.44 release gate does not support branch $branch" >&2
    exit 1
    ;;
esac

if [[ "$allow_dirty" -eq 0 ]]; then
  if [[ -n "$(git status --short)" ]]; then
    echo "ERROR: v0.44 release gate requires a clean working tree" >&2
    git status --short >&2
    exit 1
  fi
  echo "PASS: clean working tree"
else
  echo "NOTICE: dirty-tree check bypassed for transactional installer validation"
fi

echo "[v0.44 release] whitespace and conflict-marker check"
git diff --check

echo "[v0.44 release] Python and shell syntax"
mapfile -t core_python < <(find deltaaegis_core -maxdepth 1 -type f -name '*.py' -print | sort)
python3 -W error::SyntaxWarning -m py_compile \
  deltaaegis.py \
  "${core_python[@]}" \
  tools/audit_v0_44_repository.py \
  tools/validate_v0_44_stage1_2.py \
  tools/validate_v0_44_stage3_auth.py \
  tools/validate_v0_44_stage4_ingest.py \
  tools/validate_v0_44_stage5_7.py \
  tools/validate_v0_44_stage8_web.py \
  tools/validate_v0_44_architecture.py \
  tools/validate_v0_44_documentation.py \
  tools/validate_v0_44_release_metadata.py
bash -n \
  install.sh \
  uninstall.sh \
  tools/validate_v0_44_release_gate.sh
echo "PASS: source and validator syntax"

echo "[v0.44 release] focused extraction boundaries"
python3 tools/validate_v0_44_stage1_2.py
python3 tools/validate_v0_44_stage3_auth.py
python3 tools/validate_v0_44_stage4_ingest.py
python3 tools/validate_v0_44_stage5_7.py
python3 tools/validate_v0_44_stage8_web.py

echo "[v0.44 release] architecture dependency and facade ownership"
python3 tools/validate_v0_44_architecture.py

echo "[v0.44 release] deterministic repository audit"
python3 tools/audit_v0_44_repository.py --check

echo "[v0.44 release] documentation accuracy"
python3 tools/validate_v0_44_documentation.py

echo "[v0.44 release] source and flat release metadata"
python3 tools/validate_v0_44_release_metadata.py

echo "[v0.44 release] isolated predecessor behavior compatibility"
python3 tools/validate_v0_43_v0_42_compatibility.py

echo
echo "PASS: DeltaAegis v0.44 automated release gate"
echo "HOLD: obtain Parker's explicit approval before merge, tag, push, or publication"
