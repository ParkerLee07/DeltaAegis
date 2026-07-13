#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

allow_dirty=0
case "${1:-}" in
  "") ;;
  --allow-dirty) allow_dirty=1 ;;
  *) echo "Usage: $0 [--allow-dirty]" >&2; exit 2 ;;
esac

echo "DeltaAegis v0.43 Release Gate"
echo "=============================="

branch="$(git branch --show-current)"
case "$branch" in
  feature/v0.43-architecture-stability-baseline|main)
    echo "PASS: supported release branch $branch"
    ;;
  *)
    echo "ERROR: v0.43 release gate does not support branch $branch" >&2
    exit 1
    ;;
esac

if [[ "$allow_dirty" -eq 0 ]]; then
  if [[ -n "$(git status --short)" ]]; then
    echo "ERROR: v0.43 release gate requires a clean working tree." >&2
    echo "Use --allow-dirty only for the pre-commit stage 6 checkpoint." >&2
    git status --short >&2
    exit 1
  fi
  echo "PASS: clean working tree"
else
  echo "NOTICE: dirty-tree check bypassed for pre-commit stage 6 validation"
fi

echo "[v0.43 release] whitespace and conflict-marker check"
git diff --check

echo "[v0.43 release] Python and shell syntax"
python3 -W error::SyntaxWarning -m py_compile \
  deltaaegis.py \
  tools/audit_v0_43_repository.py \
  tools/benchmark_v0_43.py \
  tools/validate_v0_43_baseline.py \
  tools/validate_v0_43_documentation.py \
  tools/validate_v0_43_release_metadata.py \
  tools/validate_v0_43_v0_42_compatibility.py
bash -n tools/validate_v0_43_release_gate.sh
echo "PASS: source and validator syntax"

echo "[v0.43 release] architecture and performance baseline"
python3 tools/validate_v0_43_baseline.py

echo "[v0.43 release] documentation accuracy"
python3 tools/validate_v0_43_documentation.py

echo "[v0.43 release] metadata and flat release-path audit"
python3 tools/validate_v0_43_release_metadata.py

echo "[v0.43 release] isolated predecessor behavior compatibility"
python3 tools/validate_v0_43_v0_42_compatibility.py

echo
echo "PASS: DeltaAegis v0.43 automated release gate"
echo "HOLD: obtain Parker's explicit approval before merge, tag, push, or publication"
