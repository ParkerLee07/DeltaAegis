#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

allow_dirty=0

case "${1:-}" in
  "")
    ;;
  --allow-dirty)
    allow_dirty=1
    ;;
  *)
    echo "Usage: $0 [--allow-dirty]" >&2
    exit 2
    ;;
esac

echo "DeltaAegis v0.40 Release Gate"
echo "=============================="

if [[ "$allow_dirty" -eq 0 ]]; then
  if [[ -n "$(git status --short)" ]]; then
    echo "ERROR: v0.40 release gate requires a clean working tree." >&2
    echo "Use --allow-dirty only for the pre-commit release-hardening checkpoint." >&2
    git status --short >&2
    exit 1
  fi

  echo "PASS: clean working tree"
else
  echo "NOTICE: dirty-tree check bypassed for pre-commit validation"
fi

echo "[v0.40 release] whitespace and conflict-marker check"
git diff --check

echo "[v0.40 release] source syntax check"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py

echo "[v0.40 release] rendered dashboard JavaScript syntax"
tools/validate_v0_40_dashboard_javascript_syntax.sh

echo "[v0.40 release] client-disconnect response handling"
tools/validate_v0_40_broken_pipe_response.sh

echo "[v0.40 release] metadata, receipt, and branch-path audit"
tools/validate_v0_40_release_metadata.sh

echo "[v0.40 release] flat readability checkpoint suite"
tools/validate_v0_40_all.sh

echo "[v0.40 release] v0.39 functional compatibility suite"
tools/validate_v0_40_v0_39_compatibility.sh

echo
echo "PASS: DeltaAegis v0.40 automated release gate"
echo "HOLD: complete MANUAL_VERIFICATION_v0.40.0.md before merge, tag, or publication"
