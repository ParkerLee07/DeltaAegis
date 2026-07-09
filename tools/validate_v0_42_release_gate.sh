#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

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

echo "DeltaAegis v0.42 Release Gate"
echo "=============================="

branch="$(git branch --show-current)"

case "$branch" in
  feature/v0.42-logical-site-scopes|main)
    echo "PASS: supported release branch $branch"
    ;;
  *)
    echo "ERROR: v0.42 release gate does not support branch $branch" >&2
    exit 1
    ;;
esac

if [[ "$allow_dirty" -eq 0 ]]; then
  if [[ -n "$(git status --short)" ]]; then
    echo "ERROR: v0.42 release gate requires a clean working tree." >&2
    echo "Use --allow-dirty only for the pre-commit release-hardening checkpoint." >&2
    git status --short >&2
    exit 1
  fi

  echo "PASS: clean working tree"
else
  echo "NOTICE: dirty-tree check bypassed for pre-commit validation"
fi

echo "[v0.42 release] whitespace and conflict-marker check"
git diff --check

echo "[v0.42 release] source syntax check"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py

echo "[v0.42 release] documentation accuracy"
tools/validate_v0_42_documentation_accuracy.sh

echo "[v0.42 release] metadata and release-path audit"
tools/validate_v0_42_release_metadata.sh

echo "[v0.42 release] rendered dashboard JavaScript syntax"
tools/validate_v0_40_dashboard_javascript_syntax.sh

echo "[v0.42 release] client-disconnect response handling"
tools/validate_v0_40_broken_pipe_response.sh

echo "[v0.42 release] flat logical-site, LAN, and scan-watchdog checkpoint suite"
tools/validate_v0_42_all.sh

echo "[v0.42 compatibility] isolated v0.40 operator-action suite"
tools/validate_v0_41_v0_40_compatibility.sh

echo "[v0.42 compatibility] v0.39 functional compatibility suite"
tools/validate_v0_40_v0_39_compatibility.sh

echo
echo "PASS: DeltaAegis v0.42 automated release gate"
echo "HOLD: complete MANUAL_VERIFICATION_v0.42.0.md and obtain Parker's explicit approval before merge, tag, push, or publication"
