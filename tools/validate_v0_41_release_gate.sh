#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "DeltaAegis v0.41 Release Gate"
echo "=============================="

if [ "$#" -ne 0 ]; then
    echo "Usage: $0" >&2
    exit 2
fi

if [ -n "$(git status --short)" ]; then
    echo "ERROR: v0.41 release gate requires a clean working tree." >&2
    git status --short >&2
    exit 1
fi

echo "PASS: clean working tree"

echo "[v0.41 release] whitespace and conflict-marker check"
git diff --check

echo "[v0.41 release] source syntax check"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py

echo "[v0.41 release] documentation accuracy"
tools/validate_v0_41_documentation_accuracy.sh

echo "[v0.41 release] metadata and release-path audit"
tools/validate_v0_41_release_metadata.sh

echo "[v0.41 release] rendered dashboard JavaScript syntax"
tools/validate_v0_40_dashboard_javascript_syntax.sh

echo "[v0.41 release] client-disconnect response handling"
tools/validate_v0_40_broken_pipe_response.sh

validators=(
    tools/validate_v0_41_backup_foundation.sh
    tools/validate_v0_41_backup_manifest.sh
    tools/validate_v0_41_restore_rehearsal.sh
    tools/validate_v0_41_backup_catalog.sh
    tools/validate_v0_41_backup_retention_preview.sh
    tools/validate_v0_41_backup_retention_execution.sh
    tools/validate_v0_41_restore_cutover_preview.sh
    tools/validate_v0_41_restore_cutover_execution.sh
)

for validator in "${validators[@]}"; do
    echo "[v0.41 release] $(basename "$validator")"
    "$validator"
done

echo "[v0.41 compatibility] isolated v0.40 operator-action checkpoint suite"
tools/validate_v0_41_v0_40_compatibility.sh

echo "[v0.41 compatibility] v0.39 functional compatibility suite"
tools/validate_v0_40_v0_39_compatibility.sh

echo
echo "PASS: DeltaAegis v0.41 automated release gate"
echo "HOLD: complete MANUAL_VERIFICATION_v0.41.0.md and obtain Parker's explicit publication approval"
