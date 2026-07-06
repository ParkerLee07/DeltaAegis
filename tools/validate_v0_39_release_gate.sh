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

echo "DeltaAegis v0.39 Release Gate"
echo "=============================="

if [[ "$allow_dirty" -eq 0 ]]; then
  if [[ -n "$(git status --short)" ]]; then
    echo "ERROR: v0.39 release gate requires a clean working tree." >&2
    echo "Use --allow-dirty only for the pre-commit checkpoint." >&2
    git status --short >&2
    exit 1
  fi

  echo "PASS: clean working tree"
else
  echo "NOTICE: dirty-tree check bypassed for pre-commit validation"
fi

echo "[v0.39 release] whitespace and conflict-marker check"
git diff --check

echo "[v0.39 release] source syntax check"
python3 -m py_compile deltaaegis.py

echo "[v0.39 release] metadata and branch-diff audit"
tools/validate_v0_39_release_metadata.sh

validators=(
  tools/validate_v0_39_scan_lifecycle_storage.sh
  tools/validate_v0_39_live_scan_execution.sh
  tools/validate_v0_39_scan_job_detail_api.sh
  tools/validate_v0_39_dashboard_live_viewer.sh
  tools/validate_v0_39_dashboard_http_smoke.sh
  tools/validate_v0_39_cancellation_backend.sh
  tools/validate_v0_39_cancellation_api.sh
  tools/validate_v0_39_dashboard_cancellation_ux.sh
  tools/validate_v0_39_dashboard_cancellation_http_smoke.sh
  tools/validate_v0_39_schedule_deletion_semantics.sh
  tools/validate_v0_39_schedule_deletion_http_smoke.sh
)

for validator in "${validators[@]}"; do
  echo "[v0.39 release] $(basename "$validator")"
  "$validator"
done

echo "[v0.39 compatibility] isolated v0.38 TrueAegis follow-up suite"
tools/validate_v0_39_v0_38_compatibility.sh

echo "[v0.39 release] PASS"
