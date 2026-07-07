#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CURRENT_BRANCH="$(git -C "$REPO_ROOT" branch --show-current)"
TEMP_ROOT="$(mktemp -d -t deltaaegis-v040-v039-compat-XXXXXX)"
SANDBOX="$TEMP_ROOT/repo"

cleanup() {
  rm -rf "$TEMP_ROOT"
}
trap cleanup EXIT

echo "DeltaAegis v0.40 / v0.39 Functional Compatibility"
echo "===================================================="

git clone --quiet --shared "$REPO_ROOT" "$SANDBOX"
cp "$REPO_ROOT/deltaaegis.py" "$SANDBOX/deltaaegis.py"

python3 - "$SANDBOX" "$CURRENT_BRANCH" <<'PY'
from pathlib import Path
import sys


root = Path(sys.argv[1])
current_branch = sys.argv[2]
old_branch = "feature/v0.39-job-lifecycle-observability"

for path in (root / "tools").glob("validate_v0_39*"):
    if not path.is_file():
        continue

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue

    if old_branch in text:
        path.write_text(
            text.replace(old_branch, current_branch),
            encoding="utf-8",
        )
PY

cd "$SANDBOX"

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
  if [[ ! -x "$validator" ]]; then
    echo "FAIL: missing or non-executable compatibility validator: $validator" >&2
    exit 1
  fi

  echo "[v0.39 compatibility] $(basename "$validator")"
  "$validator"
done

echo "PASS: DeltaAegis v0.40 preserves the v0.39 functional suite"
