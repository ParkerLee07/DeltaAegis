#!/usr/bin/env bash
set -euo pipefail

repo="${1:-$(pwd)}"
cd "$repo"

python3 tools/validate_v1_0_release_blocker_hotfix.py --repo "$repo"
python3 -m py_compile deltaaegis.py deltaaegis_core/current_state.py

git diff --check

if [[ -x tools/validate_v1_stage3_5_all.sh ]]; then
  exec tools/validate_v1_stage3_5_all.sh
fi
if [[ -f tools/validate_v1_stage3_5.py ]]; then
  exec python3 tools/validate_v1_stage3_5.py
fi

echo "Targeted hotfix validation passed. No recognized Stage 3-5 full gate was found."
