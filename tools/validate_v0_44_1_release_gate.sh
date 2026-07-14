#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

allow_dirty=0
case "${1:-}" in
  "") ;;
  --allow-dirty) allow_dirty=1 ;;
  *) echo "Usage: $0 [--allow-dirty]" >&2; exit 2 ;;
esac

echo "DeltaAegis v0.44.1 Release Gate"
echo "================================"

branch="$(git branch --show-current)"
case "$branch" in
  maintenance/v0.44.1-repository-hygiene|main)
    echo "PASS: supported release branch $branch"
    ;;
  *)
    echo "ERROR: v0.44.1 release gate does not support branch $branch" >&2
    exit 1
    ;;
esac

if [[ "$allow_dirty" -eq 0 ]]; then
  if [[ -n "$(git status --short)" ]]; then
    echo "ERROR: v0.44.1 release gate requires a clean working tree" >&2
    git status --short >&2
    exit 1
  fi
  echo "PASS: clean working tree"
else
  echo "NOTICE: dirty-tree check bypassed for transactional installer validation"
fi

echo "[v0.44.1 release] whitespace and conflict-marker check"
git diff --check
git show --check --format= HEAD
if git grep -n -E '^(<<<<<<< |>>>>>>> |=======)$' -- .; then
  echo "ERROR: unresolved conflict marker found" >&2
  exit 1
fi

echo "[v0.44.1 release] Python and shell syntax"
mapfile -t core_python < <(
  find deltaaegis_core -maxdepth 1 -type f -name '*.py' -print | sort
)
mapfile -t tool_python < <(
  find tools -maxdepth 1 -type f -name '*.py' -print | sort
)
python3 -W error::SyntaxWarning -m py_compile \
  deltaaegis.py \
  "${core_python[@]}" \
  "${tool_python[@]}"

mapfile -t shell_validators < <(
  find tools -maxdepth 1 -type f -name 'validate_*.sh' -print | sort
)
for shell_source in install.sh uninstall.sh "${shell_validators[@]}"; do
  bash -n "$shell_source"
done
echo "PASS: source and validator syntax"

echo "[v0.44.1 release] repository hygiene and retention"
python3 tools/validate_v0_44_1_repository_hygiene.py
python3 tools/validate_v0_44_1_report_contracts.py
python3 tools/validate_v0_44_1_validator_retirement.py

echo "[v0.44.1 release] retained data durability and recovery"
python3 tools/validate_v0_44_1_data_durability_compatibility.py

echo "[v0.44.1 release] focused modular-core boundaries"
python3 tools/validate_v0_44_stage1_2.py
python3 tools/validate_v0_44_stage3_auth.py
python3 tools/validate_v0_44_stage4_ingest.py
python3 tools/validate_v0_44_stage5_7.py
python3 tools/validate_v0_44_stage8_web.py
python3 tools/validate_v0_44_architecture.py

echo "[v0.44.1 release] deterministic repository audit"
python3 tools/audit_v0_44_repository.py --check

echo "[v0.44.1 release] release metadata"
python3 tools/validate_v0_44_1_release_metadata.py

echo "[v0.44.1 release] regression tests"
python3 -m unittest discover -s tests -p 'test*.py' -v

echo "[v0.44.1 release] isolated predecessor behavior compatibility"
python3 tools/validate_v0_43_v0_42_compatibility.py

echo
echo "PASS: DeltaAegis v0.44.1 automated release gate"
echo "HOLD: obtain Parker's explicit approval before merge, tag, push, or publication"
