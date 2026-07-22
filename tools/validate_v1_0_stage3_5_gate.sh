#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
    echo "[FAIL] v1 Stage 3–5 gate: $*" >&2
    exit 1
}

allow_dirty=0
case "${1:-}" in
    "") ;;
    --allow-dirty) allow_dirty=1 ;;
    *) echo "Usage: $0 [--allow-dirty]" >&2; exit 2 ;;
esac

expected_stage12_witness="1ed1c6ad389ef6aa6ddbf99526404c102e0f7fc2"
expected_stage12_live="989854a723e471b93f286ee4ba9b48bc257e5a73"
expected_stage12_tree="e259130de5e54c6673a5e294c88244f6b0ab4048"

echo "DeltaAegis v1.0 Combined Stage 3–5 Candidate Gate"
echo "====================================================="

branch="$(git branch --show-current)"
case "$branch" in
    main|feature/v1.0-stages-3-5)
        echo "[PASS] supported validation branch: $branch"
        ;;
    *)
        fail "unsupported validation branch: ${branch:-DETACHED}"
        ;;
esac

baseline_found=0
for candidate in "$expected_stage12_live" "$expected_stage12_witness"; do
    if git cat-file -e "${candidate}^{commit}" 2>/dev/null \
        && git merge-base --is-ancestor "$candidate" HEAD \
        && [[ "$(git rev-parse "${candidate}^{tree}")" == \
              "$expected_stage12_tree" ]]
    then
        baseline_found=1
        break
    fi
done
if [[ "$baseline_found" -ne 1 ]]; then
    fail "candidate is not based on the exact audited Stage 1–2 tree"
fi
echo "[PASS] exact Stage 1–2 baseline is preserved"

before_status="$(git status --porcelain=v1 --untracked-files=all)"
if [[ "$allow_dirty" -eq 0 && -n "$before_status" ]]; then
    git status --short --branch >&2
    fail "candidate gate requires a clean checkout"
fi
if [[ "$allow_dirty" -eq 1 ]]; then
    echo "NOTICE: dirty-tree precondition bypassed for disposable candidate validation"
else
    echo "[PASS] clean candidate checkout"
fi

git diff --check || fail "whitespace errors"
started="$(date +%s)"
./tools/validate_v1_0_stage3_5_all.sh
elapsed="$(( $(date +%s) - started ))"
maximum="$(python3 - <<'PY'
from deltaaegis_core.operations import PERFORMANCE_TARGETS
print(int(PERFORMANCE_TARGETS["targets"]["combined_release_gate_max_seconds"]))
PY
)"
[[ "$elapsed" -le "$maximum" ]] \
    || fail "combined gate exceeded ${maximum}s: ${elapsed}s"
echo "[PASS] combined validation duration ${elapsed}s <= ${maximum}s"

python3 tools/audit_v0_44_repository.py --check

after_status="$(git status --porcelain=v1 --untracked-files=all)"
[[ "$after_status" == "$before_status" ]] \
    || fail "validation changed the candidate checkout"
git diff --check || fail "post-validation whitespace errors"

echo
echo "[PASS] DeltaAegis v1.0 combined Stage 3–5 candidate gate"
echo "NOTICE: the mandatory 24-hour GA soak is intentionally tracked separately."
