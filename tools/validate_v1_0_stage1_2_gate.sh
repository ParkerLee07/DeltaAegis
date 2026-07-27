#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
    echo "[FAIL] v1 Stage 1–2 gate: $*" >&2
    exit 1
}

allow_dirty=0
case "${1:-}" in
    "") ;;
    --allow-dirty) allow_dirty=1 ;;
    *) echo "Usage: $0 [--allow-dirty]" >&2; exit 2 ;;
esac

expected_release_merge="493df20dabed527757381e3cbae7cad3201b9c57"
expected_disposable_witness="74cba5ec5aa3d35cd57416c3891c161d8bf5fd4b"
expected_release_tree="ab2c059806e0bbd3908f32200d79cb357e8fa61c"

echo "DeltaAegis v1.0 Combined Stage 1–2 Candidate Gate"
echo "====================================================="

branch="$(git branch --show-current)"
case "$branch" in
    main|feature/v1.0-stages-1-2)
        echo "[PASS] supported validation branch: $branch"
        ;;
    *)
        fail "unsupported validation branch: ${branch:-DETACHED}"
        ;;
esac

baseline_ok=0
if git cat-file -e "${expected_release_merge}^{commit}" 2>/dev/null \
    && git merge-base --is-ancestor "$expected_release_merge" HEAD
then
    baseline_ok=1
    echo "[PASS] candidate descends from the released v0.45.0 merge commit"
elif git cat-file -e "${expected_disposable_witness}^{commit}" 2>/dev/null \
    && git merge-base --is-ancestor "$expected_disposable_witness" HEAD \
    && [[ "$(git rev-parse "${expected_disposable_witness}^{tree}")" == "$expected_release_tree" ]]
then
    baseline_ok=1
    echo "[PASS] disposable baseline has the exact released v0.45.0 tree"
fi
[[ "$baseline_ok" -eq 1 ]] || fail "candidate is not based on the audited v0.45.0 release tree"

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
./tools/validate_v1_0_stage1_2_all.sh
python3 tools/audit_v0_44_repository.py --check

after_status="$(git status --porcelain=v1 --untracked-files=all)"
[[ "$after_status" == "$before_status" ]] \
    || fail "validation changed the candidate checkout"
git diff --check || fail "post-validation whitespace errors"

echo
echo "[PASS] DeltaAegis v1.0 combined Stage 1–2 candidate gate"
echo "NOTICE: Stages 3 and later remain mandatory before v1.0.0 GA."
