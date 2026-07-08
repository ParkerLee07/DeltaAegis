#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "DeltaAegis v0.41 v0.40 Compatibility Validator"
echo "================================================"

if [ -n "$(git status --short)" ]; then
    echo "ERROR: v0.40 compatibility validation requires a clean tree." >&2
    git status --short >&2
    exit 1
fi

source_repo="$(pwd)"
temporary_root="$(
    mktemp -d /tmp/deltaaegis-v041-v040-compatibility.XXXXXX
)"
compatibility_repo="$temporary_root/DeltaAegis"

cleanup() {
    rm -rf -- "$temporary_root"
}

trap cleanup EXIT

git clone \
    --quiet \
    --no-hardlinks \
    --local \
    "$source_repo" \
    "$compatibility_repo"

git -C "$compatibility_repo" checkout \
    --quiet \
    -B main \
    HEAD

compatibility_branch="$(
    git -C "$compatibility_repo" branch --show-current
)"

if [ "$compatibility_branch" != "main" ]; then
    echo "ERROR: isolated compatibility clone is not on main." >&2
    echo "Current branch: $compatibility_branch" >&2
    exit 1
fi

if [ -n "$(git -C "$compatibility_repo" status --short)" ]; then
    echo "ERROR: isolated v0.40 compatibility clone is not clean." >&2
    git -C "$compatibility_repo" status --short >&2
    exit 1
fi

(
    export HOME="$temporary_root"
    cd "$compatibility_repo"

    resolved_repository="$(
        cd "$HOME/DeltaAegis"
        pwd -P
    )"
    current_repository="$(pwd -P)"

    if [ "$resolved_repository" != "$current_repository" ]; then
        echo "ERROR: compatibility HOME does not resolve to the clone." >&2
        echo "HOME repository: $resolved_repository" >&2
        echo "Current repo:    $current_repository" >&2
        exit 1
    fi

    echo "Compatibility branch: $(
        git branch --show-current
    )"
    echo "Compatibility HOME:   $HOME"

    tools/validate_v0_40_all.sh
)

echo
echo "PASS: DeltaAegis v0.40 operator-action compatibility"
