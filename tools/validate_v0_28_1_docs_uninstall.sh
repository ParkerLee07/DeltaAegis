#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

bash -n install.sh || fail "install.sh has bash syntax errors"
bash -n uninstall.sh || fail "uninstall.sh has bash syntax errors"

grep -Fq 'Current Release — v0.28.0' README.md \
    || fail "README does not advertise v0.28.0 as current release"

grep -Fq 'Current feature baseline: **DeltaAegis v0.28.0 — Dashboard NetSniper Import Setup**.' README.md \
    || fail "README missing v0.28 current feature baseline"

grep -Fq 'Dashboard NetSniper Import Setup' README.md \
    || fail "README does not describe v0.28.0 Dashboard NetSniper Import Setup"

grep -Fq 'data/deltaaegis.db' README.md \
    || fail "README does not document data/deltaaegis.db"

grep -Fq './uninstall.sh --purge-runtime' README.md \
    || fail "README does not document runtime-only uninstall cleanup"

grep -Fq './uninstall.sh --purge-project --yes' README.md \
    || fail "README does not document confirmed project purge"

grep -Fq 'DELTAAEGIS_NETSNIPER_ROOT' README.md \
    || fail "README does not document DELTAAEGIS_NETSNIPER_ROOT"

grep -Fq 'does not expose arbitrary shell command execution' README.md \
    || fail "README does not document no-raw-shell security boundary"

grep -Fq -- '--purge-runtime' uninstall.sh \
    || fail "uninstall.sh does not support --purge-runtime"

grep -Fq -- '--purge-project' uninstall.sh \
    || fail "uninstall.sh does not support --purge-project"

grep -Fq -- '--dry-run' uninstall.sh \
    || fail "uninstall.sh does not support --dry-run"

grep -Fq 'data/deltaaegis.db' uninstall.sh \
    || fail "uninstall.sh does not mention default data/deltaaegis.db"

./uninstall.sh --help | grep -Fq -- '--purge-runtime' \
    || fail "uninstall help does not show --purge-runtime"

./uninstall.sh --help | grep -Fq 'data/deltaaegis.db' \
    || fail "uninstall help does not show default DB path"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

mkdir -p "$tmpdir/project/data" "$tmpdir/project/events" "$tmpdir/project/reports" "$tmpdir/project/backups" "$tmpdir/bin"
touch "$tmpdir/bin/deltaaegis"
touch "$tmpdir/project/data/deltaaegis.db"

dry_run_output="$(
    DELTA_AEGIS_BASE="$tmpdir/project" BIN_DIR="$tmpdir/bin" ./uninstall.sh --dry-run --purge-runtime
)"

printf '%s\n' "$dry_run_output" | grep -Fq '[dry-run]' \
    || fail "uninstall dry-run did not print dry-run actions"

test -f "$tmpdir/bin/deltaaegis" \
    || fail "dry-run removed launcher unexpectedly"

DELTA_AEGIS_BASE="$tmpdir/project" BIN_DIR="$tmpdir/bin" ./uninstall.sh --purge-runtime >/dev/null

test ! -e "$tmpdir/bin/deltaaegis" \
    || fail "uninstall did not remove launcher"

test ! -e "$tmpdir/project/data" \
    || fail "purge-runtime did not remove data directory"

test -d "$tmpdir/project" \
    || fail "purge-runtime should keep project directory"

pass "DeltaAegis v0.28.1 docs and uninstall validation passed"
