#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

pass() {
    echo "PASS: $*"
}

echo "DeltaAegis v0.42 Install and Uninstall Lifecycle Validator"
echo "==========================================================="

echo "[install lifecycle] shell syntax"
bash -n install.sh
bash -n uninstall.sh
pass "install and uninstall shell syntax"

echo "[install lifecycle] static safety contract"
grep -Fq 'DELTAAEGIS_DB_PATH="${DELTAAEGIS_DB_PATH:-data/deltaaegis.db}"' install.sh \
    || fail "install.sh must retain the data/deltaaegis.db default"
grep -Fq 'deltaaegis-troubleshooter' install.sh \
    || fail "install.sh does not install the troubleshooter launcher"
grep -Fq 'tools/deltaaegis_troubleshooter.py' install.sh \
    || fail "install.sh does not validate the troubleshooter"
grep -Fq 'DeltaAegis first-admin bootstrap' install.sh \
    || fail "install.sh does not retain first-admin bootstrap support"
grep -Fq 'tools/bootstrap_first_admin.py' install.sh \
    || fail "install.sh does not invoke bootstrap_first_admin.py"
grep -Fq 'mkdir -p -- "$(dirname "$RESOLVED_DB_PATH")"' install.sh \
    || fail "install.sh does not create the resolved database parent"
grep -Fq 'replace_launcher_atomically()' install.sh \
    || fail "install.sh does not define exact-target launcher replacement"
grep -Fq 'mv -fT -- "$temporary" "$target"' install.sh \
    || fail "install.sh does not use exact-target atomic launcher moves"
grep -Fq 'Refusing to replace unmanaged launcher' install.sh \
    || fail "install.sh does not revalidate launcher destinations"
grep -Fq -- '--dry-run' install.sh \
    || fail "install.sh does not expose dry-run mode"
grep -Fq -- '--purge-runtime' uninstall.sh \
    || fail "uninstall.sh does not expose runtime purge"
grep -Fq -- '--purge-project' uninstall.sh \
    || fail "uninstall.sh does not expose project purge"
grep -Fq 'data/deltaaegis.db' uninstall.sh \
    || fail "uninstall.sh does not document the default database"
grep -Fq 'DeltaAegis-local-archive' uninstall.sh \
    || fail "uninstall.sh does not protect the local archive"
grep -Fq '$DELTA_AEGIS_HOME/deltaaegis.py' uninstall.sh \
    || fail "uninstall.sh does not scope process checks to the selected project"
grep -Fq '$DELTAAEGIS_NETSNIPER_ROOT/' uninstall.sh \
    || fail "uninstall.sh does not scope NetSniper process checks"
grep -Fq '$DELTAAEGIS_TRUEAEGIS_ROOT/' uninstall.sh \
    || fail "uninstall.sh does not scope TrueAegis process checks"
if grep -Fq '|[[:space:]]nmap[[:space:]]|' uninstall.sh; then
    fail "uninstall.sh still blocks unrelated system-wide nmap processes"
fi
pass "static lifecycle safety contract"

echo "[install lifecycle] temporary installation"
tmp_root="$(mktemp -d)"
cleanup() {
    local pid
    for pid in "${unrelated_dashboard_pid:-}" "${unrelated_nmap_pid:-}"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -rf -- "$tmp_root"
}
trap cleanup EXIT

project="$tmp_root/DeltaAegis"
bin_dir="$tmp_root/bin"
archive="$tmp_root/DeltaAegis-local-archive"

mkdir -p "$project/deltaaegis_core" "$project/tools" "$archive"
printf 'archive sentinel\n' > "$archive/KEEP"

cp -p \
    deltaaegis.py \
    install.sh \
    uninstall.sh \
    "$project/"

cp -p \
    deltaaegis_core/__init__.py \
    deltaaegis_core/auth.py \
    deltaaegis_core/config.py \
    deltaaegis_core/db.py \
    deltaaegis_core/ingest.py \
    deltaaegis_core/jobs.py \
    deltaaegis_core/reports.py \
    deltaaegis_core/sites.py \
    deltaaegis_core/web.py \
    "$project/deltaaegis_core/"

cp -p \
    tools/bootstrap_first_admin.py \
    tools/reset_dashboard_admin.py \
    tools/deltaaegis_troubleshooter.py \
    "$project/tools/"

HOME="$tmp_root" \
DELTA_AEGIS_BASE="$project" \
BIN_DIR="$bin_dir" \
DELTAAEGIS_ADMIN_USERNAME="lifecycle.admin" \
DELTAAEGIS_ADMIN_PASSWORD="LifecycleAdminPass123!" \
DELTAAEGIS_ADMIN_DISPLAY_NAME="Lifecycle Admin" \
    "$project/install.sh" --skip-health-check </dev/null

for path in \
    "$project/data" \
    "$project/data/backups" \
    "$project/events" \
    "$project/events/backups" \
    "$project/backups" \
    "$project/reports" \
    "$project/scan-logs" \
    "$project/trueaegis-logs" \
    "$bin_dir/deltaaegis" \
    "$bin_dir/deltaaegis-troubleshooter"
do
    [[ -e "$path" ]] || fail "installer did not create: $path"
done

HOME="$tmp_root" "$bin_dir/deltaaegis" paths \
    | grep -Fq "$project/data/deltaaegis.db" \
    || fail "installed launcher does not use the project database"

python3 - "$project/data/deltaaegis.db" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
connection.row_factory = sqlite3.Row
row = connection.execute(
    """
    SELECT username, display_name, role, is_active
    FROM access_users
    WHERE username = ?
    """,
    ("lifecycle.admin",),
).fetchone()
connection.close()

assert row is not None, "lifecycle.admin was not created"
assert row["display_name"] == "Lifecycle Admin", dict(row)
assert row["role"] == "ADMIN", dict(row)
assert row["is_active"] == 1, dict(row)
PY

HOME="$tmp_root" "$bin_dir/deltaaegis-troubleshooter" --codes \
    | grep -Fq 'DAE-TRB-4001' \
    || fail "installed troubleshooter launcher did not run"

pass "temporary installation and launchers"

echo "[uninstall lifecycle] launcher-only removal"
HOME="$tmp_root" \
DELTA_AEGIS_HOME="$project" \
BIN_DIR="$bin_dir" \
    "$project/uninstall.sh"

[[ ! -e "$bin_dir/deltaaegis" ]] \
    || fail "default uninstall did not remove deltaaegis launcher"
[[ ! -e "$bin_dir/deltaaegis-troubleshooter" ]] \
    || fail "default uninstall did not remove troubleshooter launcher"
[[ -f "$project/deltaaegis.py" ]] \
    || fail "default uninstall removed project files"

pass "launcher-only uninstall"

echo "[uninstall lifecycle] runtime purge"
HOME="$tmp_root" \
DELTA_AEGIS_BASE="$project" \
BIN_DIR="$bin_dir" \
    "$project/install.sh" --skip-health-check </dev/null

printf 'database sentinel\n' > "$project/data/deltaaegis.db"
printf 'event sentinel\n' > "$project/events/events.jsonl"
printf 'report sentinel\n' > "$project/reports/report.md"

# A purge of the disposable fixture must not be blocked by processes belonging
# to another installation. This reproduces the v0.44 Stage 8 release-gate
# failure seen when an operator had a live dashboard and NetSniper scan.
bash -c 'exec -a "python3 /opt/unrelated/DeltaAegis/deltaaegis.py dashboard" sleep 60' &
unrelated_dashboard_pid=$!
bash -c 'exec -a "timeout 900s nmap -iL /opt/unrelated/NetSniper/targets/hosts.txt" sleep 60' &
unrelated_nmap_pid=$!

HOME="$tmp_root" \
DELTA_AEGIS_HOME="$project" \
BIN_DIR="$bin_dir" \
    "$project/uninstall.sh" --purge-runtime

kill "$unrelated_dashboard_pid" "$unrelated_nmap_pid" 2>/dev/null || true
wait "$unrelated_dashboard_pid" "$unrelated_nmap_pid" 2>/dev/null || true
unrelated_dashboard_pid=""
unrelated_nmap_pid=""

for path in \
    "$project/data" \
    "$project/events" \
    "$project/backups" \
    "$project/reports" \
    "$project/scan-logs" \
    "$project/trueaegis-logs"
do
    [[ ! -e "$path" ]] || fail "runtime purge left: $path"
done

[[ -f "$project/deltaaegis.py" ]] \
    || fail "runtime purge removed project source"
[[ -f "$archive/KEEP" ]] \
    || fail "runtime purge removed local archive evidence"

pass "runtime purge and external archive preservation"

echo "[uninstall lifecycle] external database preservation"
HOME="$tmp_root" \
DELTA_AEGIS_BASE="$project" \
BIN_DIR="$bin_dir" \
    "$project/install.sh" --skip-health-check </dev/null

external_db="$tmp_root/external-deltaaegis.db"
printf 'external database sentinel\n' > "$external_db"

HOME="$tmp_root" \
DELTA_AEGIS_HOME="$project" \
DELTAAEGIS_DB_PATH="$external_db" \
BIN_DIR="$bin_dir" \
    "$project/uninstall.sh" --purge-runtime

[[ -f "$external_db" ]] \
    || fail "runtime purge deleted an external database"

pass "external database preservation"

echo "[install lifecycle] launcher destination confinement"
conflict_bin="$tmp_root/conflict-bin"
mkdir -p "$conflict_bin/deltaaegis"
printf 'directory sentinel\n' > "$conflict_bin/deltaaegis/KEEP"

if HOME="$tmp_root" \
    DELTA_AEGIS_BASE="$project" \
    BIN_DIR="$conflict_bin" \
        "$project/install.sh" --skip-health-check </dev/null \
        >"$tmp_root/conflict-install.stdout" \
        2>"$tmp_root/conflict-install.stderr"
then
    fail "installer replaced an unmanaged launcher directory"
fi

grep -Fq 'Refusing to replace unmanaged launcher' \
    "$tmp_root/conflict-install.stderr" \
    || fail "launcher-directory refusal was not explicit"
[[ -f "$conflict_bin/deltaaegis/KEEP" ]] \
    || fail "launcher conflict handling mutated the unmanaged directory"
[[ ! -e "$conflict_bin/deltaaegis-troubleshooter" ]] \
    || fail "launcher conflict handling partially installed another launcher"
pass "launcher destination confinement and atomic replacement"

echo "[uninstall lifecycle] project purge confirmation"
HOME="$tmp_root" \
DELTA_AEGIS_BASE="$project" \
BIN_DIR="$bin_dir" \
    "$project/install.sh" --skip-health-check </dev/null

HOME="$tmp_root" \
DELTA_AEGIS_HOME="$project" \
BIN_DIR="$bin_dir" \
    "$project/uninstall.sh" --purge-project --dry-run --yes

[[ -d "$project" ]] \
    || fail "dry-run project purge removed the project"

(
    cd "$tmp_root"
    HOME="$tmp_root" \
    DELTA_AEGIS_HOME="$project" \
    BIN_DIR="$bin_dir" \
        "$project/uninstall.sh" --purge-project --yes
)

[[ ! -e "$project" ]] \
    || fail "confirmed project purge left the project"
[[ -f "$archive/KEEP" ]] \
    || fail "project purge removed the external local archive"

pass "project purge confirmation and archive preservation"

echo "[install lifecycle] repository hygiene"
git diff --check
pass "repository hygiene"

echo
echo "PASS: DeltaAegis v0.42 install and uninstall lifecycle validator"
