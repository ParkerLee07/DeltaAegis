#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
    echo "[FAIL] v1 Stage 1–2 install lifecycle: $*" >&2
    exit 1
}

tmp_root="$(mktemp -d)"
cleanup() {
    rm -rf -- "$tmp_root"
}
trap cleanup EXIT

project="$tmp_root/DeltaAegis"
bin_dir="$tmp_root/bin"
archive="$tmp_root/DeltaAegis-local-archive"
mkdir -p "$project/deltaaegis_core" "$project/tools" "$archive"
printf 'preserve\n' > "$archive/KEEP"

cp -p deltaaegis.py install.sh uninstall.sh "$project/"
cp -p deltaaegis_core/*.py "$project/deltaaegis_core/"
cp -p \
    tools/bootstrap_first_admin.py \
    tools/reset_dashboard_admin.py \
    tools/deltaaegis_troubleshooter.py \
    "$project/tools/"

bash -n "$project/install.sh"
bash -n "$project/uninstall.sh"

HOME="$tmp_root" \
DELTA_AEGIS_BASE="$project" \
BIN_DIR="$bin_dir" \
    "$project/install.sh" --dry-run > "$tmp_root/dry-run.log"

grep -Fq 'DRY RUN: no files were changed' "$tmp_root/dry-run.log" \
    || fail "installer dry run did not report its non-mutating boundary"
[[ ! -e "$bin_dir" ]] || fail "installer dry run created the launcher directory"
[[ ! -e "$project/data" ]] || fail "installer dry run created runtime data"

HOME="$tmp_root" \
DELTA_AEGIS_BASE="$project" \
BIN_DIR="$bin_dir" \
DELTAAEGIS_ADMIN_USERNAME="stage12.admin" \
DELTAAEGIS_ADMIN_PASSWORD="Stage12-Install-Validation!" \
DELTAAEGIS_ADMIN_DISPLAY_NAME="Stage 1-2 Admin" \
    "$project/install.sh" --skip-health-check </dev/null \
    > "$tmp_root/install.log"

for relative in \
    data \
    data/backups \
    events \
    events/backups \
    backups \
    reports \
    scan-logs \
    trueaegis-logs \
    telemetry-evidence/trusted \
    telemetry-evidence/quarantine \
    restore-rehearsals
do
    [[ -d "$project/$relative" ]] \
        || fail "installer did not create runtime directory: $relative"
done

for launcher in deltaaegis deltaaegis-troubleshooter; do
    [[ -x "$bin_dir/$launcher" ]] || fail "installer did not create $launcher"
done

HOME="$tmp_root" "$bin_dir/deltaaegis" paths \
    | grep -Fq "$project/data/deltaaegis.db" \
    || fail "installed launcher does not resolve the project database"

python3 - "$project/data/deltaaegis.db" <<'PY'
import json
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
connection.row_factory = sqlite3.Row
try:
    migrations = connection.execute(
        "SELECT migration_id, origin, outcome_json FROM schema_migrations ORDER BY migration_id"
    ).fetchall()
    assert [row["migration_id"] for row in migrations] == [
        "0001-v045-foundation",
        "0002-v045-telemetry-trust",
        "0003-v1-api-security",
        "0004-v1-sensor-scope-identity",
        "0005-v1-deterministic-detection",
    ]
    assert all(row["origin"] == "fresh" for row in migrations)
    for row in migrations:
        outcome = json.loads(row["outcome_json"])
        assert outcome["ledger_schema_version"] == "deltaaegis-schema-migrations-v1"
        assert outcome["schema_after"]
        assert outcome["description"]
    user = connection.execute(
        "SELECT username, role, is_active FROM access_users WHERE username = ?",
        ("stage12.admin",),
    ).fetchone()
    assert user is not None and user["role"] == "ADMIN" and user["is_active"] == 1
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
finally:
    connection.close()
PY

HOME="$tmp_root" "$bin_dir/deltaaegis" \
    --db "$project/data/deltaaegis.db" \
    api-token-create stage12.admin \
    --name "Stage 1-2 lifecycle reader" \
    --role VIEWER \
    --scope dashboard.read \
    --scope session.read \
    > "$tmp_root/token-create.log"

python3 - \
    "$project/data/deltaaegis.db" \
    "$tmp_root/token-create.log" <<'PY'
import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

database = Path(sys.argv[1])
output = Path(sys.argv[2]).read_text(encoding="utf-8")
marker = "Copy this token now. It will not be shown again:\n"
assert output.count(marker) == 1
raw_token = output.split(marker, 1)[1].strip()
assert raw_token.startswith("da_")

connection = sqlite3.connect(database)
connection.row_factory = sqlite3.Row
try:
    row = connection.execute(
        "SELECT token_name, token_hash, token_prefix, role, expires_at, "
        "scopes_json, is_active FROM access_api_tokens "
        "WHERE token_name = ?",
        ("Stage 1-2 lifecycle reader",),
    ).fetchone()
    assert row is not None
    assert row["token_hash"] == hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    assert row["token_prefix"] == raw_token[:12]
    assert row["role"] == "VIEWER" and row["is_active"] == 1
    assert json.loads(row["scopes_json"]) == ["dashboard.read", "session.read"]
    expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
    remaining = expires_at - datetime.now(timezone.utc)
    assert timedelta(days=29, hours=23) < remaining <= timedelta(days=30)
    assert raw_token not in database.read_bytes().decode("latin-1")
    audit = connection.execute(
        "SELECT action FROM access_audit_log "
        "WHERE target_key = (SELECT token_id FROM access_api_tokens "
        "WHERE token_name = ?) ORDER BY audit_id DESC LIMIT 1",
        ("Stage 1-2 lifecycle reader",),
    ).fetchone()
    assert audit is not None and audit["action"] == "ACCESS_API_TOKEN_CREATE"
finally:
    connection.close()
PY

concurrent_admin_db="$tmp_root/concurrent-first-admin.db"
HOME="$tmp_root" python3 "$project/tools/bootstrap_first_admin.py" \
    --db "$concurrent_admin_db" \
    --username "concurrent.admin.one" \
    --password "Concurrent-Admin-One!" \
    --display-name "Concurrent Admin One" \
    --non-interactive > "$tmp_root/concurrent-admin-one.log" 2>&1 &
first_admin_pid=$!
HOME="$tmp_root" python3 "$project/tools/bootstrap_first_admin.py" \
    --db "$concurrent_admin_db" \
    --username "concurrent.admin.two" \
    --password "Concurrent-Admin-Two!" \
    --display-name "Concurrent Admin Two" \
    --non-interactive > "$tmp_root/concurrent-admin-two.log" 2>&1 &
second_admin_pid=$!
wait "$first_admin_pid"
wait "$second_admin_pid"

python3 - "$concurrent_admin_db" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
try:
    users = connection.execute(
        "SELECT username, role, is_active FROM access_users"
    ).fetchall()
    assert len(users) == 1
    assert users[0][1:] == ("ADMIN", 1)
    assert users[0][0] in {"concurrent.admin.one", "concurrent.admin.two"}
    assert connection.execute(
        "SELECT COUNT(*) FROM schema_migrations"
    ).fetchone()[0] == 5
finally:
    connection.close()
PY

before_hash="$(sha256sum "$project/data/deltaaegis.db" | awk '{print $1}')"
HOME="$tmp_root" DELTA_AEGIS_BASE="$project" BIN_DIR="$bin_dir" \
    "$project/install.sh" --skip-health-check </dev/null \
    > "$tmp_root/reinstall.log" 2>&1
after_hash="$(sha256sum "$project/data/deltaaegis.db" | awk '{print $1}')"
[[ "$before_hash" == "$after_hash" ]] \
    || fail "idempotent reinstall mutated the initialized database"

HOME="$tmp_root" DELTA_AEGIS_HOME="$project" BIN_DIR="$bin_dir" \
    "$project/uninstall.sh" > "$tmp_root/uninstall.log"
[[ ! -e "$bin_dir/deltaaegis" && ! -e "$bin_dir/deltaaegis-troubleshooter" ]] \
    || fail "default uninstall left managed launchers"
[[ -f "$project/data/deltaaegis.db" ]] \
    || fail "default uninstall removed the active database"
[[ -f "$project/deltaaegis_core/migrations.py" ]] \
    || fail "default uninstall removed project source"

HOME="$tmp_root" DELTA_AEGIS_BASE="$project" BIN_DIR="$bin_dir" \
    "$project/install.sh" --skip-health-check </dev/null \
    > "$tmp_root/reinstall-for-purge.log" 2>&1

HOME="$tmp_root" DELTA_AEGIS_HOME="$project" BIN_DIR="$bin_dir" \
    "$project/uninstall.sh" --purge-runtime > "$tmp_root/purge.log"

for relative in \
    data events backups reports scan-logs trueaegis-logs \
    telemetry-evidence restore-rehearsals
do
    [[ ! -e "$project/$relative" ]] \
        || fail "runtime purge left project runtime: $relative"
done
[[ -f "$project/deltaaegis.py" ]] || fail "runtime purge removed project source"
[[ -f "$archive/KEEP" ]] || fail "runtime purge removed the external local archive"

external_db="$tmp_root/external-deltaaegis.db"
printf 'external evidence\n' > "$external_db"
HOME="$tmp_root" DELTA_AEGIS_HOME="$project" BIN_DIR="$bin_dir" \
DELTAAEGIS_DB_PATH="$external_db" \
    "$project/uninstall.sh" --purge-runtime > "$tmp_root/external-purge.log"
[[ -f "$external_db" ]] || fail "runtime purge removed an external database"

echo "[PASS] v1 install lifecycle transition: Stage 1–2 controls and Stage 3–5 modules, fresh migrations, serialized admin bootstrap, bounded scoped-token CLI, idempotent reinstall, launcher removal, runtime purge, and external evidence preservation"
