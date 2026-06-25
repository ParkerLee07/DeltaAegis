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

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

python3 -m py_compile tools/bootstrap_first_admin.py \
    || fail "bootstrap_first_admin.py does not compile"

python3 -m py_compile tools/reset_dashboard_admin.py \
    || fail "reset_dashboard_admin.py does not compile"

grep -Fq 'DELTAAEGIS_DB_PATH="${DELTAAEGIS_DB_PATH:-data/deltaaegis.db}"' install.sh \
    || fail "install.sh does not default to data/deltaaegis.db"

grep -Fq 'mkdir -p "$(dirname "$DELTAAEGIS_DB_PATH")"' install.sh \
    || fail "install.sh does not create the dashboard DB parent directory"

grep -Fq 'default=str(REPO_ROOT / "data" / "deltaaegis.db")' tools/bootstrap_first_admin.py \
    || fail "bootstrap_first_admin.py does not default to repo data/deltaaegis.db"

grep -Fq 'DEFAULT_DB_PATH = REPO_ROOT / "data" / "deltaaegis.db"' tools/reset_dashboard_admin.py \
    || fail "reset_dashboard_admin.py does not default to repo data/deltaaegis.db"

python3 tools/bootstrap_first_admin.py --help | grep -Fq 'data/deltaaegis.db' \
    || fail "bootstrap_first_admin.py --help does not show data/deltaaegis.db default"

python3 tools/reset_dashboard_admin.py --help | grep -Fq 'data/deltaaegis.db' \
    || fail "reset_dashboard_admin.py --help does not show data/deltaaegis.db default"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

export DELTAAEGIS_VALIDATOR_ADMIN_PASSWORD="ValidatorPass123!"

python3 tools/reset_dashboard_admin.py \
    --db "$tmpdir/data/deltaaegis.db" \
    --username validator.admin \
    --display-name "Validator Admin" \
    --password-env DELTAAEGIS_VALIDATOR_ADMIN_PASSWORD \
    --non-interactive \
    || fail "reset_dashboard_admin.py could not create/reset an admin in a custom DB"

python3 - "$tmpdir/data/deltaaegis.db" <<'PY'
import sqlite3
import sys

db_path = sys.argv[1]
con = sqlite3.connect(db_path)
con.row_factory = sqlite3.Row

row = con.execute(
    """
    SELECT username, display_name, role, is_active, password_hash
    FROM access_users
    WHERE username = ?
    """,
    ("validator.admin",),
).fetchone()

assert row is not None, "validator.admin was not created"
assert row["display_name"] == "Validator Admin", dict(row)
assert row["role"] == "ADMIN", dict(row)
assert row["is_active"] == 1, dict(row)
assert row["password_hash"], "password hash was not set"
PY

pass "DeltaAegis v0.28 dashboard DB default alignment validation passed"
