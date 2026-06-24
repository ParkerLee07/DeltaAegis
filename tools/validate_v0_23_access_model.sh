#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

NETSNIPER_RUN_DIR="${1:-/home/parker/NetSniper/runs/20260623-123007}"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

grep -q 'CREATE TABLE IF NOT EXISTS access_users' deltaaegis.py \
    || fail "access_users schema missing"

grep -q 'CREATE TABLE IF NOT EXISTS access_api_tokens' deltaaegis.py \
    || fail "access_api_tokens schema missing"

grep -q 'CREATE TABLE IF NOT EXISTS access_audit_log' deltaaegis.py \
    || fail "access_audit_log schema missing"

grep -q 'def normalize_access_role' deltaaegis.py \
    || fail "access role normalizer missing"

grep -q 'def hash_access_password' deltaaegis.py \
    || fail "password hash helper missing"

python3 - <<'PY'
from pathlib import Path
import inspect
import tempfile

import deltaaegis as da

connect_source = inspect.getsource(da.connect)
assert "ensure_enterprise_access_schema(connection)" in connect_source, connect_source

assert da.normalize_access_role("admin") == "ADMIN"
assert da.normalize_access_role("Analyst") == "ANALYST"
assert da.normalize_access_role("viewer") == "VIEWER"
assert da.access_role_allows("ADMIN", "VIEWER") is True
assert da.access_role_allows("ANALYST", "ADMIN") is False
assert da.access_role_allows("ANALYST", "VIEWER") is True

password_hash = da.hash_access_password(
    "correct horse battery staple",
    salt="unit-test-salt",
    iterations=100000,
)
assert password_hash.startswith("pbkdf2_sha256$100000$unit-test-salt$")
assert da.verify_access_password("correct horse battery staple", password_hash) is True
assert da.verify_access_password("wrong password", password_hash) is False
assert da.verify_access_password("correct horse battery staple", "") is False

with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "deltaaegis-access-test.db"

    with da.connect(db_path) as connection:
        tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }

        for table_name in {"access_users", "access_api_tokens", "access_audit_log"}:
            assert table_name in tables, tables

        user = da.create_access_user(
            connection,
            username="Parker.Admin",
            role="admin",
            password="test-password",
            display_name="Parker Admin",
        )
        assert user["username"] == "parker.admin"
        assert user["role"] == "ADMIN"

        stored = da.access_user_by_username(connection, "PARKER.ADMIN")
        assert stored is not None
        assert stored["username"] == "parker.admin"
        assert stored["role"] == "ADMIN"
        assert da.verify_access_password("test-password", stored["password_hash"]) is True

        users = da.list_access_users(connection)
        assert len(users) == 1, users
        assert users[0]["username"] == "parker.admin"

        token = da.create_access_api_token(
            connection,
            user_id=user["user_id"],
            token_name="unit test token",
            role="analyst",
        )
        assert token["token"].startswith("da_")
        assert token["role"] == "ANALYST"
        assert token["token_prefix"] == token["token"][:12]

        token_hash = da.hash_access_api_token(token["token"])
        row = connection.execute(
            "SELECT token_hash, token_prefix, role FROM access_api_tokens WHERE token_id = ?",
            (token["token_id"],),
        ).fetchone()
        assert row["token_hash"] == token_hash
        assert row["token_prefix"] == token["token_prefix"]
        assert row["role"] == "ANALYST"

        audit_id = da.record_access_audit_event(
            connection,
            action="unit_test",
            actor=user,
            target_type="access_user",
            target_key=user["username"],
            source_ip="127.0.0.1",
            user_agent="validator",
            details={"ok": True},
        )
        assert audit_id > 0

        audit_row = connection.execute(
            "SELECT actor_username, actor_role, action, target_type, target_key, detail_json "
            "FROM access_audit_log WHERE audit_id = ?",
            (audit_id,),
        ).fetchone()
        assert audit_row["actor_username"] == "parker.admin"
        assert audit_row["actor_role"] == "ADMIN"
        assert audit_row["action"] == "UNIT_TEST"
        assert audit_row["target_type"] == "access_user"
        assert audit_row["target_key"] == "parker.admin"
        assert '"ok": true' in audit_row["detail_json"]

print("[PASS] synthetic v0.23 enterprise access model validated")
PY

./tools/validate_v0_23_backward_compatibility.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.23 backward compatibility gate failed"

pass "DeltaAegis v0.23 enterprise access model validation passed"
