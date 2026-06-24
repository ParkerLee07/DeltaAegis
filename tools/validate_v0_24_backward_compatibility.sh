#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

# v0.23 enterprise access model/token/audit capability markers.
for needle in \
    'CREATE TABLE IF NOT EXISTS access_users' \
    'CREATE TABLE IF NOT EXISTS access_api_tokens' \
    'CREATE TABLE IF NOT EXISTS access_audit_log' \
    'def create_access_user' \
    'def create_access_api_token' \
    'def authenticate_access_api_token' \
    'def record_access_audit_event' \
    'def dashboard_access_audit_payload' \
    'route == "/api/access-audit"'
do
    grep -q -- "$needle" deltaaegis.py || fail "missing v0.23 compatibility marker: $needle"
done

# v0.22 triage/operator review surface markers. Keep these broad because
# different checkpoints used different helper function names.
for needle in \
    'triage_bucket' \
    'triage_urgency' \
    'CHANGED_SINCE_REVIEW' \
    'NEEDS_REVIEW' \
    'IMMEDIATE' \
    'HIGH'
do
    grep -q -- "$needle" deltaaegis.py || fail "missing v0.22 triage compatibility marker: $needle"
done

python3 - <<'PY2'
from pathlib import Path
import tempfile

import deltaaegis as da


with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "deltaaegis-v024-compat.db"

    with da.connect(db_path) as connection:
        tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

        for table_name in [
            "access_users",
            "access_api_tokens",
            "access_audit_log",
            "access_sessions",
        ]:
            assert table_name in tables, (table_name, tables)

        user = da.create_access_user(
            connection,
            "compat.admin",
            role="ADMIN",
            password="compat-password",
            display_name="Compatibility Admin",
        )
        assert user["username"] == "compat.admin", user
        assert user["role"] == "ADMIN", user

        token = da.create_access_api_token(
            connection,
            user["user_id"],
            "compat-token",
            role="ADMIN",
        )
        assert token["token"].startswith("da_"), token

        actor = da.authenticate_access_api_token(
            connection,
            token["token"],
            required_role="ADMIN",
        )
        assert actor, actor
        assert actor["username"] == "compat.admin", actor
        assert actor["role"] == "ADMIN", actor

        da.record_access_audit_event(
            connection,
            "COMPATIBILITY_SMOKE",
            actor=actor,
            target_type="validator",
            target_key="v0.24",
            details={"ok": True},
        )
        connection.commit()

        audit_row = connection.execute(
            "SELECT action, actor_username, target_type, target_key "
            "FROM access_audit_log "
            "WHERE action = ? "
            "ORDER BY audit_id DESC "
            "LIMIT 1",
            ("COMPATIBILITY_SMOKE",),
        ).fetchone()
        assert audit_row, "COMPATIBILITY_SMOKE audit event was not recorded"
        assert audit_row["actor_username"] == "compat.admin", dict(audit_row)
        assert audit_row["target_type"] == "validator", dict(audit_row)
        assert audit_row["target_key"] == "v0.24", dict(audit_row)

        payload = da.dashboard_access_audit_payload(
            connection,
            limit=5,
        )
        assert isinstance(payload, dict), payload
        assert payload, payload

print("[PASS] synthetic v0.23/v0.24 compatibility smoke validated")
PY2

pass "DeltaAegis v0.24 backward compatibility validation passed"
