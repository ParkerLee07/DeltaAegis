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

for needle in \
    'ACCESS_SESSION_COOKIE_NAME' \
    'def ensure_dashboard_session_schema' \
    'CREATE TABLE IF NOT EXISTS access_sessions' \
    'def dashboard_user_login' \
    'def create_dashboard_session' \
    'def authenticate_dashboard_session' \
    'def expire_dashboard_session' \
    'LOGIN_SUCCESS' \
    'LOGIN_FAILED' \
    'SESSION_EXPIRED' \
    'ensure_dashboard_session_schema(connection)'
do
    grep -q "$needle" deltaaegis.py || fail "missing v0.24 session model marker: $needle"
done

python3 - <<'PY2'
from pathlib import Path
import tempfile

import deltaaegis as da


with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "deltaaegis-session-model.db"

    with da.connect(db_path) as connection:
        tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "access_sessions" in tables, tables

        user = da.create_access_user(
            connection,
            "session.admin",
            role="ADMIN",
            password="correct-horse-battery-staple",
            display_name="Session Admin",
        )

        failed = da.dashboard_user_login(
            connection,
            "session.admin",
            "wrong-password",
            source_ip="127.0.0.1",
            user_agent="validator",
        )
        assert failed is None

        login = da.dashboard_user_login(
            connection,
            "session.admin",
            "correct-horse-battery-staple",
            source_ip="127.0.0.1",
            user_agent="validator",
        )
        assert login
        assert login["session_token"].startswith("ds_")
        assert login["role"] == "ADMIN"

        viewer_actor = da.authenticate_dashboard_session(
            connection,
            login["session_token"],
            required_role="VIEWER",
        )
        assert viewer_actor
        assert viewer_actor["username"] == "session.admin"
        assert viewer_actor["role"] == "ADMIN"

        admin_actor = da.authenticate_dashboard_session(
            connection,
            login["session_token"],
            required_role="ADMIN",
        )
        assert admin_actor

        assert da.expire_dashboard_session(
            connection,
            login["session_token"],
            actor=admin_actor,
            reason="logout",
        ) is True

        expired_actor = da.authenticate_dashboard_session(
            connection,
            login["session_token"],
            required_role="VIEWER",
        )
        assert expired_actor is None

        second_session = da.create_dashboard_session(
            connection,
            user,
            source_ip="127.0.0.1",
            user_agent="validator-expiry",
        )
        second_actor = da.authenticate_dashboard_session(
            connection,
            second_session["session_token"],
            required_role="VIEWER",
        )
        assert second_actor

        assert da.expire_dashboard_session(
            connection,
            second_session["session_token"],
            actor=second_actor,
            reason="expired",
        ) is True

        actions = [
            row["action"]
            for row in connection.execute(
                "SELECT action FROM access_audit_log ORDER BY audit_id"
            ).fetchall()
        ]

        assert "LOGIN_FAILED" in actions, actions
        assert actions.count("LOGIN_SUCCESS") >= 2, actions
        assert "LOGOUT" in actions, actions
        assert "SESSION_EXPIRED" in actions, actions

print("[PASS] synthetic v0.24 dashboard session model validated")
PY2

pass "DeltaAegis v0.24 dashboard session model validation passed"
