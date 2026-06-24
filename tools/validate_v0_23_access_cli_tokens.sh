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

for needle in \
    'def authenticate_access_api_token' \
    'def list_access_api_tokens' \
    'def command_user_create' \
    'def command_users' \
    'def command_api_token_create' \
    'def command_api_tokens' \
    'sub.add_parser("user-create"' \
    'sub.add_parser("api-token-create"'
do
    grep -q "$needle" deltaaegis.py || fail "missing expected access CLI/token marker: $needle"
done

python3 - <<'PY'
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import deltaaegis as da

with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "deltaaegis-access-cli-test.db"

    create_user = subprocess.run(
        [
            sys.executable,
            "deltaaegis.py",
            "--db",
            str(db_path),
            "user-create",
            "Security.Admin",
            "--role",
            "ADMIN",
            "--password",
            "test-password",
            "--display-name",
            "Security Admin",
            "--actor",
            "validator",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "DeltaAegis access user created" in create_user.stdout
    assert "security.admin" in create_user.stdout
    assert "Role:         ADMIN" in create_user.stdout

    list_users = subprocess.run(
        [
            sys.executable,
            "deltaaegis.py",
            "--db",
            str(db_path),
            "users",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "security.admin" in list_users.stdout
    assert "ADMIN" in list_users.stdout

    create_token = subprocess.run(
        [
            sys.executable,
            "deltaaegis.py",
            "--db",
            str(db_path),
            "api-token-create",
            "security.admin",
            "--name",
            "validator token",
            "--role",
            "ANALYST",
            "--actor",
            "validator",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "DeltaAegis API token created" in create_token.stdout
    assert "Role:         ANALYST" in create_token.stdout
    match = re.search(r"^(da_[A-Za-z0-9_-]+)$", create_token.stdout, re.MULTILINE)
    assert match, create_token.stdout
    token_value = match.group(1)

    list_tokens = subprocess.run(
        [
            sys.executable,
            "deltaaegis.py",
            "--db",
            str(db_path),
            "api-tokens",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "validator token" in list_tokens.stdout
    assert "ANALYST" in list_tokens.stdout

    with da.connect(db_path) as connection:
        actor = da.authenticate_access_api_token(connection, token_value, required_role="VIEWER")
        assert actor is not None
        assert actor["username"] == "security.admin"
        assert actor["role"] == "ANALYST"
        assert actor["last_used_at"]

        denied = da.authenticate_access_api_token(connection, token_value, required_role="ADMIN")
        assert denied is None

        token_row = connection.execute(
            "SELECT last_used_at FROM access_api_tokens WHERE token_prefix = ?",
            (token_value[:12],),
        ).fetchone()
        assert token_row is not None
        assert token_row["last_used_at"], token_row

        audit_rows = connection.execute(
            "SELECT action, actor_username, target_type FROM access_audit_log ORDER BY audit_id"
        ).fetchall()
        actions = [row["action"] for row in audit_rows]
        assert "ACCESS_USER_CREATE" in actions, actions
        assert "ACCESS_API_TOKEN_CREATE" in actions, actions

print("[PASS] synthetic v0.23 access CLI/API token workflow validated")
PY

./tools/validate_v0_23_access_model.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.23 access model compatibility gate failed"

./tools/validate_v0_22_release.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.22 release compatibility gate failed"

pass "DeltaAegis v0.23 access CLI/API token validation passed"
