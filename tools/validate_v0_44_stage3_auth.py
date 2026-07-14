#!/usr/bin/env python3
"""Validate the behavior-preserving v0.44 authentication extraction."""

from __future__ import annotations

import ast
import inspect
import json
import sqlite3
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHARACTERIZATION_PATH = ROOT / "docs" / "v0.44-stage3-auth-characterization.json"
EXPECTED_SOURCE_TREE = "187d09e830bce84975d69e536d0c442d4c7e4d77"

sys.path.insert(0, str(ROOT))

import deltaaegis as facade  # noqa: E402
from deltaaegis_core import auth  # noqa: E402


def fail(message: str) -> None:
    raise AssertionError(message)


def check(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load_characterization() -> dict:
    payload = json.loads(CHARACTERIZATION_PATH.read_text(encoding="utf-8"))
    check(
        payload.get("format") == "deltaaegis-v0.44-stage3-auth-characterization-v1",
        "unexpected authentication characterization format",
    )
    check(
        payload.get("source_checkpoint_tree") == EXPECTED_SOURCE_TREE,
        "authentication extraction is not anchored to the Stage 1-2 tree",
    )
    check(payload.get("schema_change") is False, "Stage 3 must not claim a schema change")
    return payload


def top_level_functions(path: Path) -> dict[str, ast.FunctionDef]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }


def validate_ownership_and_facade(characterization: dict) -> None:
    root_path = ROOT / "deltaaegis.py"
    auth_path = ROOT / "deltaaegis_core" / "auth.py"
    root_text = root_path.read_text(encoding="utf-8")
    auth_text = auth_path.read_text(encoding="utf-8")
    root_functions = top_level_functions(root_path)
    auth_functions = top_level_functions(auth_path)

    check("from deltaaegis_core import auth as _auth" in root_text, "root auth import is missing")
    check("auth" in __import__("deltaaegis_core").__all__, "auth is not exported by the package")
    check(not (ROOT / "deltaaegis").exists(), "conflicting deltaaegis package exists")

    names = characterization["facade_functions"]
    for name in names:
        check(name in root_functions, f"root compatibility function is missing: {name}")
        check(name in auth_functions, f"auth implementation function is missing: {name}")
        segment = ast.get_source_segment(root_text, root_functions[name]) or ""
        check("_auth." in segment, f"root function is not a thin auth facade: {name}")
        check("SELECT " not in segment and "CREATE TABLE" not in segment, f"SQL leaked into facade: {name}")

        facade_signature = inspect.signature(getattr(facade, name))
        implementation_signature = inspect.signature(getattr(auth, name))
        if name == "dashboard_user_login":
            check(
                list(facade_signature.parameters)
                == list(implementation_signature.parameters)[: len(facade_signature.parameters)],
                "dashboard login compatibility parameters changed",
            )
        else:
            check(
                str(facade_signature) == str(implementation_signature),
                f"compatibility signature changed: {name}",
            )

    check("CREATE TABLE IF NOT EXISTS access_users" in auth_text, "user schema is not owned by auth")
    check("CREATE TABLE IF NOT EXISTS access_sessions" in auth_text, "session schema is not owned by auth")
    check(facade.ACCESS_RBAC_PERMISSIONS is auth.ACCESS_RBAC_PERMISSIONS, "RBAC permissions split")
    check(facade.ACCESS_RBAC_ROUTE_POLICIES is auth.ACCESS_RBAC_ROUTE_POLICIES, "route policies split")
    check(facade._ACCESS_LOGIN_ATTEMPTS is auth._ACCESS_LOGIN_ATTEMPTS, "throttle state split")
    check(facade._ACCESS_LOGIN_ATTEMPTS_LOCK is auth._ACCESS_LOGIN_ATTEMPTS_LOCK, "throttle lock split")


def table_columns(connection: sqlite3.Connection, table: str) -> list[str]:
    return [str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")]


def validate_schema(characterization: dict, connection: sqlite3.Connection) -> None:
    facade.ensure_dashboard_session_schema(connection)
    for table, expected_columns in characterization["tables"].items():
        check(table_columns(connection, table) == expected_columns, f"schema drift in {table}")

    foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    check(not foreign_keys, f"authentication foreign-key failures: {foreign_keys}")


def validate_passwords_and_rbac(characterization: dict) -> None:
    policy = characterization["password_policy"]
    check(auth.ACCESS_PASSWORD_ALGORITHM == policy["algorithm"], "password algorithm changed")
    check(auth.ACCESS_PASSWORD_ITERATIONS == policy["iterations"], "password iterations changed")
    check(auth.ACCESS_PASSWORD_MIN_LENGTH == policy["minimum_length"], "password minimum changed")
    check(auth.ACCESS_PASSWORD_MAX_LENGTH == policy["maximum_length"], "password maximum changed")

    password_hash = facade.hash_access_password(
        "Correct-Horse-42", salt="v044-characterization", iterations=260000
    )
    check(facade.verify_access_password("Correct-Horse-42", password_hash), "password verification failed")
    check(not facade.verify_access_password("wrong-password", password_hash), "wrong password accepted")
    check(facade.access_password_hash_is_usable(password_hash), "valid password hash rejected")
    check(facade.access_effective_role("ADMIN", "ANALYST") == "ANALYST", "role cap changed")
    check(facade.access_rbac_allows("ADMIN", "scan.start"), "ADMIN scan permission changed")
    check(not facade.access_rbac_allows("VIEWER", "scan.start"), "VIEWER gained scan permission")
    check(
        facade.dashboard_route_permission("POST", "/api/netsniper/scan-start") == "scan.start",
        "dashboard route permission changed",
    )


def validate_runtime_behavior(connection: sqlite3.Connection) -> None:
    admin = facade.create_access_user(
        connection,
        username="stage3.admin",
        role="ADMIN",
        password="Correct-Horse-42",
        display_name="Stage 3 Admin",
    )
    viewer = facade.create_access_user(
        connection,
        username="stage3.viewer",
        role="VIEWER",
        password="Correct-Horse-43",
    )
    connection.commit()

    session = facade.dashboard_user_login(
        connection,
        "stage3.admin",
        "Correct-Horse-42",
        source_ip="127.0.0.1",
        user_agent="v0.44-stage3-validator",
    )
    check(session is not None, "valid dashboard login failed")
    principal = facade.authenticate_dashboard_session(
        connection, session["session_token"], required_role="ANALYST"
    )
    check(principal and principal["username"] == "stage3.admin", "session authentication failed")

    token = facade.create_access_api_token(
        connection, admin["user_id"], "stage3-token", role="ANALYST"
    )
    connection.commit()
    token_principal = facade.authenticate_access_api_token(
        connection, token["token"], required_role="ANALYST"
    )
    check(token_principal and token_principal["role"] == "ANALYST", "API-token authentication failed")

    try:
        facade.create_access_api_token(
            connection, viewer["user_id"], "over-privileged", role="ADMIN"
        )
    except facade.DeltaAegisError:
        pass
    else:
        fail("API token exceeded its user's role")

    audit_id = facade.record_access_audit_event(
        connection,
        "stage3_check",
        actor={"user_id": admin["user_id"], "username": "stage3.admin", "role": "ADMIN"},
        target_type="validator",
        target_key="auth-extraction",
        details={"stage": 3},
    )
    connection.commit()
    events = facade.list_access_audit_events(connection, action="STAGE3_CHECK")
    check(events and events[0]["audit_id"] == audit_id, "access audit behavior changed")
    check(events[0]["details"] == {"stage": 3}, "access audit details changed")

    connection.execute(
        "UPDATE access_users SET role = 'VIEWER' WHERE user_id = ?", (admin["user_id"],)
    )
    connection.commit()
    check(
        facade.authenticate_dashboard_session(
            connection, session["session_token"], required_role="ANALYST"
        )
        is None,
        "session retained privilege after user demotion",
    )
    check(
        facade.authenticate_access_api_token(
            connection, token["token"], required_role="ANALYST", update_last_used=False
        )
        is None,
        "API token retained privilege after user demotion",
    )

    original_verifier = facade.verify_access_password
    try:
        facade.verify_access_password = lambda _password, _password_hash: True
        patched_session = facade.dashboard_user_login(
            connection,
            "stage3.viewer",
            "intentionally-wrong",
            source_ip="127.0.0.2",
        )
        check(patched_session is not None, "root password-verifier compatibility seam was lost")
    finally:
        facade.verify_access_password = original_verifier


def main() -> int:
    print("DeltaAegis v0.44 Stage 3 Authentication Boundary Validator")
    print("============================================================")
    characterization = load_characterization()

    validate_ownership_and_facade(characterization)
    print("PASS: extracted authentication ownership and compatibility facade")

    with tempfile.TemporaryDirectory(prefix="deltaaegis-v044-auth-") as temporary:
        database_path = Path(temporary) / "auth.db"
        connection = sqlite3.connect(database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            validate_schema(characterization, connection)
            print("PASS: unchanged users, tokens, audit, and session schema")
            validate_passwords_and_rbac(characterization)
            print("PASS: password, throttle-state, RBAC, and route contracts")
            validate_runtime_behavior(connection)
            print("PASS: login, session, token, role-cap, and audit behavior")
        finally:
            connection.close()

    print("PASS: DeltaAegis v0.44 Stage 3 authentication extraction")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
