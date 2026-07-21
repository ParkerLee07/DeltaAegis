"""Authentication, authorization, session, token, and audit core for DeltaAegis."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
import time
import uuid
from collections import Counter
from datetime import datetime, timezone, timedelta
from typing import Any, Callable


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

ACCESS_ROLES = ("ADMIN", "ANALYST", "VIEWER")


ACCESS_RBAC_PERMISSIONS = {
    "dashboard.read": "VIEWER",
    "operator.session.read": "VIEWER",
    "session.read": "VIEWER",
    "admin.users.read": "ADMIN",
    "admin.users.write": "ADMIN",
    "admin.audit.read": "ADMIN",
    "admin.telemetry.cleanup": "ADMIN",
    "workflow.write": "ANALYST",
    "scan.start": "ADMIN",
    "sites.write": "ADMIN",
    "telemetry.quality.review": "ANALYST",
    "telemetry.quality.override": "ADMIN",
}


ACCESS_RBAC_ROUTE_POLICIES = (
    ("GET", "/", "dashboard.read"),
    ("GET", "/operator", "operator.session.read"),
    ("GET", "/operator/users", "admin.users.read"),
    ("GET", "/operator/reset", "admin.telemetry.cleanup"),
    ("GET", "/operator/telemetry-quality", "operator.session.read"),
    ("GET", "/netsniper", "dashboard.read"),
    ("GET", "/api/sites", "dashboard.read"),
    ("GET", "/api/site-detail", "dashboard.read"),
    ("GET", "/api/site-management", "dashboard.read"),
    ("POST", "/api/site-create", "sites.write"),
    ("POST", "/api/site-rename", "sites.write"),
    ("POST", "/api/site-description", "sites.write"),
    ("POST", "/api/site-archive", "sites.write"),
    ("POST", "/api/site-assign-scope", "sites.write"),
    ("POST", "/api/site-remove-scope", "sites.write"),
    ("GET", "/api/netsniper/status", "dashboard.read"),
    ("GET", "/api/netsniper/job-detail", "dashboard.read"),
    ("GET", "/api/validation-summary", "dashboard.read"),
    ("GET", "/api/validation-correlations", "dashboard.read"),
    ("GET", "/api/validations", "dashboard.read"),
    ("GET", "/api/trueaegis-jobs", "dashboard.read"),
    ("GET", "/api/trueaegis/context", "dashboard.read"),
    ("POST", "/api/validation-ingest", "workflow.write"),
    ("POST", "/api/telemetry-quality/review", "telemetry.quality.review"),
    ("POST", "/api/telemetry-quality/override", "telemetry.quality.override"),
    ("GET", "/api/session", "session.read"),
    ("GET", "/api/admin/users", "admin.users.read"),
    ("GET", "/api/access-audit", "admin.audit.read"),
    ("GET", "/api/telemetry-quality", "dashboard.read"),
    ("GET", "/api/telemetry-quality/detail", "dashboard.read"),
    ("GET", "/api/telemetry-cleanup/preview", "admin.telemetry.cleanup"),
    ("GET", "/api/telemetry-cleanup/audit-events", "admin.telemetry.cleanup"),
    ("POST", "/api/telemetry-cleanup/clear-all", "admin.telemetry.cleanup"),
    ("POST", "/api/admin/users", "admin.users.write"),
    ("POST_PREFIX", "/api/admin/users/", "admin.users.write"),
    ("POST", "/api/ticket-status", "workflow.write"),
    ("POST", "/api/investigate-asset", "workflow.write"),
    ("POST", "/api/netsniper/import-latest", "workflow.write"),
    ("POST", "/api/netsniper/scan-start", "scan.start"),
    ("POST", "/api/netsniper/scan-cancel", "scan.start"),
    ("POST", "/api/trueaegis/run", "scan.start"),
    ("GET", "/api/netsniper/schedules", "dashboard.read"),
    ("GET", "/api/netsniper/schedule-history", "dashboard.read"),
    ("GET", "/api/latest-network-changes", "dashboard.read"),
    ("GET", "/api/scan-freshness", "dashboard.read"),
    ("POST", "/api/netsniper/schedule-create", "scan.start"),
    ("POST", "/api/netsniper/schedule-enable", "scan.start"),
    ("POST", "/api/netsniper/schedule-disable", "scan.start"),
    ("POST", "/api/netsniper/schedule-delete", "scan.start"),
    ("POST", "/api/netsniper/schedule-run-due", "scan.start"),
    ("POST", "/api/netsniper/stale-scan-fail", "admin.telemetry.cleanup"),
    ("POST", "/api/netsniper/hourly-monitoring", "scan.start"),
)


def access_rbac_required_role(permission: str) -> str:
    clean_permission = str(permission or "").strip()

    if clean_permission not in ACCESS_RBAC_PERMISSIONS:
        raise ValueError(f"Unknown DeltaAegis RBAC permission: {permission}")

    return ACCESS_RBAC_PERMISSIONS[clean_permission]


def access_rbac_allows(role: str | None, permission: str) -> bool:
    return access_role_allows(role, access_rbac_required_role(permission))


def dashboard_route_permission(method: str, route: str) -> str | None:
    clean_method = str(method or "").upper()
    clean_route = str(route or "").split("?", 1)[0]

    for policy_method, policy_route, permission in ACCESS_RBAC_ROUTE_POLICIES:
        if policy_method == "POST_PREFIX":
            if clean_method == "POST" and clean_route.startswith(policy_route):
                return permission
            continue

        if clean_method == policy_method and clean_route == policy_route:
            return permission

    if clean_method == "GET" and clean_route.startswith("/api/"):
        return "dashboard.read"

    return None


ACCESS_ROLE_RANKS = {
    "VIEWER": 10,
    "ANALYST": 20,
    "ADMIN": 30,
}


ACCESS_PASSWORD_ALGORITHM = "pbkdf2_sha256"


ACCESS_PASSWORD_ITERATIONS = 260000


ACCESS_PASSWORD_MIN_LENGTH = 8


ACCESS_PASSWORD_MAX_LENGTH = 1024


ACCESS_LOGIN_ACCOUNT_MAX_ATTEMPTS = 5


ACCESS_LOGIN_SOURCE_MAX_ATTEMPTS = 20


ACCESS_LOGIN_WINDOW_SECONDS = 300


ACCESS_LOGIN_MAX_TRACKED_KEYS = 4096


ACCESS_LOGIN_DUMMY_PASSWORD_HASH = (
    "pbkdf2_sha256$260000$deltaaegis-login-dummy-v1$"
    "a6965fd8e5a80577942e0871db72eb3f75957a535075e1cfa92b8d1f8db799f8"
)


ACCESS_API_TOKEN_PREFIX = "da"


ACCESS_API_TOKEN_DEFAULT_TTL_SECONDS = 30 * 24 * 60 * 60


ACCESS_API_TOKEN_MAX_TTL_SECONDS = 365 * 24 * 60 * 60


ACCESS_SESSION_COOKIE_NAME = "deltaaegis_session"


ACCESS_CSRF_COOKIE_NAME = "deltaaegis_csrf"


ACCESS_SESSION_TTL_SECONDS = 8 * 60 * 60


class DeltaAegisError(RuntimeError):
    pass


class DashboardLoginRateLimitedError(DeltaAegisError):
    def __init__(self, retry_after: int):
        super().__init__("too many login attempts; try again later")
        self.retry_after = max(1, int(retry_after))


_ACCESS_LOGIN_ATTEMPTS: dict[tuple[str, str], list[float]] = {}


_ACCESS_LOGIN_ATTEMPTS_LOCK = threading.Lock()


def ensure_enterprise_access_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS access_users ("
        "user_id TEXT PRIMARY KEY,"
        "username TEXT NOT NULL UNIQUE,"
        "display_name TEXT,"
        "role TEXT NOT NULL DEFAULT 'VIEWER',"
        "password_hash TEXT NOT NULL DEFAULT '',"
        "is_active INTEGER NOT NULL DEFAULT 1,"
        "created_at TEXT NOT NULL,"
        "updated_at TEXT NOT NULL,"
        "last_login_at TEXT,"
        "CHECK (role IN ('ADMIN', 'ANALYST', 'VIEWER'))"
        ")"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_users_username "
        "ON access_users(username)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_users_role "
        "ON access_users(role)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS access_api_tokens ("
        "token_id TEXT PRIMARY KEY,"
        "user_id TEXT NOT NULL,"
        "token_name TEXT NOT NULL,"
        "token_hash TEXT NOT NULL UNIQUE,"
        "token_prefix TEXT NOT NULL,"
        "role TEXT NOT NULL DEFAULT 'VIEWER',"
        "is_active INTEGER NOT NULL DEFAULT 1,"
        "created_at TEXT NOT NULL,"
        "updated_at TEXT NOT NULL,"
        "last_used_at TEXT,"
        "expires_at TEXT,"
        "FOREIGN KEY (user_id) REFERENCES access_users(user_id) ON DELETE CASCADE,"
        "CHECK (role IN ('ADMIN', 'ANALYST', 'VIEWER'))"
        ")"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_api_tokens_user_id "
        "ON access_api_tokens(user_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_api_tokens_prefix "
        "ON access_api_tokens(token_prefix)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS access_audit_log ("
        "audit_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "actor_user_id TEXT,"
        "actor_username TEXT,"
        "actor_role TEXT,"
        "action TEXT NOT NULL,"
        "target_type TEXT,"
        "target_key TEXT,"
        "source_ip TEXT,"
        "user_agent TEXT,"
        "detail_json TEXT NOT NULL DEFAULT '{}',"
        "created_at TEXT NOT NULL,"
        "FOREIGN KEY (actor_user_id) REFERENCES access_users(user_id) ON DELETE SET NULL"
        ")"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_audit_log_created_at "
        "ON access_audit_log(created_at)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_audit_log_action "
        "ON access_audit_log(action)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_audit_log_actor_user_id "
        "ON access_audit_log(actor_user_id)"
    )


def normalize_access_role(value: str | None, default: str = "VIEWER") -> str:
    role = str(value or default or "VIEWER").strip().upper().replace("-", "_").replace(" ", "_")

    if role not in ACCESS_ROLE_RANKS:
        raise DeltaAegisError(f"unsupported access role: {value!r}")

    return role


def access_role_allows(role: str | None, required_role: str | None) -> bool:
    actual = normalize_access_role(role)
    required = normalize_access_role(required_role)

    return ACCESS_ROLE_RANKS[actual] >= ACCESS_ROLE_RANKS[required]


def access_effective_role(*roles: str | None) -> str:
    normalized = [normalize_access_role(role) for role in roles]

    if not normalized:
        return "VIEWER"

    return min(normalized, key=lambda role: ACCESS_ROLE_RANKS[role])


def normalize_access_username(username: str) -> str:
    value = str(username or "").strip().lower()

    if not value:
        raise DeltaAegisError("username is required")

    if not re.fullmatch(r"[a-z0-9_.@-]{3,64}", value):
        raise DeltaAegisError(
            "username must be 3-64 characters using letters, numbers, dot, underscore, at-sign, or dash"
        )

    return value


def validate_access_password(password: str) -> str:
    value = str(password or "")

    if not value:
        raise DeltaAegisError("password is required")

    if len(value) < ACCESS_PASSWORD_MIN_LENGTH:
        raise DeltaAegisError(
            f"password must be at least {ACCESS_PASSWORD_MIN_LENGTH} characters"
        )

    if len(value) > ACCESS_PASSWORD_MAX_LENGTH:
        raise DeltaAegisError(
            f"password must be at most {ACCESS_PASSWORD_MAX_LENGTH} characters"
        )

    return value


def hash_access_password(password: str, salt: str | None = None, iterations: int = ACCESS_PASSWORD_ITERATIONS) -> str:
    password_value = validate_access_password(password)

    if iterations < 100000:
        raise DeltaAegisError("password hash iteration count is too low")

    salt_value = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password_value.encode("utf-8"),
        salt_value.encode("utf-8"),
        iterations,
    ).hex()

    return f"{ACCESS_PASSWORD_ALGORITHM}${iterations}${salt_value}${digest}"


def verify_access_password(password: str, password_hash: str | None) -> bool:
    if not password_hash:
        return False

    try:
        algorithm, iterations_text, salt, expected_digest = str(password_hash).split("$", 3)
        iterations = int(iterations_text)
    except (TypeError, ValueError):
        return False

    if algorithm != ACCESS_PASSWORD_ALGORITHM:
        return False

    if iterations < 100000 or iterations > 1000000 or not salt or not expected_digest:
        return False

    candidate_digest = hashlib.pbkdf2_hmac(
        "sha256",
        str(password or "").encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    ).hex()

    return hmac.compare_digest(candidate_digest, expected_digest)


def access_password_hash_is_usable(password_hash: str | None) -> bool:
    try:
        algorithm, iterations_text, salt, expected_digest = str(password_hash or "").split("$", 3)
        iterations = int(iterations_text)
    except (TypeError, ValueError):
        return False

    return bool(
        algorithm == ACCESS_PASSWORD_ALGORITHM
        and 100000 <= iterations <= 1000000
        and salt
        and expected_digest
    )


def _access_login_identity(source_ip: str | None, username: str) -> tuple[str, str]:
    source = str(source_ip or "unknown").strip().lower()[:128] or "unknown"
    account = str(username or "<empty>").strip().lower()[:64] or "<empty>"
    return source, account


def access_login_attempt_reserve(source_ip: str | None, username: str) -> None:
    source, account = _access_login_identity(source_ip, username)
    now = time.monotonic()
    cutoff = now - ACCESS_LOGIN_WINDOW_SECONDS
    dimensions = (
        (("source", source), ACCESS_LOGIN_SOURCE_MAX_ATTEMPTS),
        (("account", account), ACCESS_LOGIN_ACCOUNT_MAX_ATTEMPTS),
    )

    with _ACCESS_LOGIN_ATTEMPTS_LOCK:
        for key in list(_ACCESS_LOGIN_ATTEMPTS):
            recent = [stamp for stamp in _ACCESS_LOGIN_ATTEMPTS[key] if stamp > cutoff]
            if recent:
                _ACCESS_LOGIN_ATTEMPTS[key] = recent
            else:
                del _ACCESS_LOGIN_ATTEMPTS[key]

        retry_after = 0
        for key, maximum in dimensions:
            attempts = _ACCESS_LOGIN_ATTEMPTS.get(key, [])
            if len(attempts) >= maximum:
                retry_after = max(
                    retry_after,
                    int(ACCESS_LOGIN_WINDOW_SECONDS - (now - attempts[0])) + 1,
                )

        if retry_after:
            raise DashboardLoginRateLimitedError(retry_after)

        while len(_ACCESS_LOGIN_ATTEMPTS) + 2 > ACCESS_LOGIN_MAX_TRACKED_KEYS:
            oldest_key = min(
                _ACCESS_LOGIN_ATTEMPTS,
                key=lambda key: _ACCESS_LOGIN_ATTEMPTS[key][-1],
            )
            del _ACCESS_LOGIN_ATTEMPTS[oldest_key]

        for key, _maximum in dimensions:
            _ACCESS_LOGIN_ATTEMPTS.setdefault(key, []).append(now)


def access_login_attempt_clear(source_ip: str | None, username: str) -> None:
    source, account = _access_login_identity(source_ip, username)

    with _ACCESS_LOGIN_ATTEMPTS_LOCK:
        _ACCESS_LOGIN_ATTEMPTS.pop(("source", source), None)
        _ACCESS_LOGIN_ATTEMPTS.pop(("account", account), None)


def hash_access_api_token(token: str) -> str:
    if not token:
        raise DeltaAegisError("API token is required")

    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


def generate_access_api_token() -> str:
    return f"{ACCESS_API_TOKEN_PREFIX}_{secrets.token_urlsafe(32)}"


def access_table_has_column(
    connection: sqlite3.Connection,
    table: str,
    column: str,
) -> bool:
    return any(
        str(row[1]) == str(column)
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    )


def access_api_scopes_for_role(role: str | None) -> tuple[str, ...]:
    normalized_role = normalize_access_role(role)
    return tuple(
        sorted(
            permission
            for permission in ACCESS_RBAC_PERMISSIONS
            if access_rbac_allows(normalized_role, permission)
        )
    )


def normalize_access_api_scopes(
    scopes: Any,
    *,
    role: str | None,
) -> tuple[str, ...]:
    allowed = set(access_api_scopes_for_role(role))
    if scopes is None:
        return tuple(sorted(allowed))
    if isinstance(scopes, str):
        candidates = re.split(r"[\s,]+", scopes.strip()) if scopes.strip() else []
    elif isinstance(scopes, (list, tuple, set, frozenset)):
        candidates = list(scopes)
    else:
        raise DeltaAegisError("API token scopes must be a list or separated string")

    normalized: set[str] = set()
    for candidate in candidates:
        scope = str(candidate or "").strip().lower()
        if not scope:
            continue
        if scope not in ACCESS_RBAC_PERMISSIONS:
            raise DeltaAegisError(f"unsupported API token scope: {scope}")
        if scope not in allowed:
            raise DeltaAegisError(
                f"API token scope {scope} exceeds the token's {normalize_access_role(role)} role"
            )
        normalized.add(scope)

    if not normalized:
        raise DeltaAegisError("at least one API token scope is required")
    return tuple(sorted(normalized))


def parse_stored_access_api_scopes(value: Any) -> tuple[str, ...]:
    """Parse persisted token scopes without trusting mutable database text.

    Authentication must fail closed when a token row is malformed.  In
    particular, valid JSON values such as an object, number, or string are not
    scope lists and must never be iterated as though they granted permissions.
    """

    try:
        parsed = json.loads(str(value or "[]"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return ()
    if not isinstance(parsed, list):
        return ()
    scopes: set[str] = set()
    for candidate in parsed:
        if not isinstance(candidate, str):
            return ()
        scope = candidate.strip().lower()
        if scope not in ACCESS_RBAC_PERMISSIONS:
            return ()
        scopes.add(scope)
    return tuple(sorted(scopes))


def bounded_access_api_token_expiry(
    expires_at: str | None = None,
    *,
    now: datetime | None = None,
) -> str:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)
    requested = access_parse_datetime(expires_at)
    if requested is None:
        if str(expires_at or "").strip():
            raise DeltaAegisError("API token expires_at must be a valid ISO-8601 timestamp")
        requested = current + timedelta(seconds=ACCESS_API_TOKEN_DEFAULT_TTL_SECONDS)
    requested = requested.astimezone(timezone.utc)
    if requested <= current:
        raise DeltaAegisError("API token expiration must be in the future")
    if requested > current + timedelta(seconds=ACCESS_API_TOKEN_MAX_TTL_SECONDS):
        raise DeltaAegisError("API token lifetime must not exceed 365 days")
    return requested.isoformat()


def create_access_user(
    connection: sqlite3.Connection,
    username: str,
    role: str = "VIEWER",
    password: str | None = None,
    display_name: str | None = None,
    is_active: bool = True,
) -> dict[str, Any]:
    ensure_enterprise_access_schema(connection)

    normalized_username = normalize_access_username(username)
    normalized_role = normalize_access_role(role)
    now = utc_now()
    user_id = str(uuid.uuid4())
    password_hash = hash_access_password(password) if password else ""

    connection.execute(
        "INSERT INTO access_users ("
        "user_id, username, display_name, role, password_hash, is_active, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            user_id,
            normalized_username,
            display_name,
            normalized_role,
            password_hash,
            1 if is_active else 0,
            now,
            now,
        ),
    )

    return {
        "user_id": user_id,
        "username": normalized_username,
        "display_name": display_name,
        "role": normalized_role,
        "is_active": bool(is_active),
        "created_at": now,
        "updated_at": now,
    }


def access_user_by_username(connection: sqlite3.Connection, username: str) -> dict[str, Any] | None:
    ensure_enterprise_access_schema(connection)

    normalized_username = normalize_access_username(username)
    row = connection.execute(
        "SELECT user_id, username, display_name, role, password_hash, is_active, "
        "created_at, updated_at, last_login_at "
        "FROM access_users WHERE username = ?",
        (normalized_username,),
    ).fetchone()

    if not row:
        return None

    return dict(row)


def list_access_users(connection: sqlite3.Connection, include_inactive: bool = False) -> list[dict[str, Any]]:
    ensure_enterprise_access_schema(connection)

    where = "" if include_inactive else "WHERE is_active = 1"
    rows = connection.execute(
        "SELECT user_id, username, display_name, role, is_active, created_at, updated_at, last_login_at "
        f"FROM access_users {where} ORDER BY username"
    ).fetchall()

    return [dict(row) for row in rows]


def create_access_api_token(
    connection: sqlite3.Connection,
    user_id: str,
    token_name: str,
    role: str | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    return create_scoped_access_api_token(
        connection,
        user_id,
        token_name,
        role=role,
        expires_at=expires_at,
        scopes=None,
    )


def create_scoped_access_api_token(
    connection: sqlite3.Connection,
    user_id: str,
    token_name: str,
    role: str | None = None,
    expires_at: str | None = None,
    scopes: Any = None,
) -> dict[str, Any]:
    ensure_enterprise_access_schema(connection)

    user = connection.execute(
        "SELECT user_id, username, role, is_active FROM access_users WHERE user_id = ?",
        (user_id,),
    ).fetchone()

    if not user:
        raise DeltaAegisError(f"access user not found: {user_id}")

    if not int(user["is_active"] or 0):
        raise DeltaAegisError(f"access user is inactive: {user['username']}")

    token_value = generate_access_api_token()
    token_hash = hash_access_api_token(token_value)
    token_id = str(uuid.uuid4())
    now = utc_now()
    token_role = normalize_access_role(role or user["role"])
    user_role = normalize_access_role(user["role"])

    if not access_role_allows(user_role, token_role):
        raise DeltaAegisError(
            f"API token role {token_role} exceeds the user's current {user_role} role"
        )

    clean_expires_at = bounded_access_api_token_expiry(expires_at)
    clean_scopes = normalize_access_api_scopes(scopes, role=token_role)

    token_prefix = token_value[:12]
    clean_token_name = str(token_name or "DeltaAegis API Token").strip() or "DeltaAegis API Token"

    if access_table_has_column(connection, "access_api_tokens", "scopes_json"):
        connection.execute(
            "INSERT INTO access_api_tokens ("
            "token_id, user_id, token_name, token_hash, token_prefix, role, "
            "is_active, created_at, updated_at, expires_at, scopes_json"
            ") VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)",
            (
                token_id,
                user_id,
                clean_token_name,
                token_hash,
                token_prefix,
                token_role,
                now,
                now,
                clean_expires_at,
                json.dumps(clean_scopes, separators=(",", ":")),
            ),
        )
    else:
        # Standalone predecessor fixtures intentionally materialize the frozen
        # v0.44 table shape. The application migration adds scopes_json before
        # any stable API credential can be used.
        connection.execute(
            "INSERT INTO access_api_tokens ("
            "token_id, user_id, token_name, token_hash, token_prefix, role, "
            "is_active, created_at, updated_at, expires_at"
            ") VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
            (
                token_id,
                user_id,
                clean_token_name,
                token_hash,
                token_prefix,
                token_role,
                now,
                now,
                clean_expires_at,
            ),
        )

    return {
        "token_id": token_id,
        "user_id": user_id,
        "username": user["username"],
        "token_name": clean_token_name,
        "token": token_value,
        "token_prefix": token_prefix,
        "role": token_role,
        "scopes": list(clean_scopes),
        "created_at": now,
        "expires_at": clean_expires_at,
    }


def record_access_audit_event(
    connection: sqlite3.Connection,
    action: str,
    actor: dict[str, Any] | None = None,
    target_type: str | None = None,
    target_key: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
    details: dict[str, Any] | None = None,
) -> int:
    ensure_enterprise_access_schema(connection)

    actor = actor or {}
    now = utc_now()
    cursor = connection.execute(
        "INSERT INTO access_audit_log ("
        "actor_user_id, actor_username, actor_role, action, target_type, target_key, "
        "source_ip, user_agent, detail_json, created_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            actor.get("user_id"),
            actor.get("username"),
            actor.get("role"),
            str(action or "").strip().upper() or "UNKNOWN",
            target_type,
            target_key,
            source_ip,
            user_agent,
            json.dumps(details or {}, sort_keys=True),
            now,
        ),
    )

    return int(cursor.lastrowid)


def ensure_dashboard_session_schema(connection: sqlite3.Connection) -> None:
    ensure_enterprise_access_schema(connection)

    connection.execute(
        "CREATE TABLE IF NOT EXISTS access_sessions ("
        "session_id TEXT PRIMARY KEY, "
        "user_id TEXT NOT NULL, "
        "session_token_hash TEXT NOT NULL UNIQUE, "
        "role TEXT NOT NULL, "
        "is_active INTEGER NOT NULL DEFAULT 1, "
        "created_at TEXT NOT NULL, "
        "last_seen_at TEXT, "
        "expires_at TEXT NOT NULL, "
        "source_ip TEXT, "
        "user_agent TEXT, "
        "ended_at TEXT, "
        "end_reason TEXT, "
        "FOREIGN KEY(user_id) REFERENCES access_users(user_id)"
        ")"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_sessions_user_id "
        "ON access_sessions(user_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_sessions_token_hash "
        "ON access_sessions(session_token_hash)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_sessions_expires_at "
        "ON access_sessions(expires_at)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_sessions_active "
        "ON access_sessions(is_active)"
    )


def generate_dashboard_session_token() -> str:
    return "ds_" + secrets.token_urlsafe(32)


def generate_dashboard_csrf_token() -> str:
    return "dc_" + secrets.token_urlsafe(32)


def hash_dashboard_session_token(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def hash_dashboard_csrf_token(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def dashboard_session_expiry(ttl_seconds: int = ACCESS_SESSION_TTL_SECONDS) -> str:
    ttl = max(300, int(ttl_seconds or ACCESS_SESSION_TTL_SECONDS))
    return (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat()


def dashboard_user_login(
    connection: sqlite3.Connection,
    username: str,
    password: str,
    source_ip: str | None = None,
    user_agent: str | None = None,
    *,
    password_verifier: Callable[[str, str | None], bool] | None = None,
) -> dict[str, Any] | None:
    ensure_dashboard_session_schema(connection)

    login_name = str(username or "").strip().lower()[:64]

    try:
        access_login_attempt_reserve(source_ip, login_name)
    except DashboardLoginRateLimitedError:
        record_access_audit_event(
            connection,
            action="LOGIN_RATE_LIMITED",
            actor={"username": login_name or None, "role": None},
            target_type="access_user",
            target_key=login_name or "<empty>",
            source_ip=source_ip,
            user_agent=user_agent,
            details={"reason": "rolling_window_limit"},
        )
        connection.commit()
        raise

    try:
        normalized_username = normalize_access_username(username)
    except DeltaAegisError:
        normalized_username = None

    user = (
        access_user_by_username(connection, normalized_username)
        if normalized_username
        else None
    )
    active_user = user if user and int(user.get("is_active") or 0) else None
    stored_hash = (active_user or {}).get("password_hash") or ""
    password_hash = (
        stored_hash
        if access_password_hash_is_usable(stored_hash)
        else ACCESS_LOGIN_DUMMY_PASSWORD_HASH
    )
    verifier = password_verifier or verify_access_password
    password_matches = verifier(password, password_hash)

    if not active_user or not password_matches:
        failure_reason = (
            "invalid_password"
            if active_user
            else "unknown_or_inactive_user"
        )
        record_access_audit_event(
            connection,
            action="LOGIN_FAILED",
            actor={
                "user_id": (user or {}).get("user_id"),
                "username": (user or {}).get("username") or login_name or None,
                "role": (user or {}).get("role"),
            },
            target_type="access_user",
            target_key=(user or {}).get("username") or login_name or "<empty>",
            source_ip=source_ip,
            user_agent=user_agent,
            details={"reason": failure_reason},
        )
        connection.commit()
        return None

    session = create_dashboard_session(
        connection,
        active_user,
        source_ip=source_ip,
        user_agent=user_agent,
    )
    access_login_attempt_clear(source_ip, login_name)
    return session


def create_dashboard_session(
    connection: sqlite3.Connection,
    user: dict[str, Any],
    source_ip: str | None = None,
    user_agent: str | None = None,
    ttl_seconds: int = ACCESS_SESSION_TTL_SECONDS,
) -> dict[str, Any]:
    ensure_dashboard_session_schema(connection)

    session_id = str(uuid.uuid4())
    session_token = generate_dashboard_session_token()
    session_hash = hash_dashboard_session_token(session_token)
    csrf_token = generate_dashboard_csrf_token()
    csrf_hash = hash_dashboard_csrf_token(csrf_token)
    now = utc_now()
    expires_at = dashboard_session_expiry(ttl_seconds)

    role = normalize_access_role(user.get("role") or "VIEWER")

    if access_table_has_column(connection, "access_sessions", "csrf_token_hash"):
        connection.execute(
            "INSERT INTO access_sessions ("
            "session_id, user_id, session_token_hash, role, is_active, "
            "created_at, last_seen_at, expires_at, source_ip, user_agent, csrf_token_hash"
            ") VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)",
            (
                session_id,
                user.get("user_id"),
                session_hash,
                role,
                now,
                now,
                expires_at,
                source_ip,
                user_agent,
                csrf_hash,
            ),
        )
    else:
        connection.execute(
            "INSERT INTO access_sessions ("
            "session_id, user_id, session_token_hash, role, is_active, "
            "created_at, last_seen_at, expires_at, source_ip, user_agent"
            ") VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)",
            (
                session_id,
                user.get("user_id"),
                session_hash,
                role,
                now,
                now,
                expires_at,
                source_ip,
                user_agent,
            ),
        )
        csrf_token = ""

    actor = {
        "user_id": user.get("user_id"),
        "username": user.get("username"),
        "role": role,
    }

    record_access_audit_event(
        connection,
        action="LOGIN_SUCCESS",
        actor=actor,
        target_type="access_session",
        target_key=session_id,
        source_ip=source_ip,
        user_agent=user_agent,
        details={
            "session_id": session_id,
            "expires_at": expires_at,
            "role": role,
        },
    )
    connection.commit()

    return {
        "session_id": session_id,
        "session_token": session_token,
        "session_token_hash": session_hash,
        "csrf_token": csrf_token,
        "user_id": user.get("user_id"),
        "username": user.get("username"),
        "display_name": user.get("display_name"),
        "role": role,
        "expires_at": expires_at,
    }


def session_is_expired(expires_at: str | None) -> bool:
    if not expires_at:
        return True

    try:
        expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
    except ValueError:
        return True

    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)

    return expiry <= datetime.now(timezone.utc)


def authenticate_dashboard_session(
    connection: sqlite3.Connection,
    session_token: str,
    required_role: str = "VIEWER",
    update_last_seen: bool = True,
) -> dict[str, Any] | None:
    ensure_dashboard_session_schema(connection)

    token = str(session_token or "").strip()

    if not token:
        return None

    session_hash = hash_dashboard_session_token(token)

    csrf_select = (
        "s.csrf_token_hash"
        if access_table_has_column(connection, "access_sessions", "csrf_token_hash")
        else "'' AS csrf_token_hash"
    )
    row = connection.execute(
        "SELECT "
        "s.session_id, "
        "s.user_id, "
        "s.role AS session_role, "
        "s.is_active AS session_active, "
        "s.created_at AS session_created_at, "
        "s.last_seen_at, "
        "s.expires_at, "
        f"{csrf_select}, "
        "u.username, "
        "u.display_name, "
        "u.role AS user_role, "
        "u.is_active AS user_active "
        "FROM access_sessions s "
        "JOIN access_users u ON u.user_id = s.user_id "
        "WHERE s.session_token_hash = ?",
        (session_hash,),
    ).fetchone()

    if not row:
        return None

    actor = {
        "auth_type": "dashboard_session",
        "session_id": row["session_id"],
        "user_id": row["user_id"],
        "username": row["username"],
        "display_name": row["display_name"],
        # Authorization follows the user's current role. The session role is
        # retained only as issuance evidence and can never preserve a removed
        # privilege after an administrator demotes the account.
        "role": normalize_access_role(row["user_role"] or "VIEWER"),
        "session_issued_role": normalize_access_role(
            row["session_role"] or row["user_role"] or "VIEWER"
        ),
        "expires_at": row["expires_at"],
        "_csrf_token_hash": row["csrf_token_hash"],
    }

    if not int(row["session_active"] or 0) or not int(row["user_active"] or 0):
        return None

    if session_is_expired(row["expires_at"]):
        expire_dashboard_session(
            connection,
            token,
            actor=actor,
            reason="expired",
            commit=True,
        )
        return None

    if not access_role_allows(actor["role"], required_role):
        return None

    if update_last_seen:
        now = utc_now()
        connection.execute(
            "UPDATE access_sessions "
            "SET last_seen_at = ? "
            "WHERE session_id = ?",
            (now, row["session_id"]),
        )
        connection.commit()
        actor["last_seen_at"] = now

    return actor


def verify_dashboard_csrf_token(
    actor: dict[str, Any] | None,
    supplied_token: str | None,
) -> bool:
    expected = str((actor or {}).get("_csrf_token_hash") or "")
    supplied = str(supplied_token or "").strip()
    if not expected or not supplied:
        return False
    return hmac.compare_digest(expected, hash_dashboard_csrf_token(supplied))


def revoke_dashboard_user_sessions(
    connection: sqlite3.Connection,
    user_id: str,
    reason: str,
) -> int:
    """Revoke every live browser session for one user inside the caller's transaction."""
    ensure_dashboard_session_schema(connection)
    now = utc_now()
    cursor = connection.execute(
        "UPDATE access_sessions "
        "SET is_active = 0, ended_at = COALESCE(ended_at, ?), end_reason = ? "
        "WHERE user_id = ? AND is_active = 1",
        (now, str(reason or "administrative_change"), str(user_id or "")),
    )
    return max(0, int(cursor.rowcount or 0))


def expire_dashboard_session(
    connection: sqlite3.Connection,
    session_token: str,
    actor: dict[str, Any] | None = None,
    reason: str = "logout",
    commit: bool = True,
) -> bool:
    ensure_dashboard_session_schema(connection)

    token = str(session_token or "").strip()

    if not token:
        return False

    session_hash = hash_dashboard_session_token(token)
    now = utc_now()

    row = connection.execute(
        "SELECT session_id, user_id, role "
        "FROM access_sessions "
        "WHERE session_token_hash = ?",
        (session_hash,),
    ).fetchone()

    if not row:
        return False

    connection.execute(
        "UPDATE access_sessions "
        "SET is_active = 0, ended_at = ?, end_reason = ? "
        "WHERE session_id = ?",
        (now, str(reason or "logout"), row["session_id"]),
    )

    record_access_audit_event(
        connection,
        action="LOGOUT" if str(reason or "").lower() == "logout" else "SESSION_EXPIRED",
        actor=actor,
        target_type="access_session",
        target_key=row["session_id"],
        details={"reason": reason},
    )

    if commit:
        connection.commit()

    return True


def access_parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None

    text_value = str(value).strip()

    if not text_value:
        return None

    if text_value.endswith("Z"):
        text_value = text_value[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text_value)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def access_token_is_expired(expires_at: str | None) -> bool:
    if not str(expires_at or "").strip():
        return False

    parsed = access_parse_datetime(expires_at)

    if not parsed:
        return True

    return parsed <= datetime.now(timezone.utc)


def access_token_expiry_is_bounded(
    expires_at: str | None,
    *,
    now: datetime | None = None,
) -> bool:
    """Fail closed when a stable-API token exceeds the maximum live TTL."""

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)
    parsed = access_parse_datetime(expires_at)
    if parsed is None:
        return False
    parsed = parsed.astimezone(timezone.utc)
    return current < parsed <= current + timedelta(
        seconds=ACCESS_API_TOKEN_MAX_TTL_SECONDS
    )


def authenticate_access_api_token(
    connection: sqlite3.Connection,
    token: str,
    required_role: str = "VIEWER",
    update_last_used: bool = True,
) -> dict[str, Any] | None:
    ensure_enterprise_access_schema(connection)

    supplied = str(token or "").strip()

    if not supplied:
        return None

    token_hash = hash_access_api_token(supplied)
    scopes_select = (
        "t.scopes_json"
        if access_table_has_column(connection, "access_api_tokens", "scopes_json")
        else "'[]' AS scopes_json"
    )
    row = connection.execute(
        "SELECT "
        "t.token_id, "
        "t.user_id, "
        "t.token_name, "
        "t.token_prefix, "
        "t.role AS token_role, "
        "t.is_active AS token_active, "
        "t.created_at AS token_created_at, "
        "t.updated_at AS token_updated_at, "
        "t.last_used_at, "
        "t.expires_at, "
        f"{scopes_select}, "
        "u.username, "
        "u.display_name, "
        "u.role AS user_role, "
        "u.is_active AS user_active "
        "FROM access_api_tokens t "
        "JOIN access_users u ON u.user_id = t.user_id "
        "WHERE t.token_hash = ?",
        (token_hash,),
    ).fetchone()

    if not row:
        return None

    if not int(row["token_active"] or 0):
        return None

    if not int(row["user_active"] or 0):
        return None

    if access_token_is_expired(row["expires_at"]):
        return None

    token_role = normalize_access_role(row["token_role"])
    user_role = normalize_access_role(row["user_role"])
    effective_role = access_effective_role(token_role, user_role)

    if not access_role_allows(effective_role, required_role):
        return None

    authenticated_at = utc_now()

    if update_last_used:
        connection.execute(
            "UPDATE access_api_tokens "
            "SET last_used_at = ?, updated_at = ? "
            "WHERE token_id = ?",
            (authenticated_at, authenticated_at, row["token_id"]),
        )
        connection.commit()

    stored_scopes = parse_stored_access_api_scopes(row["scopes_json"])
    effective_scopes = sorted(
        scope
        for scope in stored_scopes
        if scope in ACCESS_RBAC_PERMISSIONS
        and access_rbac_allows(effective_role, scope)
    )

    return {
        "auth_type": "api_token",
        "token_id": row["token_id"],
        "token_name": row["token_name"],
        "token_prefix": row["token_prefix"],
        "user_id": row["user_id"],
        "username": row["username"],
        "display_name": row["display_name"],
        "role": effective_role,
        "token_role": token_role,
        "user_role": user_role,
        "last_used_at": authenticated_at if update_last_used else row["last_used_at"],
        "expires_at": row["expires_at"],
        "created_at": row["token_created_at"],
        "scopes": effective_scopes,
        "authenticated_at": authenticated_at,
    }


def authenticate_scoped_access_api_token(
    connection: sqlite3.Connection,
    token: str,
    required_scope: str,
    update_last_used: bool = True,
) -> dict[str, Any] | None:
    scope = str(required_scope or "").strip().lower()
    if scope not in ACCESS_RBAC_PERMISSIONS:
        raise DeltaAegisError(f"unsupported API authorization scope: {required_scope}")
    if not access_table_has_column(connection, "access_api_tokens", "scopes_json"):
        return None
    actor = authenticate_access_api_token(
        connection,
        token,
        required_role="VIEWER",
        update_last_used=False,
    )
    if not actor or not access_token_expiry_is_bounded(actor.get("expires_at")):
        return None
    if scope not in set(actor.get("scopes") or ()):
        return None
    if not access_rbac_allows(actor.get("role"), scope):
        return None

    authenticated_at = utc_now()
    if update_last_used:
        connection.execute(
            "UPDATE access_api_tokens SET last_used_at = ?, updated_at = ? "
            "WHERE token_id = ?",
            (authenticated_at, authenticated_at, actor["token_id"]),
        )
        connection.commit()
    actor["auth_type"] = "api_token_v1"
    actor["authenticated_at"] = authenticated_at
    actor["last_used_at"] = authenticated_at if update_last_used else actor.get("last_used_at")
    return actor


def access_actor_allows_scope(actor: dict[str, Any] | None, scope: str) -> bool:
    permission = str(scope or "").strip().lower()
    if permission not in ACCESS_RBAC_PERMISSIONS or not actor:
        return False
    if not access_rbac_allows(actor.get("role"), permission):
        return False
    if str(actor.get("auth_type") or "").startswith("api_token"):
        return permission in set(actor.get("scopes") or ())
    return True


def list_access_api_tokens(
    connection: sqlite3.Connection,
    include_inactive: bool = False,
) -> list[dict[str, Any]]:
    ensure_enterprise_access_schema(connection)

    where = "" if include_inactive else "WHERE t.is_active = 1 AND u.is_active = 1"
    scopes_select = (
        "t.scopes_json"
        if access_table_has_column(connection, "access_api_tokens", "scopes_json")
        else "'[]' AS scopes_json"
    )
    rows = connection.execute(
        "SELECT "
        "t.token_id, "
        "t.user_id, "
        "u.username, "
        "t.token_name, "
        "t.token_prefix, "
        "t.role, "
        "t.is_active, "
        "t.created_at, "
        "t.updated_at, "
        "t.last_used_at, "
        "t.expires_at, "
        f"{scopes_select} "
        "FROM access_api_tokens t "
        "JOIN access_users u ON u.user_id = t.user_id "
        f"{where} "
        "ORDER BY t.created_at DESC, t.token_name"
    ).fetchall()

    result: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        scopes = parse_stored_access_api_scopes(
            item.pop("scopes_json", "[]")
        )
        item["scopes"] = [
            scope for scope in scopes if scope in ACCESS_RBAC_PERMISSIONS
        ]
        result.append(item)
    return result


def list_access_audit_events(
    connection: sqlite3.Connection,
    limit: int = 50,
    action: str | None = None,
    actor: str | None = None,
    target_type: str | None = None,
) -> list[dict[str, Any]]:
    ensure_enterprise_access_schema(connection)

    requested_limit = max(1, min(int(limit or 50), 500))
    clauses = []
    values: list[Any] = []

    if action:
        clauses.append("action = ?")
        values.append(str(action).strip().upper())

    if actor:
        clauses.append("(actor_username = ? OR actor_user_id = ?)")
        values.extend([str(actor).strip(), str(actor).strip()])

    if target_type:
        clauses.append("target_type = ?")
        values.append(str(target_type).strip())

    where = "WHERE " + " AND ".join(clauses) if clauses else ""

    rows = connection.execute(
        "SELECT "
        "audit_id, "
        "actor_user_id, "
        "actor_username, "
        "actor_role, "
        "action, "
        "target_type, "
        "target_key, "
        "source_ip, "
        "user_agent, "
        "detail_json, "
        "created_at "
        "FROM access_audit_log "
        f"{where} "
        "ORDER BY audit_id DESC "
        "LIMIT ?",
        (*values, requested_limit),
    ).fetchall()

    events: list[dict[str, Any]] = []

    for row in rows:
        detail_json = row["detail_json"] or "{}"

        try:
            details = json.loads(detail_json)
        except json.JSONDecodeError:
            details = {"raw": detail_json}

        event = dict(row)
        event["details"] = details
        events.append(event)

    return events


def access_audit_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    action_counts = Counter(str(row.get("action") or "UNKNOWN") for row in rows)
    actor_counts = Counter(str(row.get("actor_username") or "system") for row in rows)

    return {
        "event_count": len(rows),
        "action_counts": dict(action_counts),
        "actor_counts": dict(actor_counts),
    }


def dashboard_access_audit_payload(
    connection: sqlite3.Connection,
    limit: int = 25,
    action: str | None = None,
    actor: str | None = None,
    target_type: str | None = None,
) -> dict[str, Any]:
    rows = list_access_audit_events(
        connection,
        limit=limit,
        action=action,
        actor=actor,
        target_type=target_type,
    )

    return {
        "available": True,
        "items": rows,
        "item_count": len(rows),
        "summary": access_audit_summary(rows),
        "filters": {
            "action": str(action or "").strip().upper() or "ALL",
            "actor": str(actor or "").strip() or "ALL",
            "target_type": str(target_type or "").strip() or "ALL",
        },
    }
