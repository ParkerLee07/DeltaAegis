#!/usr/bin/env python3
"""Validate the DeltaAegis v1 Stage 2 API and web-security boundary."""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlencode


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import deltaaegis  # noqa: E402
from deltaaegis_core import api_v1, auth, web  # noqa: E402


SECURITY_HEADERS = {
    "content-security-policy",
    "cross-origin-opener-policy",
    "permissions-policy",
    "referrer-policy",
    "x-content-type-options",
    "x-frame-options",
}
REQUEST_ID_RE = re.compile(r"[A-Za-z0-9._:-]{8,128}")
OPENAPI_DOCUMENT = api_v1.openapi_document()


class ValidationFailure(RuntimeError):
    pass


def check(condition: Any, message: str) -> None:
    if not condition:
        raise ValidationFailure(message)


def openapi_resolve(reference: str) -> Any:
    check(reference.startswith("#/"), f"non-local OpenAPI reference: {reference}")
    current: Any = OPENAPI_DOCUMENT
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        check(isinstance(current, dict) and part in current, f"unresolved OpenAPI reference: {reference}")
        current = current[part]
    return current


def validate_schema_instance(instance: Any, schema: Mapping[str, Any], path: str = "$") -> None:
    if "$ref" in schema:
        validate_schema_instance(instance, openapi_resolve(str(schema["$ref"])), path)
        return
    for member in schema.get("allOf", []):
        validate_schema_instance(instance, member, path)
    if "const" in schema:
        check(instance == schema["const"], f"{path} differs from schema const")
    if "enum" in schema:
        check(instance in schema["enum"], f"{path} is outside schema enum")
    expected_type = schema.get("type")
    if expected_type is not None:
        allowed = expected_type if isinstance(expected_type, list) else [expected_type]
        type_checks = {
            "array": lambda value: isinstance(value, list),
            "boolean": lambda value: isinstance(value, bool),
            "integer": lambda value: isinstance(value, int) and not isinstance(value, bool),
            "null": lambda value: value is None,
            "number": lambda value: isinstance(value, (int, float)) and not isinstance(value, bool),
            "object": lambda value: isinstance(value, dict),
            "string": lambda value: isinstance(value, str),
        }
        check(
            any(type_checks[name](instance) for name in allowed),
            f"{path} does not match schema type {allowed}",
        )
    if isinstance(instance, dict):
        required = schema.get("required", [])
        missing = sorted(set(required) - set(instance))
        check(not missing, f"{path} is missing required fields: {missing}")
        properties = schema.get("properties", {})
        for name, child_schema in properties.items():
            if name in instance:
                validate_schema_instance(instance[name], child_schema, f"{path}.{name}")
        if schema.get("additionalProperties") is False:
            unexpected = sorted(set(instance) - set(properties))
            check(not unexpected, f"{path} has unexpected fields: {unexpected}")
    if isinstance(instance, list) and isinstance(schema.get("items"), dict):
        for index, item in enumerate(instance):
            validate_schema_instance(item, schema["items"], f"{path}[{index}]")
    if isinstance(instance, str):
        if "minLength" in schema:
            check(len(instance) >= int(schema["minLength"]), f"{path} is shorter than schema minimum")
        if "maxLength" in schema:
            check(len(instance) <= int(schema["maxLength"]), f"{path} exceeds schema maximum")
        if "pattern" in schema:
            check(re.search(str(schema["pattern"]), instance) is not None, f"{path} does not match schema pattern")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema:
            check(instance >= schema["minimum"], f"{path} is below schema minimum")
        if "maximum" in schema:
            check(instance <= schema["maximum"], f"{path} exceeds schema maximum")


def validate_openapi_http_response(method: str, path: str, response: "Response", document: Any) -> None:
    route = path.split("?", 1)[0]
    endpoint = next(
        (
            item
            for item in api_v1.API_V1_ENDPOINTS
            if item.method == method.upper()
            and re.fullmatch(
                re.sub(
                    r"\\\{[a-z_]+\\\}",
                    r"[^/]+",
                    re.escape(item.template),
                ),
                route,
            )
        ),
        None,
    )
    if endpoint is None:
        return
    operation = OPENAPI_DOCUMENT["paths"][endpoint.template][method.lower()]
    response_contract = (operation.get("responses") or {}).get(str(response.status))
    check(response_contract is not None, f"OpenAPI omits HTTP {response.status} for {endpoint.operation_id}")
    if "$ref" in response_contract:
        response_contract = openapi_resolve(str(response_contract["$ref"]))
    schema = (((response_contract.get("content") or {}).get("application/json") or {}).get("schema"))
    check(isinstance(schema, dict), f"OpenAPI response schema is missing for {endpoint.operation_id}")
    validate_schema_instance(document, schema)


@dataclass(frozen=True)
class Response:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def values(self, name: str) -> list[str]:
        lowered = name.casefold()
        return [value for key, value in self.headers if key.casefold() == lowered]

    def value(self, name: str) -> str:
        values = self.values(name)
        return values[-1] if values else ""

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationFailure(
                f"HTTP {self.status} did not contain JSON: {self.body[:500]!r}"
            ) from exc


def assert_security_headers(response: Response) -> None:
    names = {name.casefold() for name, _value in response.headers}
    missing = sorted(SECURITY_HEADERS - names)
    check(not missing, f"HTTP {response.status} is missing security headers: {missing}")
    check(response.value("Cache-Control") == "no-store", "response is not marked no-store")
    check(response.value("X-Frame-Options") == "DENY", "frame denial header drift")
    check(response.value("X-Content-Type-Options") == "nosniff", "MIME-sniffing header drift")


class HttpClient:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port

    @property
    def origin(self) -> str:
        return f"http://{self.host}:{self.port}"

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | str | None = None,
    ) -> Response:
        payload = body.encode("utf-8") if isinstance(body, str) else body
        connection = http.client.HTTPConnection(self.host, self.port, timeout=10)
        try:
            connection.request(method, path, body=payload, headers=dict(headers or {}))
            raw = connection.getresponse()
            result = Response(raw.status, tuple(raw.getheaders()), raw.read())
        finally:
            connection.close()
        assert_security_headers(result)
        return result

    def raw_request(
        self,
        method: str,
        path: str,
        *,
        headers: list[tuple[str, str]],
        body: bytes = b"",
    ) -> Response:
        """Send exact header multiplicity without http.client normalization."""

        connection = http.client.HTTPConnection(self.host, self.port, timeout=10)
        try:
            has_host = any(name.casefold() == "host" for name, _value in headers)
            connection.putrequest(method, path, skip_host=has_host)
            for name, value in headers:
                connection.putheader(name, value)
            connection.endheaders(body)
            raw = connection.getresponse()
            result = Response(raw.status, tuple(raw.getheaders()), raw.read())
        finally:
            connection.close()
        assert_security_headers(result)
        return result

    def json_request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        cookie: str | None = None,
        csrf: str | None = None,
        origin: str | None = None,
        idempotency_key: str | None = None,
        request_id: str | None = None,
        payload: Any | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> tuple[Response, Any]:
        request_headers = dict(headers or {})
        if token:
            request_headers["Authorization"] = f"Bearer {token}"
        if cookie:
            request_headers["Cookie"] = cookie
        if csrf:
            request_headers["X-DeltaAegis-CSRF"] = csrf
        if origin:
            request_headers["Origin"] = origin
        if idempotency_key:
            request_headers["Idempotency-Key"] = idempotency_key
        if request_id:
            request_headers["X-Request-ID"] = request_id
        body: bytes | None = None
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        response = self.request(method, path, headers=request_headers, body=body)
        document = response.json()
        if path == "/api/v1" or path.startswith("/api/v1/"):
            validate_openapi_http_response(method, path, response, document)
        if path == "/api/v1/openapi.json" and response.status == 200:
            return response, document
        if path == "/api/v1" or path.startswith("/api/v1/"):
            check(isinstance(document, dict), "stable API response is not an object")
            api_v1.validate_envelope(document)
            response_id = response.value("X-Request-ID")
            check(response_id == document["meta"]["request_id"], "request ID header/envelope mismatch")
            check(REQUEST_ID_RE.fullmatch(response_id) is not None, "response request ID is malformed")
            check(len(response.body) < 65536, "stable API error or response is unexpectedly unbounded")
            check(b"Traceback" not in response.body, "stable API exposed a traceback")
        return response, document


def unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def seed_database(database: Path) -> dict[str, Any]:
    connection = deltaaegis.connect(database)
    try:
        admin = auth.create_access_user(
            connection,
            "stage2-admin",
            role="ADMIN",
            password="Stage2-Validation!2026",
            display_name="Stage 2 Admin",
        )
        viewer = auth.create_access_user(
            connection,
            "stage2-viewer",
            role="VIEWER",
            password="Stage2-Viewer!2026",
        )
        demoted = auth.create_access_user(
            connection,
            "stage2-demoted",
            role="ADMIN",
            password="Stage2-Demoted!2026",
        )

        read_token = auth.create_scoped_access_api_token(
            connection,
            viewer["user_id"],
            "read-only",
            role="VIEWER",
            scopes=["dashboard.read", "session.read"],
        )
        write_token = auth.create_scoped_access_api_token(
            connection,
            admin["user_id"],
            "site-writer",
            role="ADMIN",
            scopes=["dashboard.read", "session.read", "sites.write"],
        )
        write_only_token = auth.create_scoped_access_api_token(
            connection,
            admin["user_id"],
            "site-write-only",
            role="ADMIN",
            scopes=["sites.write"],
        )
        demoted_token = auth.create_scoped_access_api_token(
            connection,
            demoted["user_id"],
            "demoted-writer",
            role="ADMIN",
            scopes=["sites.write"],
        )
        revoked_token = auth.create_scoped_access_api_token(
            connection,
            admin["user_id"],
            "revoked-writer",
            role="ADMIN",
            scopes=["sites.write"],
        )
        malformed_token = auth.create_scoped_access_api_token(
            connection,
            admin["user_id"],
            "malformed-scopes",
            role="ADMIN",
            scopes=["sites.write"],
        )
        default_token = auth.create_access_api_token(
            connection,
            viewer["user_id"],
            "default-bounded",
        )

        default_expiry = auth.access_parse_datetime(default_token["expires_at"])
        now = datetime.now(timezone.utc)
        check(default_expiry is not None, "default API token has no expiration")
        check(timedelta(days=29) < default_expiry - now < timedelta(days=31), "default API token lifetime is not 30 days")
        try:
            auth.bounded_access_api_token_expiry(
                (now + timedelta(days=366)).isoformat()
            )
        except deltaaegis.DeltaAegisError:
            pass
        else:
            raise ValidationFailure("API token lifetime beyond 365 days was accepted")
        try:
            auth.normalize_access_api_scopes(["sites.write"], role="VIEWER")
        except deltaaegis.DeltaAegisError:
            pass
        else:
            raise ValidationFailure("VIEWER token was allowed an ADMIN scope")

        now_text = now.isoformat()
        manual_tokens = {
            "unbounded": "da_unbounded_stage2_fixture",
            "expired": "da_expired_stage2_fixture",
            "far_future": "da_far_future_stage2_fixture",
        }
        for name, token in manual_tokens.items():
            connection.execute(
                "INSERT INTO access_api_tokens ("
                "token_id, user_id, token_name, token_hash, token_prefix, role, "
                "is_active, created_at, updated_at, expires_at, scopes_json"
                ") VALUES (?, ?, ?, ?, ?, 'ADMIN', 1, ?, ?, ?, ?)",
                (
                    f"manual-{name}",
                    admin["user_id"],
                    name,
                    auth.hash_access_api_token(token),
                    token[:12],
                    now_text,
                    now_text,
                    (
                        None
                        if name == "unbounded"
                        else (
                            now + timedelta(days=366)
                            if name == "far_future"
                            else now - timedelta(minutes=1)
                        ).isoformat()
                    ),
                    '["sites.write"]',
                ),
            )
        connection.execute(
            "UPDATE access_users SET role = 'VIEWER', updated_at = ? WHERE user_id = ?",
            (now_text, demoted["user_id"]),
        )
        connection.execute(
            "UPDATE access_api_tokens SET is_active = 0 WHERE token_id = ?",
            (revoked_token["token_id"],),
        )
        connection.execute(
            "UPDATE access_api_tokens SET scopes_json = '{}' WHERE token_id = ?",
            (malformed_token["token_id"],),
        )
        connection.commit()
        check(
            auth.authenticate_scoped_access_api_token(
                connection,
                malformed_token["token"],
                "sites.write",
                update_last_used=False,
            )
            is None,
            "malformed persisted scopes did not fail closed",
        )
        return {
            "admin": admin,
            "viewer": viewer,
            "read": read_token,
            "write": write_token,
            "write_only": write_only_token,
            "demoted": demoted_token,
            "revoked": revoked_token,
            "malformed": malformed_token,
            **manual_tokens,
        }
    finally:
        connection.close()


def start_server(
    database: Path,
    root: Path,
    port: int,
    *,
    lan: bool = False,
    public_origin: str | None = None,
    secure_cookies: bool = False,
) -> subprocess.Popen[bytes]:
    command = [
        sys.executable,
        "-u",
        str(ROOT / "deltaaegis.py"),
        "--db",
        str(database),
        "--events",
        str(root / "events.jsonl"),
        "--reports-dir",
        str(root / "reports"),
        "dashboard",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--token",
        "legacy-dashboard-secret",
        "--require-login",
        "--no-enable-scheduled-scans",
        "--quiet",
    ]
    if lan:
        command.append("--lan")
    if public_origin:
        command.extend(("--public-origin", public_origin))
    if secure_cookies:
        command.append("--secure-cookies")
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.Popen(
        command,
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def wait_for_server(
    process: subprocess.Popen[bytes],
    client: HttpClient,
    *,
    host_header: str | None = None,
) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = (process.stdout.read() if process.stdout else b"").decode("utf-8", errors="replace")
            raise ValidationFailure(f"dashboard exited during startup:\n{output}")
        try:
            response = client.request(
                "GET",
                "/healthz",
                headers={"Host": host_header} if host_header else None,
            )
        except OSError:
            time.sleep(0.05)
            continue
        check(response.status == 200 and response.body == b"ok", "dashboard health endpoint failed")
        return
    raise ValidationFailure("dashboard did not start within 15 seconds")


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def cookie_values(
    response: Response,
    *,
    secure: bool = False,
) -> tuple[str, str, str]:
    values = response.values("Set-Cookie")
    check(len(values) == 2, "login did not emit exactly session and CSRF cookies")
    session_header = next((value for value in values if value.startswith("deltaaegis_session=")), "")
    csrf_header = next((value for value in values if value.startswith("deltaaegis_csrf=")), "")
    check(session_header and csrf_header, "login cookies have unexpected names")
    check("HttpOnly" in session_header and "SameSite=Strict" in session_header, "session cookie attributes are unsafe")
    check("HttpOnly" not in csrf_header and "SameSite=Strict" in csrf_header, "CSRF cookie attributes are incorrect")
    if secure:
        check(
            "; Secure" in session_header and "; Secure" in csrf_header,
            "HTTPS proxy cookies were not marked Secure",
        )
    else:
        check(
            "; Secure" not in session_header and "; Secure" not in csrf_header,
            "direct HTTP cookies were incorrectly marked Secure",
        )
    session_pair = session_header.split(";", 1)[0]
    csrf_pair = csrf_header.split(";", 1)[0]
    csrf_token = csrf_pair.split("=", 1)[1]
    return f"{session_pair}; {csrf_pair}", csrf_token, session_pair.split("=", 1)[1]


def validate_openapi_contract(client: HttpClient) -> None:
    document = api_v1.openapi_document()
    api_v1.validate_openapi_document(document)
    artifact_path = ROOT / "contracts" / "v1" / "openapi.json"
    check(artifact_path.is_file(), "tracked OpenAPI artifact is missing")
    try:
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationFailure(f"tracked OpenAPI artifact is unreadable: {exc}") from exc
    check(artifact == document, "tracked OpenAPI artifact differs from runtime generation")
    serialized = json.dumps(document, sort_keys=True, separators=(",", ":"))
    check("/api/v1/sites" in serialized and "Idempotency-Key" in serialized, "OpenAPI mutation contract is incomplete")
    check(document["openapi"] == "3.1.0", "OpenAPI version drift")
    check(document["jsonSchemaDialect"].endswith("2020-12/schema"), "OpenAPI JSON Schema dialect drift")
    check(document["servers"] == [{"url": "/"}], "OpenAPI server URL duplicates the stable path prefix")
    response, served = client.json_request("GET", "/api/v1/openapi.json")
    check(response.status == 200, "OpenAPI endpoint failed")
    check(served == document, "served OpenAPI document differs from runtime inventory")
    check("api_version" not in served, "OpenAPI endpoint was incorrectly wrapped in an API envelope")


def validate_read_surface(client: HttpClient, tokens: dict[str, Any]) -> None:
    request_id = "stage2.request-0001"
    response, payload = client.json_request("GET", "/api/v1", request_id=request_id)
    check(response.status == 200 and payload["ok"] is True, "stable API discovery failed")
    check(response.value("X-Request-ID") == request_id, "valid caller request ID was not preserved")

    response, payload = client.json_request("GET", "/api/v1/summary")
    check(response.status == 401 and payload["error"]["code"] == "unauthorized", "missing stable API authentication did not fail")

    read_token = tokens["read"]["token"]
    for path in (
        "/api/v1/session",
        "/api/v1/summary",
        "/api/v1/scopes?limit=1&offset=0",
        "/api/v1/sites?limit=1&offset=0",
        "/api/v1/assets?limit=1&offset=0",
        "/api/v1/events?limit=1&offset=0",
        "/api/v1/alerts?limit=1&offset=0",
        "/api/v1/scan-jobs?limit=1&offset=0",
        "/api/v1/validations?limit=1&offset=0",
        "/api/v1/telemetry-quality/decisions?limit=1&offset=0",
    ):
        response, payload = client.json_request("GET", path, token=read_token)
        check(response.status == 200 and payload["ok"] is True, f"stable read endpoint failed: {path}")

    response, payload = client.json_request("GET", "/api/v1/sites?limit=0", token=read_token)
    check(response.status == 400 and payload["error"]["code"] == "invalid_pagination", "invalid pagination was accepted")
    response, payload = client.json_request("GET", "/api/v1/not-real", token=read_token)
    check(response.status == 404 and payload["error"]["code"] == "not_found", "unknown stable route did not use the error envelope")
    response, payload = client.json_request("PUT", "/api/v1/sites", token=read_token, payload={"name": "wrong method"})
    check(response.status == 405 and payload["error"]["code"] == "method_not_allowed", "stable unsupported method did not return 405")

    response = client.request(
        "GET",
        "/api/session",
        headers={"X-DeltaAegis-Token": "legacy-dashboard-secret"},
    )
    check(response.status == 200 and response.json().get("auth_type") == "legacy_dashboard_token", "private compatibility API stopped accepting its legacy credential")
    response, payload = client.json_request(
        "GET",
        "/api/v1/summary",
        headers={"X-DeltaAegis-Token": read_token},
    )
    check(response.status == 401 and payload["error"]["code"] == "unauthorized", "stable API accepted the private X-DeltaAegis-Token transport")
    response, payload = client.json_request(
        "GET",
        "/api/v1/summary",
        token=read_token,
        headers={"X-DeltaAegis-Token": read_token},
    )
    check(response.status == 400 and payload["error"]["code"] == "ambiguous_credentials", "stable API accepted ambiguous credentials")

    duplicate_authorization = client.raw_request(
        "GET",
        "/api/v1/summary",
        headers=[
            ("Authorization", f"Bearer {read_token}"),
            ("Authorization", f"Bearer {read_token}"),
        ],
    )
    duplicate_payload = duplicate_authorization.json()
    api_v1.validate_envelope(duplicate_payload)
    check(
        duplicate_authorization.status == 400
        and duplicate_payload["error"]["code"] == "ambiguous_credentials",
        "stable API accepted duplicate Authorization headers",
    )


def validate_token_boundaries(client: HttpClient, tokens: dict[str, Any]) -> None:
    payload = {"name": "Denied Site"}
    cases = (
        (tokens["read"]["token"], 403),
        (tokens["demoted"]["token"], 403),
        (tokens["revoked"]["token"], 401),
        (tokens["malformed"]["token"], 403),
        (tokens["unbounded"], 403),
        (tokens["far_future"], 403),
        (tokens["expired"], 401),
        ("da_invalid_stage2_fixture", 401),
        ("legacy-dashboard-secret", 401),
    )
    for index, (token, expected_status) in enumerate(cases):
        response, document = client.json_request(
            "POST",
            "/api/v1/sites",
            token=token,
            idempotency_key=f"denied-token-{index:02d}",
            payload=payload,
        )
        check(response.status == expected_status and document["ok"] is False, f"token boundary returned {response.status}, expected {expected_status}")

    response, document = client.json_request(
        "GET",
        "/api/v1/sites",
        token=tokens["write_only"]["token"],
    )
    check(response.status == 403 and document["error"]["details"]["required_scope"] == "dashboard.read", "write-only token read data")


def validate_idempotency(client: HttpClient, database: Path, tokens: dict[str, Any]) -> None:
    token = tokens["write"]["token"]
    connection = deltaaegis.connect(database)
    try:
        connection.execute(
            "INSERT INTO api_idempotency_keys ("
            "idempotency_id, principal_key, method, route, idempotency_key, "
            "request_sha256, state, response_status, response_json, "
            "created_at, updated_at, expires_at"
            ") VALUES (?, ?, 'POST', '/api/v1/sites', ?, ?, 'FAILED', 400, ?, ?, ?, ?)",
            (
                "expired-stage2-fixture",
                "api_token_v1:expired-fixture",
                "expired-idempotency-fixture",
                "0" * 64,
                "{}",
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
                "2026-01-02T00:00:00Z",
            ),
        )
        connection.commit()
    finally:
        connection.close()
    payload = {"name": "Idempotent Site", "description": "exact replay", "network_scopes": ["10.90.0.0/24"]}
    response1, document1 = client.json_request(
        "POST", "/api/v1/sites", token=token, idempotency_key="site-create-exact-001", request_id="stage2.first-request", payload=payload
    )
    check(response1.status == 201 and document1["ok"] is True, "site creation failed")
    response2, document2 = client.json_request(
        "POST", "/api/v1/sites", token=token, idempotency_key="site-create-exact-001", request_id="stage2.second-request", payload=payload
    )
    check(response2.status == 201 and response2.value("Idempotency-Replayed") == "true", "exact mutation was not replayed")
    check(document2 == document1, "idempotency replay changed the original response")
    response, conflict = client.json_request(
        "POST", "/api/v1/sites", token=token, idempotency_key="site-create-exact-001", payload={"name": "Different Site"}
    )
    check(response.status == 409 and conflict["error"]["code"] == "idempotency_key_conflict", "idempotency key payload collision was accepted")

    failed_payload = {"name": ""}
    first, failed1 = client.json_request(
        "POST", "/api/v1/sites", token=token, idempotency_key="site-create-failed-001", payload=failed_payload
    )
    second, failed2 = client.json_request(
        "POST", "/api/v1/sites", token=token, idempotency_key="site-create-failed-001", payload=failed_payload
    )
    check(first.status == 400 and second.status == 400, "failed idempotent mutation status drift")
    check(second.value("Idempotency-Replayed") == "true" and failed1 == failed2, "failed mutation did not replay exactly")

    concurrent_payload = {"name": "Concurrent Site", "network_scopes": ["10.91.0.0/24"]}
    barrier = threading.Barrier(3)

    def concurrent_request() -> tuple[int, Any, str]:
        barrier.wait(timeout=10)
        response, document = client.json_request(
            "POST", "/api/v1/sites", token=token, idempotency_key="site-create-concurrent-001", payload=concurrent_payload
        )
        return response.status, document, response.value("Idempotency-Replayed")

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(concurrent_request) for _ in range(2)]
        barrier.wait(timeout=10)
        outcomes = [future.result(timeout=15) for future in futures]
    statuses = {item[0] for item in outcomes}
    check(statuses.issubset({201, 409}) and 201 in statuses, f"concurrent idempotency statuses are unsafe: {statuses}")
    retry, _document = client.json_request(
        "POST", "/api/v1/sites", token=token, idempotency_key="site-create-concurrent-001", payload=concurrent_payload
    )
    check(retry.status == 201 and retry.value("Idempotency-Replayed") == "true", "concurrent mutation did not converge to replay")

    connection = deltaaegis.connect(database)
    try:
        counts = dict(
            connection.execute(
                "SELECT name, COUNT(*) FROM logical_sites WHERE name IN (?, ?) GROUP BY name",
                ("Idempotent Site", "Concurrent Site"),
            ).fetchall()
        )
        check(counts == {"Concurrent Site": 1, "Idempotent Site": 1}, f"idempotency created duplicate domain rows: {counts}")
        states = dict(
            connection.execute(
                "SELECT idempotency_key, state FROM api_idempotency_keys WHERE idempotency_key LIKE 'site-create-%'"
            ).fetchall()
        )
        check(states["site-create-exact-001"] == "COMPLETED", "successful idempotency record did not complete")
        check(states["site-create-failed-001"] == "FAILED", "failed idempotency record did not finalize")
        expired_count = connection.execute(
            "SELECT COUNT(*) FROM api_idempotency_keys WHERE idempotency_id = ?",
            ("expired-stage2-fixture",),
        ).fetchone()[0]
        check(expired_count == 0, "expired idempotency record was not pruned")
    finally:
        connection.close()


def validate_request_parsing(client: HttpClient, tokens: dict[str, Any]) -> None:
    headers = bearer(tokens["write"]["token"])
    headers["Idempotency-Key"] = "request-parse-001"
    response, document = client.json_request(
        "POST",
        "/api/v1/sites",
        token=tokens["write"]["token"],
        idempotency_key="request-media-001",
        headers={"Content-Type": "text/application/json-evil"},
    )
    check(response.status == 415 and document["error"]["code"] == "unsupported_media_type", "invalid media type was accepted")

    for suffix, body, expected_code in (
        ("json", b'{"name":', "invalid_json"),
        ("utf8", b'\xff', "invalid_json_encoding"),
        ("type", b'[]', "invalid_json_type"),
    ):
        request_headers = bearer(tokens["write"]["token"])
        request_headers.update({"Content-Type": "application/json", "Idempotency-Key": f"request-{suffix}-001"})
        response = client.request("POST", "/api/v1/sites", headers=request_headers, body=body)
        document = response.json()
        api_v1.validate_envelope(document)
        check(response.status == 400 and document["error"]["code"] == expected_code, f"malformed {suffix} body was not rejected")

    oversized = json.dumps({"name": "x", "padding": "z" * 70000}).encode("utf-8")
    request_headers = bearer(tokens["write"]["token"])
    request_headers.update({"Content-Type": "application/json", "Idempotency-Key": "request-large-001"})
    response = client.request("POST", "/api/v1/sites", headers=request_headers, body=oversized)
    document = response.json()
    api_v1.validate_envelope(document)
    check(response.status == 413 and document["error"]["code"] == "request_too_large", "oversized body was accepted")

    token = tokens["write"]["token"]
    base_headers = [
        ("Authorization", f"Bearer {token}"),
        ("Content-Type", "application/json"),
        ("Idempotency-Key", "raw-boundary-001"),
    ]
    raw_cases = (
        ("missing-length", base_headers, "length_required", 411),
        (
            "duplicate-length",
            [*base_headers, ("Content-Length", "2"), ("Content-Length", "2")],
            "length_required",
            411,
        ),
        (
            "signed-length",
            [*base_headers, ("Content-Length", "+2")],
            "invalid_content_length",
            400,
        ),
        (
            "transfer-encoding",
            [*base_headers, ("Content-Length", "2"), ("Transfer-Encoding", "chunked")],
            "unsupported_transfer_encoding",
            400,
        ),
        (
            "duplicate-content-type",
            [
                *base_headers,
                ("Content-Type", "application/json"),
                ("Content-Length", "2"),
            ],
            "unsupported_media_type",
            415,
        ),
        (
            "duplicate-idempotency",
            [
                *base_headers,
                ("Idempotency-Key", "raw-boundary-002"),
                ("Content-Length", "2"),
            ],
            "invalid_idempotency_key",
            400,
        ),
    )
    for label, header_pairs, expected_code, expected_status in raw_cases:
        raw_response = client.raw_request(
            "POST",
            "/api/v1/sites",
            headers=list(header_pairs),
            body=b"{}",
        )
        raw_payload = raw_response.json()
        api_v1.validate_envelope(raw_payload)
        check(
            raw_response.status == expected_status
            and raw_payload["error"]["code"] == expected_code,
            f"{label} boundary returned an unexpected response",
        )

    duplicate_host = client.raw_request(
        "GET",
        "/api/v1/summary",
        headers=[
            ("Host", f"127.0.0.1:{client.port}"),
            ("Host", f"127.0.0.1:{client.port}"),
            ("Authorization", f"Bearer {tokens['read']['token']}"),
        ],
    )
    duplicate_host_payload = duplicate_host.json()
    api_v1.validate_envelope(duplicate_host_payload)
    check(
        duplicate_host.status == 400
        and duplicate_host_payload["error"]["code"] == "invalid_host",
        "duplicate Host headers were accepted",
    )

    unsupported_private = client.request("OPTIONS", "/not-a-route")
    check(
        unsupported_private.status == 501,
        "private unsupported-method error boundary drifted",
    )


def login(
    client: HttpClient,
    username: str,
    password: str,
    *,
    host_header: str | None = None,
    secure: bool = False,
) -> tuple[str, str, str]:
    body = urlencode({"username": username, "password": password})
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if host_header:
        headers["Host"] = host_header
    response = client.request(
        "POST",
        "/login",
        headers=headers,
        body=body,
    )
    check(response.status == 303 and response.value("Location") == "/", "dashboard login failed")
    return cookie_values(response, secure=secure)


def validate_cookie_security(client: HttpClient, database: Path, tokens: dict[str, Any]) -> None:
    cookie, csrf, session_token = login(client, "stage2-admin", "Stage2-Validation!2026")
    response, document = client.json_request("GET", "/api/v1/session", cookie=cookie)
    check(response.status == 200 and document["data"]["auth_type"] == "dashboard_session", "session did not authenticate stable API")
    check("_csrf_token_hash" not in document["data"], "session API exposed the CSRF hash")

    response, document = client.json_request(
        "GET",
        "/api/v1/session",
        cookie=cookie,
        token=tokens["read"]["token"],
    )
    check(
        response.status == 400
        and document["error"]["code"] == "ambiguous_credentials",
        "stable API accepted simultaneous cookie and bearer credentials",
    )

    response, document = client.json_request(
        "POST",
        "/api/v1/sites",
        cookie=cookie,
        token=tokens["write"]["token"],
        idempotency_key="mixed-credentials-001",
        payload={"name": "Mixed Credentials"},
    )
    check(
        response.status == 400
        and document["error"]["code"] == "ambiguous_credentials",
        "stable mutation evaluated CSRF before rejecting mixed credentials",
    )

    attempts = (
        ({"cookie": cookie}, "missing origin and token"),
        ({"cookie": cookie, "origin": client.origin}, "missing CSRF token"),
        ({"cookie": cookie, "origin": client.origin, "csrf": "dc_wrong"}, "mismatched CSRF token"),
        ({"cookie": cookie, "origin": "http://evil.example", "csrf": csrf}, "cross-origin request"),
        ({"cookie": cookie, "origin": f"https://{client.host}:{client.port}", "csrf": csrf}, "cross-scheme request"),
    )
    for index, (arguments, label) in enumerate(attempts):
        response, payload = client.json_request(
            "POST",
            "/api/v1/sites",
            idempotency_key=f"csrf-denied-{index:02d}",
            payload={"name": f"CSRF Denied {index}"},
            **arguments,
        )
        check(response.status == 403 and payload["error"]["code"] == "csrf_validation_failed", f"{label} was accepted")

    response, payload = client.json_request(
        "POST",
        "/api/v1/sites",
        cookie=cookie,
        csrf=csrf,
        origin=client.origin,
        idempotency_key="csrf-valid-create-001",
        payload={"name": "CSRF Valid Site"},
    )
    check(response.status == 201 and payload["ok"] is True, "valid same-origin CSRF mutation failed")

    response = client.request("GET", "/logout", headers={"Cookie": cookie})
    check(response.status == 405 and response.value("Allow") == "POST", "GET logout changed session state")

    connection = deltaaegis.connect(database)
    connection.execute("UPDATE access_users SET role = 'VIEWER' WHERE username = 'stage2-admin'")
    connection.commit()
    connection.close()
    response, payload = client.json_request(
        "POST",
        "/api/v1/sites",
        cookie=cookie,
        csrf=csrf,
        origin=client.origin,
        idempotency_key="csrf-demoted-001",
        payload={"name": "Demoted Session Site"},
    )
    check(response.status == 403 and payload["error"]["code"] == "forbidden", "role demotion did not immediately constrain the session")

    connection = deltaaegis.connect(database)
    connection.execute("UPDATE access_users SET role = 'ADMIN' WHERE username = 'stage2-admin'")
    connection.execute(
        "UPDATE access_sessions SET is_active = 0, ended_at = ?, end_reason = 'validator_revocation' "
        "WHERE session_token_hash = ?",
        (datetime.now(timezone.utc).isoformat(), auth.hash_dashboard_session_token(session_token)),
    )
    connection.commit()
    connection.close()
    response, payload = client.json_request("GET", "/api/v1/session", cookie=cookie)
    check(response.status == 401 and payload["error"]["code"] == "unauthorized", "revoked session remained active")
    cleared = response.values("Set-Cookie")
    check(len(cleared) == 2 and all("Max-Age=0" in value for value in cleared), "revoked session did not clear both cookies")

    cookie, csrf, _session_token = login(client, "stage2-admin", "Stage2-Validation!2026")
    response = client.request(
        "POST",
        "/logout",
        headers={"Cookie": cookie, "Origin": client.origin, "X-DeltaAegis-CSRF": csrf},
        body=b"",
    )
    check(response.status == 303 and response.value("Location") == "/login", "CSRF-protected logout failed")
    check(len(response.values("Set-Cookie")) == 2, "logout did not clear both cookies")

    previous = web._DASHBOARD_FORCE_SECURE_COOKIES
    try:
        web._DASHBOARD_FORCE_SECURE_COOKIES = True
        check("; Secure" in web.dashboard_session_cookie_header("fixture"), "HTTPS proxy session flag does not add Secure")
        check("; Secure" in web.dashboard_csrf_cookie_header("fixture"), "HTTPS proxy CSRF flag does not add Secure")
    finally:
        web._DASHBOARD_FORCE_SECURE_COOKIES = previous

    for value, secure in (
        (None, True),
        ("http://deltaaegis.example", True),
        ("https://deltaaegis.example", False),
        ("https://user@deltaaegis.example", True),
        ("https://deltaaegis.example/path", True),
    ):
        try:
            web._dashboard_public_origin_identity(
                value,
                secure_cookies=secure,
            )
        except ValueError:
            continue
        raise ValidationFailure(
            f"unsafe public-origin configuration was accepted: {value!r}, secure={secure}"
        )


def validate_host_boundary(client: HttpClient, tokens: dict[str, Any]) -> None:
    response, payload = client.json_request(
        "GET",
        "/api/v1/summary",
        token=tokens["read"]["token"],
        headers={"Host": "evil.example"},
    )
    check(response.status == 400 and payload["error"]["code"] == "invalid_host", "untrusted Host header was accepted")
    response, payload = client.json_request(
        "GET",
        "/api/v1/summary",
        token=tokens["read"]["token"],
        headers={"X-Forwarded-Host": "evil.example", "X-Forwarded-For": "203.0.113.10"},
    )
    check(response.status == 200 and payload["ok"] is True, "untrusted forwarding headers changed the direct bind identity")


def validate_lan_host_boundary(database: Path, root: Path, tokens: dict[str, Any]) -> None:
    port = unused_port()
    client = HttpClient("127.0.0.1", port)
    process = start_server(database, root, port, lan=True)
    try:
        wait_for_server(process, client)
        response, payload = client.json_request(
            "GET",
            "/api/v1/summary",
            token=tokens["read"]["token"],
        )
        check(response.status == 200 and payload["ok"] is True, "LAN wildcard bind rejected the actual local socket authority")
        response, payload = client.json_request(
            "GET",
            "/api/v1/summary",
            token=tokens["read"]["token"],
            headers={"Host": f"10.123.45.67:{port}"},
        )
        check(
            response.status == 400 and payload["error"]["code"] == "invalid_host",
            "LAN wildcard bind accepted an unrelated private Host authority",
        )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def validate_explicit_proxy_origin(
    database: Path,
    root: Path,
    tokens: dict[str, Any],
) -> None:
    port = unused_port()
    client = HttpClient("127.0.0.1", port)
    public_origin = "https://deltaaegis.example"
    public_authority = "deltaaegis.example"
    process = start_server(
        database,
        root,
        port,
        public_origin=public_origin,
        secure_cookies=True,
    )
    try:
        wait_for_server(process, client, host_header=public_authority)
        response, payload = client.json_request(
            "GET",
            "/api/v1/summary",
            token=tokens["read"]["token"],
            headers={"Host": public_authority},
        )
        check(
            response.status == 200 and payload["ok"] is True,
            "explicit proxy authority was rejected",
        )
        response, payload = client.json_request(
            "GET",
            "/api/v1/summary",
            token=tokens["read"]["token"],
            headers={
                "Host": f"127.0.0.1:{port}",
                "X-Forwarded-Host": public_authority,
            },
        )
        check(
            response.status == 400 and payload["error"]["code"] == "invalid_host",
            "forwarded Host bypassed the explicit proxy authority",
        )

        cookie, csrf, _session_token = login(
            client,
            "stage2-admin",
            "Stage2-Validation!2026",
            host_header=public_authority,
            secure=True,
        )
        response, payload = client.json_request(
            "POST",
            "/api/v1/sites",
            cookie=cookie,
            csrf=csrf,
            origin=public_origin,
            idempotency_key="proxy-origin-valid-001",
            payload={"name": "Explicit Proxy Site"},
            headers={"Host": public_authority},
        )
        check(
            response.status == 201 and payload["ok"] is True,
            "explicit HTTPS proxy origin failed CSRF validation",
        )
        response, payload = client.json_request(
            "POST",
            "/api/v1/sites",
            cookie=cookie,
            csrf=csrf,
            origin="http://deltaaegis.example",
            idempotency_key="proxy-origin-scheme-001",
            payload={"name": "Wrong Proxy Scheme"},
            headers={"Host": public_authority},
        )
        check(
            response.status == 403
            and payload["error"]["code"] == "csrf_validation_failed",
            "explicit proxy origin accepted a downgraded scheme",
        )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def validate_http(database: Path, root: Path, tokens: dict[str, Any]) -> None:
    port = unused_port()
    client = HttpClient("127.0.0.1", port)
    process = start_server(database, root, port)
    try:
        wait_for_server(process, client)
        response = client.request("GET", "/login")
        check(response.status == 200 and b"DeltaAegis Login" in response.body, "HTML login surface failed")
        validate_openapi_contract(client)
        validate_read_surface(client, tokens)
        validate_token_boundaries(client, tokens)
        validate_request_parsing(client, tokens)
        validate_idempotency(client, database, tokens)
        validate_cookie_security(client, database, tokens)
        validate_host_boundary(client, tokens)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    validate_lan_host_boundary(database, root, tokens)
    validate_explicit_proxy_origin(database, root, tokens)


def main() -> int:
    check(
        deltaaegis.DELTAAEGIS_VERSION
        in {"1.0.0-stage12", "1.0.0"},
        "runtime stage version is outside the approved v1 candidate sequence",
    )
    check(web.DASHBOARD_SECURITY_HEADERS == web.dashboard_security_headers(), "security header accessor drift")
    with tempfile.TemporaryDirectory(prefix="deltaaegis-v1-stage2-") as temporary:
        root = Path(temporary)
        database = root / "deltaaegis.db"
        tokens = seed_database(database)
        validate_http(database, root, tokens)
        connection = deltaaegis.connect(database)
        try:
            check(connection.execute("PRAGMA foreign_key_check").fetchall() == [], "Stage 2 HTTP tests left foreign-key violations")
            check(connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "Stage 2 HTTP tests damaged the database")
        finally:
            connection.close()

    print(
        "[PASS] v1 Stage 2: OpenAPI 3.1, stable envelopes and pagination, "
        "bounded scoped tokens, revocation, CSRF, host/origin controls, "
        "security headers, body limits, and concurrent idempotent HTTP mutations"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValidationFailure as exc:
        print(f"[FAIL] v1 Stage 2: {exc}", file=sys.stderr)
        raise SystemExit(1)
