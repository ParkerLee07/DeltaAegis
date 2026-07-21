"""Stable DeltaAegis ``/api/v1`` contract primitives.

This module owns the public envelope, endpoint inventory, OpenAPI document,
pagination contract, and durable idempotency records.  HTTP transport remains
in :mod:`deltaaegis_core.web`; domain operations remain in their existing
owners and are called directly by that transport.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence


API_VERSION = "v1"
OPENAPI_VERSION = "3.1.0"
IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60
IDEMPOTENCY_KEY_PATTERN = re.compile(r"[A-Za-z0-9._:-]{8,128}")
REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9._:-]{8,128}")


class ApiV1Error(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: int = 400,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = str(code)
        self.status = int(status)
        self.details = dict(details or {})


@dataclass(frozen=True)
class ApiV1Endpoint:
    method: str
    template: str
    operation_id: str
    permission: str | None
    summary: str
    paginated: bool = False
    idempotent: bool = False


API_V1_ENDPOINTS = (
    ApiV1Endpoint("GET", "/api/v1", "getApiIndex", None, "Discover the stable API."),
    ApiV1Endpoint("GET", "/api/v1/openapi.json", "getOpenApi", None, "Read the OpenAPI contract."),
    ApiV1Endpoint("GET", "/api/v1/session", "getSession", "session.read", "Read the authenticated principal."),
    ApiV1Endpoint("GET", "/api/v1/summary", "getSummary", "dashboard.read", "Read the current DeltaAegis summary."),
    ApiV1Endpoint("GET", "/api/v1/scopes", "listScopes", "dashboard.read", "List observed network scopes.", paginated=True),
    ApiV1Endpoint("GET", "/api/v1/sites", "listSites", "dashboard.read", "List logical sites.", paginated=True),
    ApiV1Endpoint("POST", "/api/v1/sites", "createSite", "sites.write", "Create a logical site.", idempotent=True),
    ApiV1Endpoint("GET", "/api/v1/assets", "listAssets", "dashboard.read", "List assets.", paginated=True),
    ApiV1Endpoint("GET", "/api/v1/assets/{asset_key}", "getAsset", "dashboard.read", "Read one asset."),
    ApiV1Endpoint("GET", "/api/v1/events", "listEvents", "dashboard.read", "List delta events.", paginated=True),
    ApiV1Endpoint("GET", "/api/v1/alerts", "listAlerts", "dashboard.read", "List alerts.", paginated=True),
    ApiV1Endpoint("GET", "/api/v1/scan-jobs", "listScanJobs", "dashboard.read", "List scan jobs.", paginated=True),
    ApiV1Endpoint("GET", "/api/v1/validations", "listValidations", "dashboard.read", "List validation evidence.", paginated=True),
    ApiV1Endpoint("GET", "/api/v1/telemetry-quality/decisions", "listTelemetryQualityDecisions", "dashboard.read", "List telemetry-quality decisions.", paginated=True),
    ApiV1Endpoint("GET", "/api/v1/telemetry-quality/decisions/{decision_id}", "getTelemetryQualityDecision", "dashboard.read", "Read one telemetry-quality decision."),
)


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def request_id(value: str | None = None) -> str:
    supplied = str(value or "").strip()
    if supplied and REQUEST_ID_PATTERN.fullmatch(supplied):
        return supplied
    return "req_" + uuid.uuid4().hex


def success_envelope(
    data: Any,
    *,
    request_id_value: str,
    meta: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    response_meta = {"request_id": request_id_value}
    response_meta.update(dict(meta or {}))
    return {
        "api_version": API_VERSION,
        "ok": True,
        "data": data,
        "meta": response_meta,
    }


def error_envelope(
    code: str,
    message: str,
    *,
    request_id_value: str,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "api_version": API_VERSION,
        "ok": False,
        "error": {
            "code": str(code),
            "message": str(message),
            "details": dict(details or {}),
        },
        "meta": {"request_id": request_id_value},
    }


def validate_envelope(payload: Mapping[str, Any]) -> None:
    if payload.get("api_version") != API_VERSION:
        raise ApiV1Error("invalid_envelope", "API envelope version is missing or invalid", status=500)
    if not isinstance(payload.get("ok"), bool):
        raise ApiV1Error("invalid_envelope", "API envelope ok flag is missing", status=500)
    meta = payload.get("meta")
    if not isinstance(meta, dict) or not str(meta.get("request_id") or ""):
        raise ApiV1Error("invalid_envelope", "API envelope request ID is missing", status=500)
    if payload["ok"] is True:
        if "data" not in payload or "error" in payload:
            raise ApiV1Error("invalid_envelope", "success envelope is malformed", status=500)
    else:
        error = payload.get("error")
        if not isinstance(error, dict) or not str(error.get("code") or "") or not str(error.get("message") or ""):
            raise ApiV1Error("invalid_envelope", "error envelope is malformed", status=500)
        if "data" in payload:
            raise ApiV1Error("invalid_envelope", "error envelope contains success data", status=500)


def parse_pagination(
    query: Mapping[str, Sequence[str]],
    *,
    default_limit: int = 50,
    maximum_limit: int = 200,
) -> tuple[int, int]:
    try:
        limit = int((query.get("limit") or [str(default_limit)])[0])
        offset = int((query.get("offset") or ["0"])[0])
    except (TypeError, ValueError) as exc:
        raise ApiV1Error(
            "invalid_pagination",
            "limit and offset must be integers",
            status=400,
        ) from exc
    if limit < 1 or limit > maximum_limit:
        raise ApiV1Error(
            "invalid_pagination",
            f"limit must be between 1 and {maximum_limit}",
            status=400,
        )
    if offset < 0 or offset > 10_000_000:
        raise ApiV1Error(
            "invalid_pagination",
            "offset must be between 0 and 10000000",
            status=400,
        )
    return limit, offset


def paginated_envelope(
    items: Sequence[Any],
    *,
    limit: int,
    offset: int,
    request_id_value: str,
) -> dict[str, Any]:
    materialized = list(items)
    has_more = len(materialized) > limit
    page = materialized[:limit]
    return success_envelope(
        {"items": page},
        request_id_value=request_id_value,
        meta={
            "pagination": {
                "limit": limit,
                "offset": offset,
                "count": len(page),
                "has_more": has_more,
                "next_offset": offset + limit if has_more else None,
            }
        },
    )


def api_index() -> dict[str, Any]:
    return {
        "name": "DeltaAegis API",
        "version": API_VERSION,
        "openapi": "/api/v1/openapi.json",
        "authentication": {
            "api_tokens": "Authorization: Bearer <token>",
            "browser_sessions": "cookie plus X-DeltaAegis-CSRF for mutations",
        },
        "private_compatibility_namespace": "/api/* (unversioned, not stable)",
    }


def _response_schema(success: bool = True) -> dict[str, Any]:
    component = "SuccessEnvelope" if success else "ErrorEnvelope"
    return {"$ref": f"#/components/responses/{component}"}


def _response_component(success: bool = True) -> dict[str, Any]:
    name = "SuccessEnvelope" if success else "ErrorEnvelope"
    return {
        "description": "Successful response" if success else "Error response",
        "headers": {
            "X-Request-ID": {
                "description": "Request correlation identifier.",
                "schema": {"type": "string"},
            }
        },
        "content": {
            "application/json": {
                "schema": {"$ref": f"#/components/schemas/{name}"}
            }
        },
    }


def _operation_data_schema(endpoint: ApiV1Endpoint) -> dict[str, Any]:
    page_items = {
        "listScopes": "ScopeRecord",
        "listSites": "LogicalSite",
        "listAssets": "AssetRecord",
        "listEvents": "EventRecord",
        "listAlerts": "AlertRecord",
        "listScanJobs": "ScanJobRecord",
        "listValidations": "ValidationRecord",
        "listTelemetryQualityDecisions": "TelemetryQualityDecision",
    }
    if endpoint.paginated:
        item_name = page_items[endpoint.operation_id]
        return {
            "type": "object",
            "required": ["items"],
            "properties": {
                "items": {
                    "type": "array",
                    "items": {"$ref": f"#/components/schemas/{item_name}"},
                }
            },
            "additionalProperties": False,
        }
    component_names = {
        "getApiIndex": "ApiIndex",
        "getSession": "SessionPrincipal",
        "getSummary": "Summary",
        "createSite": "SiteMutationResult",
        "getAsset": "AssetDetail",
        "getTelemetryQualityDecision": "TelemetryQualityDecision",
    }
    component = component_names.get(endpoint.operation_id)
    return (
        {"$ref": f"#/components/schemas/{component}"}
        if component
        else {}
    )


def _operation_success_response(endpoint: ApiV1Endpoint) -> dict[str, Any]:
    response = _response_component(True)
    response["description"] = endpoint.summary
    response["content"]["application/json"]["schema"] = {
        "allOf": [
            {"$ref": "#/components/schemas/SuccessEnvelope"},
            {
                "type": "object",
                "properties": {
                    "data": _operation_data_schema(endpoint),
                },
            },
        ]
    }
    if endpoint.idempotent:
        response["headers"]["Idempotency-Replayed"] = {
            "description": (
                "True when the stored result of an identical request is replayed."
            ),
            "schema": {"type": "string", "enum": ["true"]},
        }
    return response


def openapi_document() -> dict[str, Any]:
    paths: dict[str, Any] = {}
    for endpoint in API_V1_ENDPOINTS:
        success_status = "200" if endpoint.method == "GET" else "201"
        operation: dict[str, Any] = {
            "operationId": endpoint.operation_id,
            "summary": endpoint.summary,
            "responses": {
                success_status: _operation_success_response(endpoint),
                "400": _response_schema(False),
                "401": _response_schema(False),
                "403": _response_schema(False),
                "404": _response_schema(False),
                "409": _response_schema(False),
                "405": _response_schema(False),
                "411": _response_schema(False),
                "413": _response_schema(False),
                "415": _response_schema(False),
                "429": _response_schema(False),
                "500": _response_schema(False),
            },
            "x-deltaaegis-permission": endpoint.permission or "public",
        }
        if endpoint.operation_id == "getOpenApi":
            operation["responses"]["200"] = {
                "description": "OpenAPI 3.1 document",
                "headers": {
                    "X-Request-ID": {
                        "description": "Request correlation identifier.",
                        "schema": {"type": "string"},
                    }
                },
                "content": {
                    "application/json": {
                        "schema": {"type": "object", "required": ["openapi", "info", "paths"]}
                    }
                },
            }
        if endpoint.permission:
            operation["security"] = [{"bearerAuth": []}]
            operation["security"].append(
                {"sessionCookie": [], "csrfCookie": []}
                if endpoint.idempotent
                else {"sessionCookie": []}
            )
        else:
            operation["security"] = []
        parameters: list[dict[str, Any]] = [
            {
                "name": "X-Request-ID",
                "in": "header",
                "required": False,
                "schema": {
                    "type": "string",
                    "minLength": 8,
                    "maxLength": 128,
                    "pattern": r"^[A-Za-z0-9._:-]+$",
                },
            }
        ]
        for name in re.findall(r"{([a-z_]+)}", endpoint.template):
            parameters.append(
                {
                    "name": name,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string", "minLength": 1, "maxLength": 256},
                }
            )
        if endpoint.paginated:
            parameters.extend(
                [
                    {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50}},
                    {"name": "offset", "in": "query", "schema": {"type": "integer", "minimum": 0, "default": 0}},
                ]
            )
        if endpoint.operation_id in {
            "getSummary",
            "listAssets",
            "listEvents",
            "listAlerts",
            "listTelemetryQualityDecisions",
        }:
            parameters.append(
                {
                    "name": "scope",
                    "in": "query",
                    "required": False,
                    "schema": {"type": "string", "format": "ipv4-network"},
                }
            )
        if endpoint.operation_id == "listAssets":
            parameters.extend(
                [
                    {"name": "state", "in": "query", "required": False, "schema": {"type": "string"}},
                    {"name": "identity", "in": "query", "required": False, "schema": {"type": "string"}},
                ]
            )
        if endpoint.operation_id == "listTelemetryQualityDecisions":
            parameters.append(
                {"name": "state", "in": "query", "required": False, "schema": {"type": "string"}}
            )
        if endpoint.idempotent:
            parameters.append(
                {
                    "name": "Idempotency-Key",
                    "in": "header",
                    "required": True,
                    "schema": {"type": "string", "minLength": 8, "maxLength": 128},
                }
            )
            parameters.append(
                {
                    "name": "X-DeltaAegis-CSRF",
                    "in": "header",
                    "required": False,
                    "description": "Required with cookie authentication and must match the csrfCookie value.",
                    "schema": {"type": "string"},
                }
            )
            operation["requestBody"] = {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/SiteCreateRequest"}
                    }
                },
            }
        if parameters:
            operation["parameters"] = parameters
        paths.setdefault(endpoint.template, {})[endpoint.method.lower()] = operation

    return {
        "openapi": OPENAPI_VERSION,
        "jsonSchemaDialect": "https://json-schema.org/draft/2020-12/schema",
        "info": {
            "title": "DeltaAegis API",
            "version": "1.0.0-stage2",
            "description": "Stable, authenticated DeltaAegis programmatic API. Unversioned /api routes are private dashboard interfaces.",
        },
        # Paths already include the stable ``/api/v1`` prefix.  A root server
        # URL keeps OpenAPI clients from composing ``/api/v1/api/v1/...``.
        "servers": [{"url": "/"}],
        "paths": paths,
        "components": {
            "responses": {
                "SuccessEnvelope": _response_component(True),
                "ErrorEnvelope": _response_component(False),
                "IdempotentSuccessEnvelope": {
                    **_response_component(True),
                    "headers": {
                        **_response_component(True)["headers"],
                        "Idempotency-Replayed": {
                            "description": "True when the stored result of an identical request is replayed.",
                            "schema": {"type": "string", "enum": ["true"]},
                        },
                    },
                },
            },
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "DeltaAegis API token"},
                "sessionCookie": {"type": "apiKey", "in": "cookie", "name": "deltaaegis_session"},
                "csrfCookie": {"type": "apiKey", "in": "cookie", "name": "deltaaegis_csrf"},
            },
            "schemas": {
                "StableRecord": {
                    "type": "object",
                    "additionalProperties": True,
                },
                "ApiIndex": {
                    "type": "object",
                    "required": [
                        "name",
                        "version",
                        "openapi",
                        "authentication",
                        "private_compatibility_namespace",
                    ],
                    "properties": {
                        "name": {"type": "string"},
                        "version": {"const": API_VERSION},
                        "openapi": {"const": "/api/v1/openapi.json"},
                        "authentication": {"type": "object"},
                        "private_compatibility_namespace": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
                "SessionPrincipal": {
                    "type": "object",
                    "required": ["auth_type", "role"],
                    "properties": {
                        "auth_type": {
                            "type": "string",
                            "enum": ["api_token_v1", "dashboard_session"],
                        },
                        "role": {
                            "type": "string",
                            "enum": ["ADMIN", "ANALYST", "VIEWER"],
                        },
                        "username": {"type": ["string", "null"]},
                        "user_id": {"type": ["string", "null"]},
                        "token_id": {"type": ["string", "null"]},
                        "session_id": {"type": ["string", "null"]},
                        "expires_at": {"type": ["string", "null"], "format": "date-time"},
                        "scopes": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                    "additionalProperties": True,
                },
                "Summary": {
                    "type": "object",
                    "required": [
                        "selected_scope",
                        "snapshots",
                        "events",
                        "alerts",
                        "open_alerts",
                        "telemetry_quality",
                        "telemetry_projection",
                    ],
                    "properties": {
                        "selected_scope": {"type": ["string", "null"]},
                        "snapshots": {"type": "integer", "minimum": 0},
                        "events": {"type": "integer", "minimum": 0},
                        "alerts": {"type": "integer", "minimum": 0},
                        "open_alerts": {"type": "integer", "minimum": 0},
                        "telemetry_quality": {"type": "object"},
                        "telemetry_projection": {"type": "object"},
                    },
                    "additionalProperties": True,
                },
                "ScopeRecord": {
                    "allOf": [{"$ref": "#/components/schemas/StableRecord"}],
                },
                "LogicalSite": {
                    "type": "object",
                    "required": ["site_id", "name", "status", "member_count"],
                    "properties": {
                        "site_id": {"type": "string"},
                        "name": {"type": "string"},
                        "description": {"type": "string"},
                        "status": {"type": "string", "enum": ["ACTIVE", "ARCHIVED"]},
                        "member_count": {"type": "integer", "minimum": 0},
                    },
                    "additionalProperties": True,
                },
                "AssetRecord": {
                    "allOf": [{"$ref": "#/components/schemas/StableRecord"}],
                },
                "AssetDetail": {
                    "allOf": [{"$ref": "#/components/schemas/StableRecord"}],
                },
                "EventRecord": {
                    "allOf": [{"$ref": "#/components/schemas/StableRecord"}],
                },
                "AlertRecord": {
                    "allOf": [{"$ref": "#/components/schemas/StableRecord"}],
                },
                "ScanJobRecord": {
                    "allOf": [{"$ref": "#/components/schemas/StableRecord"}],
                },
                "ValidationRecord": {
                    "allOf": [{"$ref": "#/components/schemas/StableRecord"}],
                },
                "TelemetryQualityDecision": {
                    "type": "object",
                    "required": ["decision_id"],
                    "properties": {
                        "decision_id": {"type": "string"},
                        "current_state": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
                "SiteMutationResult": {
                    "type": "object",
                    "required": [
                        "ok",
                        "action",
                        "changed",
                        "site",
                        "memberships",
                        "receipt",
                    ],
                    "properties": {
                        "ok": {"const": True},
                        "action": {"const": "logical_site.create"},
                        "changed": {"type": "boolean"},
                        "site": {"$ref": "#/components/schemas/LogicalSite"},
                        "membership": {"type": ["object", "null"]},
                        "memberships": {
                            "type": "array",
                            "items": {"type": "object"},
                        },
                        "receipt": {"type": "object"},
                    },
                    "additionalProperties": False,
                },
                "ResponseMeta": {
                    "type": "object",
                    "required": ["request_id"],
                    "properties": {
                        "request_id": {"type": "string"},
                        "pagination": {"$ref": "#/components/schemas/Pagination"},
                    },
                    "additionalProperties": True,
                },
                "Pagination": {
                    "type": "object",
                    "required": ["limit", "offset", "count", "has_more", "next_offset"],
                    "properties": {
                        "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                        "offset": {"type": "integer", "minimum": 0},
                        "count": {"type": "integer", "minimum": 0},
                        "has_more": {"type": "boolean"},
                        "next_offset": {"type": ["integer", "null"], "minimum": 0},
                    },
                    "additionalProperties": False,
                },
                "SuccessEnvelope": {
                    "type": "object",
                    "required": ["api_version", "ok", "data", "meta"],
                    "properties": {
                        "api_version": {"const": API_VERSION},
                        "ok": {"const": True},
                        "data": {},
                        "meta": {"$ref": "#/components/schemas/ResponseMeta"},
                    },
                    "additionalProperties": False,
                },
                "ErrorObject": {
                    "type": "object",
                    "required": ["code", "message", "details"],
                    "properties": {
                        "code": {"type": "string"},
                        "message": {"type": "string"},
                        "details": {"type": "object"},
                    },
                    "additionalProperties": False,
                },
                "ErrorEnvelope": {
                    "type": "object",
                    "required": ["api_version", "ok", "error", "meta"],
                    "properties": {
                        "api_version": {"const": API_VERSION},
                        "ok": {"const": False},
                        "error": {"$ref": "#/components/schemas/ErrorObject"},
                        "meta": {"$ref": "#/components/schemas/ResponseMeta"},
                    },
                    "additionalProperties": False,
                },
                "SiteCreateRequest": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": {"type": "string", "minLength": 1, "maxLength": 120},
                        "description": {"type": "string", "maxLength": 2000},
                        "network_scopes": {
                            "type": "array",
                            "maxItems": 256,
                            "items": {"type": "string", "format": "ipv4-network"},
                        },
                    },
                    "additionalProperties": False,
                },
            },
        },
    }


def validate_openapi_document(document: Mapping[str, Any] | None = None) -> None:
    payload = dict(document or openapi_document())
    if payload.get("openapi") != OPENAPI_VERSION:
        raise ApiV1Error("invalid_openapi", "OpenAPI version must be 3.1.0", status=500)
    paths = payload.get("paths")
    if not isinstance(paths, dict):
        raise ApiV1Error("invalid_openapi", "OpenAPI paths are missing", status=500)
    expected_operations = {
        (endpoint.template, endpoint.method.lower()): endpoint
        for endpoint in API_V1_ENDPOINTS
    }
    actual_operations = {
        (path, method)
        for path, path_item in paths.items()
        if isinstance(path_item, dict)
        for method, operation in path_item.items()
        if method.lower() in {"get", "post", "put", "patch", "delete", "options", "head"}
        and isinstance(operation, dict)
    }
    if actual_operations != set(expected_operations):
        raise ApiV1Error(
            "invalid_openapi",
            "OpenAPI operation inventory differs from the stable endpoint inventory",
            status=500,
        )
    for endpoint in API_V1_ENDPOINTS:
        operation = (paths.get(endpoint.template) or {}).get(endpoint.method.lower())
        if not isinstance(operation, dict):
            raise ApiV1Error("invalid_openapi", f"OpenAPI operation is missing: {endpoint.operation_id}", status=500)
        if operation.get("operationId") != endpoint.operation_id:
            raise ApiV1Error("invalid_openapi", f"OpenAPI operation ID drift: {endpoint.operation_id}", status=500)
        if operation.get("x-deltaaegis-permission") != (endpoint.permission or "public"):
            raise ApiV1Error("invalid_openapi", f"OpenAPI permission drift: {endpoint.operation_id}", status=500)
        security = operation.get("security")
        if endpoint.permission and not isinstance(security, list):
            raise ApiV1Error("invalid_openapi", f"OpenAPI security is missing: {endpoint.operation_id}", status=500)
        for requirement in security or []:
            if not isinstance(requirement, dict):
                raise ApiV1Error("invalid_openapi", f"OpenAPI security is malformed: {endpoint.operation_id}", status=500)
            for scopes in requirement.values():
                if scopes != []:
                    raise ApiV1Error("invalid_openapi", f"non-OAuth security scopes must be empty: {endpoint.operation_id}", status=500)
        if endpoint.idempotent and not any(
            parameter.get("name") == "Idempotency-Key" and parameter.get("required") is True
            for parameter in operation.get("parameters", [])
        ):
            raise ApiV1Error("invalid_openapi", f"idempotency header is missing: {endpoint.operation_id}", status=500)
        success_status = "200" if endpoint.method == "GET" else "201"
        success_response = (operation.get("responses") or {}).get(success_status)
        if not isinstance(success_response, dict):
            raise ApiV1Error("invalid_openapi", f"success response is missing: {endpoint.operation_id}", status=500)
        if endpoint.operation_id != "getOpenApi":
            success_schema = (
                ((success_response.get("content") or {}).get("application/json") or {}).get("schema")
            )
            all_of = success_schema.get("allOf") if isinstance(success_schema, dict) else None
            if not isinstance(all_of, list) or len(all_of) != 2:
                raise ApiV1Error("invalid_openapi", f"operation data schema is missing: {endpoint.operation_id}", status=500)
            specialization = all_of[1] if isinstance(all_of[1], dict) else {}
            data_schema = (specialization.get("properties") or {}).get("data")
            if not isinstance(data_schema, dict) or not data_schema:
                raise ApiV1Error("invalid_openapi", f"operation data schema is empty: {endpoint.operation_id}", status=500)

    operation_ids = [
        endpoint.operation_id for endpoint in API_V1_ENDPOINTS
    ]
    if len(operation_ids) != len(set(operation_ids)):
        raise ApiV1Error(
            "invalid_openapi",
            "OpenAPI operation IDs must be unique",
            status=500,
        )

    def resolve_reference(reference: str) -> Any:
        if not reference.startswith("#/"):
            raise ApiV1Error(
                "invalid_openapi",
                f"OpenAPI reference is not local: {reference}",
                status=500,
            )
        current: Any = payload
        for raw_part in reference[2:].split("/"):
            part = raw_part.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, dict) or part not in current:
                raise ApiV1Error(
                    "invalid_openapi",
                    f"OpenAPI reference does not resolve: {reference}",
                    status=500,
                )
            current = current[part]
        return current

    def validate_references(value: Any) -> None:
        if isinstance(value, dict):
            reference = value.get("$ref")
            if reference is not None:
                resolve_reference(str(reference))
            for child in value.values():
                validate_references(child)
        elif isinstance(value, list):
            for child in value:
                validate_references(child)

    validate_references(payload)


def canonical_request_sha256(method: str, route: str, payload: Any) -> str:
    encoded = json.dumps(
        {
            "method": str(method).upper(),
            "route": str(route),
            "payload": payload,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def principal_key(actor: Mapping[str, Any]) -> str:
    auth_type = str(actor.get("auth_type") or "")
    identity = actor.get("token_id") or actor.get("session_id") or actor.get("user_id")
    if auth_type not in {"api_token_v1", "dashboard_session"} or not identity:
        raise ApiV1Error(
            "unsupported_principal",
            "stable API mutations require a scoped API token or dashboard session",
            status=403,
        )
    return f"{auth_type}:{identity}"


def normalize_idempotency_key(value: str | None) -> str:
    key = str(value or "").strip()
    if IDEMPOTENCY_KEY_PATTERN.fullmatch(key) is None:
        raise ApiV1Error(
            "invalid_idempotency_key",
            "Idempotency-Key must be 8-128 characters using letters, numbers, dot, underscore, colon, or dash",
            status=400,
        )
    return key


def reserve_idempotency_key(
    connection: sqlite3.Connection,
    *,
    actor: Mapping[str, Any],
    method: str,
    route: str,
    key: str | None,
    payload: Any,
) -> dict[str, Any]:
    normalized_key = normalize_idempotency_key(key)
    owner = principal_key(actor)
    method_value = str(method).upper()
    route_value = str(route)
    request_hash = canonical_request_sha256(method_value, route_value, payload)
    now = utc_now()
    expires = (
        datetime.now(timezone.utc) + timedelta(seconds=IDEMPOTENCY_TTL_SECONDS)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    connection.execute("BEGIN IMMEDIATE")
    try:
        # Keep the durable replay window bounded even when clients never
        # reuse old keys. Production records use canonical UTC ``Z`` values,
        # so the indexed text comparison is chronological.
        connection.execute(
            "DELETE FROM api_idempotency_keys WHERE expires_at <= ?",
            (now,),
        )
        row = connection.execute(
            "SELECT idempotency_id, request_sha256, state, response_status, "
            "response_json, expires_at FROM api_idempotency_keys "
            "WHERE principal_key = ? AND method = ? AND route = ? "
            "AND idempotency_key = ?",
            (owner, method_value, route_value, normalized_key),
        ).fetchone()
        if row:
            try:
                expiry = datetime.fromisoformat(
                    str(row["expires_at"]).replace("Z", "+00:00")
                )
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                expiry = datetime.min.replace(tzinfo=timezone.utc)
            if expiry <= datetime.now(timezone.utc):
                connection.execute(
                    "DELETE FROM api_idempotency_keys WHERE idempotency_id = ?",
                    (row["idempotency_id"],),
                )
                row = None
        if row:
            if str(row["request_sha256"]) != request_hash:
                raise ApiV1Error(
                    "idempotency_key_conflict",
                    "Idempotency-Key was already used with a different request",
                    status=409,
                )
            if str(row["state"]) in {"COMPLETED", "FAILED"} and row["response_json"]:
                try:
                    replay_payload = json.loads(str(row["response_json"]))
                except json.JSONDecodeError as exc:
                    raise ApiV1Error(
                        "idempotency_record_corrupt",
                        "Stored idempotency response is invalid",
                        status=500,
                    ) from exc
                connection.commit()
                return {
                    "replay": True,
                    "idempotency_id": row["idempotency_id"],
                    "status": int(row["response_status"] or 500),
                    "payload": replay_payload,
                }
            raise ApiV1Error(
                "idempotency_request_in_progress",
                "An identical mutation is already in progress",
                status=409,
                details={"idempotency_id": row["idempotency_id"]},
            )

        identifier = str(uuid.uuid4())
        connection.execute(
            "INSERT INTO api_idempotency_keys ("
            "idempotency_id, principal_key, method, route, idempotency_key, "
            "request_sha256, state, created_at, updated_at, expires_at"
            ") VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?)",
            (
                identifier,
                owner,
                method_value,
                route_value,
                normalized_key,
                request_hash,
                now,
                now,
                expires,
            ),
        )
        connection.commit()
        return {"replay": False, "idempotency_id": identifier}
    except Exception:
        connection.rollback()
        raise


def complete_idempotency_key(
    connection: sqlite3.Connection,
    *,
    idempotency_id: str,
    status: int,
    payload: Mapping[str, Any],
) -> None:
    state = "COMPLETED" if 200 <= int(status) < 400 else "FAILED"
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    owns_transaction = not connection.in_transaction
    if owns_transaction:
        connection.execute("BEGIN IMMEDIATE")
    try:
        cursor = connection.execute(
            "UPDATE api_idempotency_keys SET state = ?, response_status = ?, "
            "response_json = ?, updated_at = ? "
            "WHERE idempotency_id = ? AND state = 'PENDING'",
            (state, int(status), encoded, utc_now(), str(idempotency_id)),
        )
        if int(cursor.rowcount or 0) != 1:
            raise ApiV1Error(
                "idempotency_transition_failed",
                "Idempotency record is not pending",
                status=500,
            )
        if owns_transaction:
            connection.commit()
    except Exception:
        if owns_transaction:
            connection.rollback()
        raise


__all__ = (
    "API_VERSION",
    "API_V1_ENDPOINTS",
    "ApiV1Endpoint",
    "ApiV1Error",
    "api_index",
    "canonical_request_sha256",
    "complete_idempotency_key",
    "error_envelope",
    "openapi_document",
    "paginated_envelope",
    "parse_pagination",
    "principal_key",
    "request_id",
    "reserve_idempotency_key",
    "success_envelope",
    "validate_envelope",
    "validate_openapi_document",
)
