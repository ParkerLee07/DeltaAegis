#!/usr/bin/env python3
"""Validate v0.45 authenticated review and override boundaries."""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUTH = ROOT / "deltaaegis_core" / "auth.py"
ROOT_SOURCE = ROOT / "deltaaegis.py"
QUALITY = ROOT / "deltaaegis_core" / "telemetry_quality.py"
WEB = ROOT / "deltaaegis_core" / "web.py"


def require(condition, message):
    if not condition:
        raise SystemExit(f"[FAIL] {message}")


def function_calls(node):
    calls = []
    for item in ast.walk(node):
        if not isinstance(item, ast.Call):
            continue
        if isinstance(item.func, ast.Name):
            calls.append(item.func.id)
        elif isinstance(item.func, ast.Attribute):
            calls.append(item.func.attr)
    return calls


def active_function(tree, name):
    matches = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    require(matches, f"missing function: {name}")
    return matches[-1]


def load_quality_module():
    spec = importlib.util.spec_from_file_location(
        "deltaaegis_v045_quality_review_validator",
        QUALITY,
    )
    require(spec is not None and spec.loader is not None, "could not load quality runtime")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    auth_source = AUTH.read_text(encoding="utf-8")
    root_source = ROOT_SOURCE.read_text(encoding="utf-8")
    quality_source = QUALITY.read_text(encoding="utf-8")
    web_source = WEB.read_text(encoding="utf-8")

    auth_tree = ast.parse(auth_source)
    root_tree = ast.parse(root_source)
    ast.parse(quality_source)
    ast.parse(web_source)

    for marker in (
        '"telemetry.quality.review": "ANALYST"',
        '"telemetry.quality.override": "ADMIN"',
        '("GET", "/operator/telemetry-quality", "operator.session.read")',
        '("GET", "/api/telemetry-quality", "dashboard.read")',
        '("GET", "/api/telemetry-quality/detail", "dashboard.read")',
        '("POST", "/api/telemetry-quality/review", "telemetry.quality.review")',
        '("POST", "/api/telemetry-quality/override", "telemetry.quality.override")',
    ):
        require(marker in auth_source, f"missing RBAC marker: {marker}")

    require(
        'auth_type != "dashboard_session"' in root_source,
        "root review boundary does not require a dashboard-session actor",
    )
    require(
        'auth_type != "dashboard_session"' in quality_source,
        "quality runtime does not require a dashboard-session actor",
    )
    require(
        "telemetry-quality actor identity is session-derived" in root_source,
        "caller-supplied actor fields are not rejected",
    )

    for name in (
        "dashboard_telemetry_quality_review_payload",
        "dashboard_telemetry_quality_override_payload",
    ):
        node = active_function(root_tree, name)
        calls = function_calls(node)
        require(
            calls.count("_dashboard_v045_require_session_actor") == 1,
            f"{name} must enforce the session actor exactly once",
        )
        require(
            calls.count("_dashboard_v045_reject_actor_fields") == 1,
            f"{name} must reject caller-supplied actor fields exactly once",
        )

    module = load_quality_module()
    for actor in (
        None,
        {},
        {"auth_type": "api_token", "username": "token", "role": "ADMIN"},
    ):
        try:
            module._actor_fields(actor)
        except module.TelemetryQualityError:
            pass
        else:
            raise SystemExit(
                "[FAIL] non-dashboard actor passed the quality runtime boundary"
            )

    accepted = module._actor_fields(
        {
            "auth_type": "dashboard_session",
            "user_id": "user-1",
            "username": "analyst",
            "role": "ANALYST",
        }
    )
    require(
        accepted[1:] == ("analyst", "ANALYST", "dashboard_session"),
        "valid dashboard-session actor was not preserved",
    )

    require(
        "REJECTED telemetry is non-overridable" in quality_source,
        "REJECTED non-override rule is missing",
    )
    require(
        'route == "/operator/telemetry-quality"' in web_source,
        "protected quality center page route is missing",
    )
    require(
        'route in {\n                "/api/telemetry-quality/review",\n                "/api/telemetry-quality/override",' in web_source,
        "review/override POST dispatcher is missing",
    )
    require(
        "dashboard_telemetry_quality_review_payload" in web_source,
        "review route does not call the review payload",
    )
    require(
        "dashboard_telemetry_quality_override_payload" in web_source,
        "override route does not call the override payload",
    )

    print("[PASS] v0.45 review/override RBAC and session-derived actor boundary")


if __name__ == "__main__":
    main()
