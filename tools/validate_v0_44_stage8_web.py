#!/usr/bin/env python3
"""Validate the behavior-preserving v0.44 dashboard web extraction."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHARACTERIZATION_PATH = ROOT / "docs" / "v0.44-stage8-web-characterization.json"
EXPECTED_SOURCE_TREE = "0ef3bdacb5bfdd19653c5abf7ce0288b601e28e0"

sys.path.insert(0, str(ROOT))

import deltaaegis as facade  # noqa: E402
from deltaaegis_core import web  # noqa: E402


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def load_characterization() -> dict:
    payload = json.loads(CHARACTERIZATION_PATH.read_text(encoding="utf-8"))
    check(payload.get("format") == "deltaaegis-v0.44-stage8-web-characterization-v1", "format changed")
    check(payload.get("source_checkpoint_tree") == EXPECTED_SOURCE_TREE, "Stage 8 source checkpoint changed")
    check(payload.get("schema_change") is False, "Stage 8 must not claim a schema change")
    check(payload.get("runtime_version_change") is False, "Stage 8 must not change runtime metadata")
    check(payload.get("stable_api_introduced") is False, "Stage 8 must not claim the future stable API")
    return payload


def top_level_functions(path: Path) -> dict[str, ast.FunctionDef]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}


def comparable_parameters(function) -> list[tuple[str, inspect._ParameterKind, str]]:
    result = []
    for parameter in inspect.signature(function).parameters.values():
        if parameter.name == "namespace":
            continue
        default = "<empty>" if parameter.default is inspect.Parameter.empty else repr(parameter.default)
        result.append((parameter.name, parameter.kind, default))
    return result


def validate_ownership(characterization: dict) -> None:
    root_path = ROOT / "deltaaegis.py"
    web_path = ROOT / characterization["module"]
    root_source = root_path.read_text(encoding="utf-8")
    web_source = web_path.read_text(encoding="utf-8")
    root_functions = top_level_functions(root_path)
    web_functions = top_level_functions(web_path)

    check("from deltaaegis_core import web as _web" in root_source, "web import missing")
    check("web" in __import__("deltaaegis_core").__all__, "web package export missing")
    check("def _command_dashboard_impl(args):" in web_source, "handler implementation missing")
    check("class DeltaAegisDashboardHandler" in web_source, "HTTP handler ownership missing")
    check("ThreadingHTTPServer" in web_source, "server lifecycle ownership missing")

    for name in characterization["facade_functions"]:
        check(name in root_functions, f"root facade missing: {name}")
        check(name in web_functions, f"web implementation missing: {name}")
        root_segment = ast.get_source_segment(root_source, root_functions[name]) or ""
        check("_web." in root_segment, f"root function is not a web facade: {name}")
        check(
            comparable_parameters(getattr(facade, name)) == comparable_parameters(getattr(web, name)),
            f"compatibility parameters changed: {name}",
        )

    command_segment = ast.get_source_segment(root_source, root_functions["command_dashboard"]) or ""
    check("class DeltaAegisDashboardHandler" not in command_segment, "HTTP handler remains in root command")
    check("if False:" in command_segment, "documented LAN source-contract shim missing")
    check("namespace=globals()" in command_segment, "runtime collaborator handoff missing")


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def validate_rendering(characterization: dict) -> None:
    for name, expected in characterization["render_fingerprints"].items():
        rendered = getattr(facade, name)()
        check(isinstance(rendered, str), f"renderer no longer returns text: {name}")
        check(len(rendered.encode("utf-8")) == expected["bytes"], f"rendered size changed: {name}")
        check(digest(rendered) == expected["sha256"], f"rendered content changed: {name}")

    sample = "<html><head><title>DeltaAegis</title></head><body></body></html>"
    root_rendered = facade.dashboard_inject_netsniper_navigation(
        facade.dashboard_inject_operator_floating_button(sample)
    )
    web.install_namespace(vars(facade))
    module_rendered = web.dashboard_inject_netsniper_navigation(
        web.dashboard_inject_operator_floating_button(sample)
    )
    check(root_rendered == module_rendered, "HTML injection behavior split")


def validate_routes(characterization: dict) -> None:
    source = (ROOT / characterization["module"]).read_text(encoding="utf-8")
    routes = sorted(
        set(
            re.findall(
                r'''["'](/(?:api/[^"'?# ]+|healthz|login|logout|operator(?:/users)?|netsniper))["']''',
                source,
            )
        )
    )
    encoded = json.dumps(routes, separators=(",", ":"))
    check(len(routes) == characterization["route_inventory"]["count"], "route count changed")
    check(digest(encoded) == characterization["route_inventory"]["sha256"], "route inventory changed")
    check("/healthz" in routes and "/api/session" in routes, "core authenticated routes missing")
    check("/api/netsniper/scan-start" in routes, "scan route missing")
    check("/api/sites" in routes, "Sites route missing")


class Writer:
    def __init__(self, exception=None):
        self.exception = exception
        self.body = b""

    def write(self, body):
        if self.exception:
            raise self.exception("simulated disconnect")
        self.body += body


class Handler:
    def __init__(self, exception=None):
        self.wfile = Writer(exception)
        self.statuses = []
        self.headers = []

    def send_response(self, status):
        self.statuses.append(status)

    def send_header(self, name, value):
        self.headers.append((name, value))

    def end_headers(self):
        pass


def validate_response_and_bind_boundaries() -> None:
    for response in (facade.dashboard_json_response, web.dashboard_json_response):
        handler = Handler()
        response(handler, {"ok": True})
        check(handler.statuses == [200], "JSON response status changed")
        check(json.loads(handler.wfile.body) == {"ok": True}, "JSON response body changed")
        for exception in (BrokenPipeError, ConnectionResetError):
            response(Handler(exception), {"ok": True})
        try:
            response(Handler(RuntimeError), {"ok": True})
        except RuntimeError:
            pass
        else:
            raise AssertionError("unrelated response write failure was masked")

    for host in ("127.0.0.1", "::1", "localhost"):
        check(facade.dashboard_bind_host_is_loopback(host), f"loopback rejected: {host}")
    for host in ("0.0.0.0", "::", "192.168.1.10"):
        check(not facade.dashboard_bind_host_is_loopback(host), f"network bind treated as loopback: {host}")


def main() -> int:
    print("DeltaAegis v0.44 Stage 8 Dashboard Web Boundary Validator")
    print("===========================================================")
    characterization = load_characterization()
    validate_ownership(characterization)
    print("PASS: extracted handler, routing, response, rendering, and lifecycle ownership")
    validate_rendering(characterization)
    print("PASS: deterministic login, NetSniper, and navigation rendering")
    validate_routes(characterization)
    print("PASS: frozen authenticated route inventory")
    validate_response_and_bind_boundaries()
    print("PASS: disconnect handling and loopback/LAN bind boundaries")
    print("PASS: unchanged schema, runtime metadata, and root public facade")
    print("PASS: DeltaAegis v0.44 Stage 8 dashboard web extraction")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
