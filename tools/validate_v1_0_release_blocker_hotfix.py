#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Regression validator for DeltaAegis v1.0 release-blocker hotfixes."""
from __future__ import annotations

import argparse
import ast
import importlib.util
import inspect
import ipaddress
import sqlite3
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any


class ValidationFailure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationFailure(message)


def definitions(tree: ast.Module, name: str) -> list[ast.FunctionDef]:
    return [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]


def compile_function(node: ast.FunctionDef, globals_dict: dict[str, Any]):
    module = ast.Module(body=[node], type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = dict(globals_dict)
    exec(compile(module, "<extracted-deltaaegis-function>", "exec"), namespace)
    return namespace[node.name]


def ip_key(row: dict[str, Any]) -> tuple[Any, ...]:
    scope = str(row.get("network_scope") or "")
    raw = str(row.get("current_ip") or row.get("ip_address") or "").strip()
    try:
        parsed = ipaddress.ip_address(raw)
        parsed_key = (0, parsed.version, int(parsed))
    except ValueError:
        parsed_key = (1, 0, raw.casefold())
    return (scope, parsed_key, str(row.get("mac_address") or "").casefold(), str(row.get("asset_key") or "").casefold())


def validate_deltaaegis(repo: Path) -> list[str]:
    path = repo / "deltaaegis.py"
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    passed: list[str] = []

    detail_defs = definitions(tree, "dashboard_asset_detail_payload")
    require(len(detail_defs) >= 2, "expected wrapped dashboard_asset_detail_payload definitions")
    wrapped_detail = detail_defs[-1]
    arg_names = [arg.arg for arg in wrapped_detail.args.args]
    require("limit" in arg_names, "final asset-detail wrapper does not accept limit")
    detail_source = ast.get_source_segment(source, wrapped_detail) or ""
    require("limit=limit" in detail_source, "final asset-detail wrapper does not forward limit")

    captured: dict[str, Any] = {}
    def base_detail(connection, identifier, scope=None, limit=20):
        captured.update(identifier=identifier, scope=scope, limit=limit)
        return {"found": True, "latest_observation": {"asset_key": identifier}}
    detail = compile_function(
        wrapped_detail,
        {
            "_deltaaegis_dashboard_asset_detail_v045_base": base_detail,
            "dashboard_enrich_classification_context_payload": lambda value: value,
            "_current_state": SimpleNamespace(augment_asset_detail=lambda connection, payload: payload),
        },
    )
    payload = detail(object(), "asset-1", scope="192.168.1.0/24", limit=7)
    require(payload.get("found") is True, "asset-detail wrapper did not return payload")
    require(captured.get("limit") == 7, "asset-detail wrapper did not forward requested limit")
    passed.append("asset-detail limit contract")

    asset_defs = definitions(tree, "dashboard_assets_payload")
    require(len(asset_defs) >= 3, "expected layered dashboard_assets_payload definitions")
    final_assets = asset_defs[-1]
    calls: list[int] = []
    dataset = [
        {"network_scope": "192.168.1.0/24", "current_ip": f"192.168.1.{number}", "asset_key": f"ip:{number}"}
        for number in range(1, 31)
    ]
    lexical = sorted(dataset, key=lambda row: row["current_ip"])
    def base_assets(connection, limit, scope=None, state=None, identity=None):
        calls.append(limit)
        return lexical[:limit]
    assets = compile_function(
        final_assets,
        {
            "sqlite3": sqlite3,
            "Any": Any,
            "_deltaaegis_dashboard_assets_payload_v042_numeric_base": base_assets,
            "dashboard_asset_numeric_ip_sort_key": ip_key,
        },
    )
    result = assets(object(), 5)
    require(calls == [10000], f"asset wrapper fetched {calls!r}, expected [10000]")
    require(
        [row["current_ip"] for row in result] == [f"192.168.1.{n}" for n in range(1, 6)],
        "asset wrapper truncated before numeric IP ordering",
    )
    passed.append("global numeric ordering before truncation")

    site_defs = definitions(tree, "dashboard_site_assets_payload")
    require(len(site_defs) == 1, "expected one dashboard_site_assets_payload definition")
    site_calls: list[tuple[str | None, int]] = []
    per_scope = {
        "10.0.0.0/24": [
            {"network_scope": "10.0.0.0/24", "current_ip": "10.0.0.10", "asset_key": "a10", "state": "ACTIVE"},
            {"network_scope": "10.0.0.0/24", "current_ip": "10.0.0.2", "asset_key": "a2", "state": "ACTIVE"},
        ],
        "192.168.1.0/24": [
            {"network_scope": "192.168.1.0/24", "current_ip": "192.168.1.11", "asset_key": "b11", "state": "ACTIVE"},
            {"network_scope": "192.168.1.0/24", "current_ip": "192.168.1.3", "asset_key": "b3", "state": "ACTIVE"},
        ],
    }
    def site_assets_loader(connection, limit, scope=None, state=None, identity=None):
        site_calls.append((scope, limit))
        return list(per_scope[str(scope)])[:limit]
    site_assets = compile_function(
        site_defs[0],
        {
            "sqlite3": sqlite3,
            "Any": Any,
            "dashboard_site_aggregation_context": lambda connection, site_id: {"member_scopes": list(per_scope)},
            "dashboard_site_tag_rows": lambda rows, scope, context: rows,
            "dashboard_assets_payload": site_assets_loader,
            "dashboard_asset_numeric_ip_sort_key": ip_key,
        },
    )
    site_result = site_assets(object(), "site-1", 4)
    require(all(limit == 10000 for _scope, limit in site_calls), "site assets were truncated per scope")
    require(
        [row["current_ip"] for row in site_result]
        == ["10.0.0.2", "10.0.0.10", "192.168.1.3", "192.168.1.11"],
        "site assets are not numerically ordered before global truncation",
    )
    passed.append("logical-site numeric ordering before truncation")

    for name in ("dashboard_netsniper_scan_worker", "dashboard_trueaegis_validation_worker"):
        node = definitions(tree, name)[0]
        segment = ast.get_source_segment(source, node) or ""
        require("_record_background_worker_persistence_failure" in segment, f"{name} still hides persistence failures")
    require(
        "result[\"persistence_error\"] = str(persistence_exc)" in source,
        "TrueAegis start failure does not expose persistence failure",
    )
    reporter = definitions(tree, "_record_background_worker_persistence_failure")
    require(len(reporter) == 1, "worker persistence reporter is missing or duplicated")
    reporter_source = ast.get_source_segment(source, reporter[0]) or ""
    require("worker-persistence-failures.jsonl" in reporter_source, "durable worker failure log is missing")
    require("connection.rollback()" in reporter_source, "worker failure reporter does not roll back")
    passed.append("worker persistence failure observability")
    return passed


def validate_current_state(repo: Path) -> list[str]:
    path = repo / "deltaaegis_core/current_state.py"
    spec = importlib.util.spec_from_file_location("deltaaegis_hotfix_current_state", path)
    require(spec is not None and spec.loader is not None, "could not load current_state module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        "CREATE TABLE telemetry_current_assets (network_scope TEXT, asset_key TEXT, ip_address TEXT)"
    )
    for number in range(1, 31):
        connection.execute(
            "INSERT INTO telemetry_current_assets VALUES (?, ?, ?)",
            ("192.168.1.0/24", f"ip:{number}", f"192.168.1.{number}"),
        )
    module.ensure_ready = lambda connection: None
    module.ensure_schema = lambda connection: None
    rows = module.current_assets(connection, limit=5)
    require(
        [row["ip_address"] for row in rows] == [f"192.168.1.{n}" for n in range(1, 6)],
        "current_assets truncates before numeric ordering",
    )

    module.current_assets = lambda connection, scope=None, limit=10000: []
    merged = module.merge_asset_rows(
        connection,
        [
            {"network_scope": "192.168.1.0/24", "state": "ACTIVE", "current_ip": "192.168.1.10", "asset_key": "a10"},
            {"network_scope": "192.168.1.0/24", "state": "ACTIVE", "current_ip": "192.168.1.2", "asset_key": "a2"},
            {"network_scope": "192.168.1.0/24", "state": "ACTIVE", "current_ip": "192.168.1.1", "asset_key": "a1"},
        ],
        limit=2,
    )
    require(
        [row["current_ip"] for row in merged] == ["192.168.1.1", "192.168.1.2"],
        "merge_asset_rows truncates before numeric ordering",
    )
    return ["current-state numeric ordering"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args()
    repo = args.repo.expanduser().resolve()
    checks = []
    checks.extend(validate_deltaaegis(repo))
    checks.extend(validate_current_state(repo))
    compile((repo / "deltaaegis.py").read_text(encoding="utf-8"), str(repo / "deltaaegis.py"), "exec", ast.PyCF_ONLY_AST)
    compile((repo / "deltaaegis_core/current_state.py").read_text(encoding="utf-8"), str(repo / "deltaaegis_core/current_state.py"), "exec", ast.PyCF_ONLY_AST)
    checks.append("Python syntax")
    for check in checks:
        print(f"PASS: {check}")
    print(f"PASS: {len(checks)} DeltaAegis v1.0 release-blocker hotfix checks")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValidationFailure as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
