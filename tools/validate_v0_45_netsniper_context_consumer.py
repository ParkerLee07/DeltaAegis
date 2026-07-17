#!/usr/bin/env python3
"""Validate the v0.45 detail-only NetSniper context consumer."""

from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT / "deltaaegis.py"
MARKER = "DELTAAEGIS_V045_NETSNIPER_CONTEXT_CONSUMER"
CONTEXT_HELPER = "dashboard_enrich_classification_context_payload"
LIST_HELPER = "dashboard_enrich_classification_payload"
DETAIL_FUNCTION = "dashboard_asset_detail_payload"


def fail(message):
    raise SystemExit(f"[FAIL] {message}")


def require(condition, message):
    if not condition:
        fail(message)


def load_deltaaegis():
    spec = importlib.util.spec_from_file_location(
        "deltaaegis_v045_context_validation",
        SOURCE_PATH,
    )
    if spec is None or spec.loader is None:
        fail("could not create DeltaAegis import specification")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def base_row(classification_json):
    return {
        "classification_json": classification_json,
        "classification_evidence_json": "[]",
        "classification_contradictions_json": "[]",
        "classification_candidates_json": "[]",
        "classification_type": "network_device",
        "classification_primary_type": "network_device",
        "classification_method": "netsniper",
        "classification_confidence": 72,
        "classification_decision": "classified",
        "device_type": "Network Device",
        "device_type_confidence": 72,
    }


def call_name(node):
    function = node.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return None


def function_map(tree):
    result = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result.setdefault(node.name, []).append(node)
    return result


def active_function(functions, name):
    definitions = functions.get(name, [])
    require(definitions, f"missing required function: {name}")
    return definitions[-1]


def function_calls(definition, target):
    return [
        node.lineno
        for node in ast.walk(definition)
        if isinstance(node, ast.Call) and call_name(node) == target
    ]


def semantic_tokens(node):
    tokens = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Name):
            tokens.add(item.id)
        elif isinstance(item, ast.Attribute):
            tokens.add(item.attr)
        elif isinstance(item, ast.Constant) and isinstance(item.value, str):
            tokens.add(item.value)
    return tokens


def require_single_new_function(functions, name):
    definitions = functions.get(name, [])
    require(
        len(definitions) == 1,
        f"expected one v0.45 helper {name}, found {len(definitions)}",
    )
    return definitions[0]


def main():
    source = SOURCE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(SOURCE_PATH))
    functions = function_map(tree)

    require(source.count(MARKER) == 1, "source marker missing or duplicated")

    require_single_new_function(functions, CONTEXT_HELPER)
    require_single_new_function(functions, LIST_HELPER)

    detail_function = active_function(functions, DETAIL_FUNCTION)
    list_function = active_function(functions, "dashboard_assets_payload")
    event_function = active_function(functions, "classification_delta_events")
    risk_query_function = active_function(functions, "risk_latest_asset_context")
    risk_function = active_function(functions, "risk_classification_context")

    detail_calls = function_calls(detail_function, CONTEXT_HELPER)
    require(
        len(detail_calls) == 1,
        f"active {DETAIL_FUNCTION} must call the context helper exactly once; "
        f"found lines {detail_calls}",
    )

    for name, definitions in functions.items():
        if name == DETAIL_FUNCTION:
            continue
        for definition in definitions:
            calls = function_calls(definition, CONTEXT_HELPER)
            require(
                not calls,
                f"context helper must remain detail-only; {name} calls it at {calls}",
            )

    list_tokens = semantic_tokens(list_function)
    require("classification_context" not in list_tokens, "asset-list payload exposes full context")
    require("classification_json" not in list_tokens, "asset-list query selects full classification JSON")
    require(CONTEXT_HELPER not in list_tokens, "asset-list path calls the detail-only helper")

    event_tokens = semantic_tokens(event_function)
    require("semantic_fingerprint" not in event_tokens, "semantic fingerprint creates events")

    risk_tokens = semantic_tokens(risk_query_function) | semantic_tokens(risk_function)
    require("classification_context" not in risk_tokens, "risk path consumes the new context")
    require("operator_disposition" not in risk_tokens, "risk path consumes operator disposition")
    require("semantic_fingerprint" not in risk_tokens, "risk path consumes semantic fingerprint")

    schema_strings = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "CREATE TABLE IF NOT EXISTS asset_observations" in node.value
    ]
    require(schema_strings, "could not identify the asset_observations schema")
    require(
        all("classification_context" not in value for value in schema_strings),
        "context consumer added a database column",
    )

    context_field_functions = []
    for name, definitions in functions.items():
        for definition in definitions:
            values = {
                node.value
                for node in ast.walk(definition)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
            }
            if {"classification_context", "classification_context_available"} & values:
                context_field_functions.append(name)
    require(
        set(context_field_functions) == {CONTEXT_HELPER},
        "context payload fields must be emitted only by the detail helper; "
        f"found {context_field_functions}",
    )

    module = load_deltaaegis()
    context = {
        "schema_version": "netsniper-deltaaegis-evidence-context-v1",
        "operator_disposition": "review",
        "semantic_fingerprint": "sha256:test-fingerprint",
        "network_roles": ["infrastructure"],
        "axes": {"device_family": {"label": "network_device"}},
        "observation_quality": {"scan_completeness": "complete"},
        "uncertainty_reasons": ["platform_unresolved"],
    }

    encoded = json.dumps({"deltaaegis_context": context}, sort_keys=True)
    row = base_row(encoded)
    original_row = dict(row)
    detail = module.dashboard_enrich_classification_context_payload(row)
    require(row == original_row, "detail helper mutated its input row")
    require(detail["classification_context_available"] is True, "valid context unavailable")
    require(detail["classification_context"] == context, "valid context was transformed")
    require(detail["classification_display_type"] == "network_device", "legacy detail changed")

    direct_classification = {"deltaaegis_context": context}
    direct_detail = module.dashboard_enrich_classification_context_payload(
        base_row(direct_classification)
    )
    require(direct_detail["classification_context"] is context, "direct dictionary context was copied or transformed")

    require(
        module.dashboard_enrich_classification_context_payload(None) is None,
        "None row compatibility changed",
    )

    list_payload = module.dashboard_enrich_classification_payload(base_row(encoded))
    require(
        "classification_context" not in list_payload
        and "classification_context_available" not in list_payload,
        "shared list serializer leaked detail-only context",
    )

    cases = (
        ("none", None),
        ("empty string", ""),
        ("absent", "{}"),
        ("malformed", "{broken"),
        ("direct list", ["not", "a", "classification object"]),
        ("direct integer", 7),
        ("top-level JSON list", json.dumps(["not", "an", "object"])),
        ("wrong context type", json.dumps({"deltaaegis_context": ["not", "an", "object"]})),
        ("empty", json.dumps({"deltaaegis_context": {}})),
    )
    for label, value in cases:
        payload = module.dashboard_enrich_classification_context_payload(base_row(value))
        require(
            payload["classification_context_available"] is False,
            f"{label} context marked available",
        )
        require(
            payload["classification_context"] == {},
            f"{label} context did not fail closed",
        )

    print("[PASS] AST confirms context is emitted only by the asset-detail path")
    print("[PASS] valid string and dictionary contexts are preserved without reinterpretation")
    print("[PASS] absent, malformed, empty, and wrong-type inputs fail closed")
    print("[PASS] schema, risk, events, and list-payload boundaries are preserved")
    print("[PASS] DeltaAegis v0.45 NetSniper context consumer validator complete")


if __name__ == "__main__":
    main()
