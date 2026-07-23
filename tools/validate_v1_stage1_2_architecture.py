#!/usr/bin/env python3
"""Validate the additive v1 Stage 1–2 architecture transition."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEGACY_MODULES = (
    "auth",
    "config",
    "db",
    "ingest",
    "jobs",
    "reports",
    "sites",
    "web",
)
ADDITIVE_MODULES = (
    "api_v1",
    "current_state",
    "migrations",
    "telemetry_quality",
)
STAGE3_5_MODULES = (
    "detection",
    "identity",
    "operations",
)
STAGE1_2_MODULES = tuple(sorted((*LEGACY_MODULES, *ADDITIVE_MODULES)))
EXPECTED_MODULES = tuple(sorted((*STAGE1_2_MODULES, *STAGE3_5_MODULES)))
ALIASES = {
    "auth": "_auth",
    "ingest": "_ingest",
    "jobs": "_jobs",
    "reports": "_reports",
    "sites": "_sites",
    "web": "_web",
}
CHARACTERIZATIONS = (
    ("docs/v0.44-stage3-auth-characterization.json", "implementation_module", None),
    ("docs/v0.44-stage4-ingest-characterization.json", "implementation_module", None),
    ("docs/v0.44-stage5-7-characterization.json", None, "stages"),
    ("docs/v0.44-stage8-web-characterization.json", "module", None),
)


class ValidationFailure(RuntimeError):
    pass


def check(condition: object, message: str) -> None:
    if not condition:
        raise ValidationFailure(message)


def parse(relative: str) -> tuple[str, ast.Module]:
    path = ROOT / relative
    check(path.is_file(), f"missing architecture file: {relative}")
    source = path.read_text(encoding="utf-8")
    return source, ast.parse(source, filename=relative)


def internal_dependencies(tree: ast.AST) -> set[str]:
    dependencies: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
            if node.module == "deltaaegis_core":
                names.extend(f"deltaaegis_core.{alias.name}" for alias in node.names)
        else:
            continue
        for imported in names:
            check(
                imported != "deltaaegis" and not imported.startswith("deltaaegis."),
                f"internal module imports root compatibility facade: {imported}",
            )
            if imported.startswith("deltaaegis_core."):
                dependency = imported.split(".", 1)[1].split(".", 1)[0]
                if dependency in EXPECTED_MODULES:
                    dependencies.add(dependency)
    return dependencies


def dependency_graph() -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {}
    for module in EXPECTED_MODULES:
        _source, tree = parse(f"deltaaegis_core/{module}.py")
        graph[module] = internal_dependencies(tree) - {module}
    return graph


def validate_acyclic(graph: dict[str, set[str]]) -> None:
    visiting: list[str] = []
    visited: set[str] = set()

    def visit(module: str) -> None:
        if module in visited:
            return
        if module in visiting:
            cycle = visiting[visiting.index(module) :] + [module]
            raise ValidationFailure("internal dependency cycle: " + " -> ".join(cycle))
        visiting.append(module)
        for dependency in sorted(graph[module]):
            visit(dependency)
        visiting.pop()
        visited.add(module)

    for module in EXPECTED_MODULES:
        visit(module)


def top_level_functions(tree: ast.Module) -> dict[str, ast.AST]:
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def characterized_facades() -> dict[str, list[str]]:
    facades: dict[str, list[str]] = {}
    for relative, module_key, stages_key in CHARACTERIZATIONS:
        payload = json.loads((ROOT / relative).read_text(encoding="utf-8"))
        if stages_key:
            for stage in payload[stages_key].values():
                module = Path(stage["module"]).stem
                facades.setdefault(module, []).extend(stage["facade_functions"])
        else:
            module = Path(payload[module_key]).stem
            facades.setdefault(module, []).extend(payload["facade_functions"])
    return facades


def validate_legacy_facades() -> None:
    root_source, root_tree = parse("deltaaegis.py")
    root_functions = top_level_functions(root_tree)
    for module, names in characterized_facades().items():
        module_source, module_tree = parse(f"deltaaegis_core/{module}.py")
        module_functions = top_level_functions(module_tree)
        alias = ALIASES[module]
        for name in names:
            check(name in root_functions, f"root compatibility facade is missing {name}")
            check(name in module_functions, f"authoritative module {module} is missing {name}")
            segment = ast.get_source_segment(root_source, root_functions[name]) or ""
            check(f"{alias}." in segment, f"root facade no longer delegates {name} to {module}")
        check(module_source.strip(), f"authoritative module is empty: {module}")


def validate_package_surface() -> None:
    source, tree = parse("deltaaegis_core/__init__.py")
    exported: tuple[str, ...] | None = None
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets):
            continue
        exported = tuple(ast.literal_eval(node.value))
    check(exported is not None, "deltaaegis_core.__all__ is missing")
    check(tuple(sorted(exported)) == EXPECTED_MODULES, f"package exports drifted: {exported!r}")
    for marker in (
        "compatibility",
        "repository-root ``deltaaegis.py``",
        "``import deltaaegis``",
    ):
        check(marker in source, f"package compatibility documentation is missing {marker}")


def validate_isolated_import() -> None:
    imports = ", ".join(EXPECTED_MODULES)
    code = (
        "import sys; "
        f"sys.path.insert(0, {str(ROOT)!r}); "
        "import deltaaegis, deltaaegis_core; "
        f"from deltaaegis_core import {imports}; "
        "assert deltaaegis.DELTAAEGIS_VERSION == '1.0.0'; "
        f"assert tuple(sorted(deltaaegis_core.__all__)) == {EXPECTED_MODULES!r}"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code],
        cwd="/",
        capture_output=True,
        text=True,
        check=False,
    )
    check(completed.returncode == 0, "isolated package import failed: " + completed.stderr.strip())


def main() -> int:
    actual = tuple(
        sorted(
            path.stem
            for path in (ROOT / "deltaaegis_core").glob("*.py")
            if path.name != "__init__.py"
        )
    )
    check(actual == EXPECTED_MODULES, f"unexpected core module inventory: {actual!r}")
    graph = dependency_graph()
    validate_acyclic(graph)
    validate_package_surface()
    validate_legacy_facades()
    validate_isolated_import()
    print(
        "[PASS] v1 Stage 1–2 architecture transition: baseline modules remain "
        "complete beneath the exact Stage 3–5 additive inventory, dependencies "
        "are acyclic, v0.44 facades are preserved, and imports are isolated"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValidationFailure, ValueError, SyntaxError) as exc:
        print(f"[FAIL] v1 Stage 1–2 architecture: {exc}", file=sys.stderr)
        raise SystemExit(1)
