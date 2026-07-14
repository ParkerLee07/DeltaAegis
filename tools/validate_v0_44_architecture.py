#!/usr/bin/env python3
"""Validate the completed v0.44 internal module and compatibility boundaries."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MODULES = ("auth", "config", "db", "ingest", "jobs", "reports", "sites", "web")
ALIASES = {
    "auth": "_auth", "ingest": "_ingest", "sites": "_sites",
    "jobs": "_jobs", "reports": "_reports", "web": "_web",
}
CHARACTERIZATIONS = (
    ("docs/v0.44-stage3-auth-characterization.json", "implementation_module", None),
    ("docs/v0.44-stage4-ingest-characterization.json", "implementation_module", None),
    ("docs/v0.44-stage5-7-characterization.json", None, "stages"),
    ("docs/v0.44-stage8-web-characterization.json", "module", None),
)


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def parse(relative: str) -> tuple[str, ast.Module]:
    path = ROOT / relative
    if not path.is_file():
        fail(f"missing architecture file: {relative}")
    source = path.read_text(encoding="utf-8")
    return source, ast.parse(source, filename=relative)


def imports(tree: ast.AST) -> list[str]:
    result: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            result.append(node.module)
    return result


def dependency_graph() -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {}
    for name in EXPECTED_MODULES:
        _, tree = parse(f"deltaaegis_core/{name}.py")
        graph[name] = set()
        for imported in imports(tree):
            if imported == "deltaaegis" or imported.startswith("deltaaegis."):
                fail(f"internal module imports root compatibility facade: {name}: {imported}")
            if imported.startswith("deltaaegis_core."):
                dependency = imported.split(".", 1)[1].split(".", 1)[0]
                if dependency in EXPECTED_MODULES and dependency != name:
                    graph[name].add(dependency)
    return graph


def assert_acyclic(graph: dict[str, set[str]]) -> None:
    visiting: list[str] = []
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visited:
            return
        if node in visiting:
            cycle = visiting[visiting.index(node):] + [node]
            fail("circular internal dependency: " + " -> ".join(cycle))
        visiting.append(node)
        for dependency in sorted(graph[node]):
            visit(dependency)
        visiting.pop()
        visited.add(node)

    for node in sorted(graph):
        visit(node)


def top_level_functions(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def characterized_facades() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for relative, module_key, stages_key in CHARACTERIZATIONS:
        payload = json.loads((ROOT / relative).read_text(encoding="utf-8"))
        if stages_key:
            for stage in payload[stages_key].values():
                module = Path(stage["module"]).stem
                result.setdefault(module, []).extend(stage["facade_functions"])
        else:
            module = Path(payload[module_key]).stem
            result.setdefault(module, []).extend(payload["facade_functions"])
    return result


def validate_facade_ownership() -> None:
    root_source, root_tree = parse("deltaaegis.py")
    root_functions = top_level_functions(root_tree)
    for module, names in characterized_facades().items():
        module_source, module_tree = parse(f"deltaaegis_core/{module}.py")
        module_functions = top_level_functions(module_tree)
        alias = ALIASES[module]
        for name in names:
            if name not in root_functions:
                fail(f"root compatibility facade is missing {name}")
            if name not in module_functions:
                fail(f"authoritative module {module} is missing {name}")
            segment = ast.get_source_segment(root_source, root_functions[name]) or ""
            if f"{alias}." not in segment:
                fail(f"root facade does not delegate {name} to {module}")


def validate_package_surface() -> None:
    init_source, init_tree = parse("deltaaegis_core/__init__.py")
    values = None
    for node in init_tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets):
            continue
        try:
            values = tuple(ast.literal_eval(node.value))
        except Exception as exc:
            fail(f"could not read deltaaegis_core.__all__: {exc}")
    if values != EXPECTED_MODULES:
        fail(f"deltaaegis_core.__all__ changed: {values!r}")
    root_source, _ = parse("deltaaegis.py")
    for name in EXPECTED_MODULES:
        if name in {"config", "db"}:
            continue
        if f"from deltaaegis_core import {name} as _{name}" not in root_source:
            fail(f"root facade import missing for {name}")
    for marker in (
        "from deltaaegis_core.config import (",
        "from deltaaegis_core.db import open_database_connection",
    ):
        if marker not in root_source:
            fail(f"low-level boundary import missing: {marker}")
    package_doc = ast.get_docstring(init_tree, clean=False) or ""
    for marker in (
        "compatibility",
        "repository-root ``deltaaegis.py``",
        "``import deltaaegis``",
    ):
        if marker not in package_doc:
            fail(f"package documentation is missing compatibility marker: {marker}")


def validate_isolated_import() -> None:
    code = (
        "import sys; "
        f"sys.path.insert(0, {str(ROOT)!r}); "
        "import deltaaegis; "
        "import deltaaegis_core; "
        "from deltaaegis_core import auth, config, db, ingest, jobs, reports, sites, web; "
        "assert deltaaegis.DELTAAEGIS_VERSION == '0.44.0'; "
        "assert tuple(deltaaegis_core.__all__) == ('auth','config','db','ingest','jobs','reports','sites','web')"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code],
        cwd="/",
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode:
        fail("isolated installed-checkout import failed: " + completed.stderr.strip())


def main() -> int:
    print("DeltaAegis v0.44 Architecture Boundary Validator")
    print("==================================================")
    actual = tuple(sorted(path.stem for path in (ROOT / "deltaaegis_core").glob("*.py") if path.name != "__init__.py"))
    if actual != tuple(sorted(EXPECTED_MODULES)):
        fail(f"unexpected core module inventory: {actual!r}")
    graph = dependency_graph()
    assert_acyclic(graph)
    print("PASS: exact internal module inventory and acyclic dependency graph")
    validate_package_surface()
    print("PASS: root executable/import facade and internal package surface")
    validate_facade_ownership()
    print("PASS: characterized functions retain one authoritative module and root delegation")
    validate_isolated_import()
    print("PASS: imports work from an isolated non-repository working directory")
    print("PASS: no internal module imports the root deltaaegis compatibility facade")
    print("PASS: DeltaAegis v0.44 modular architecture boundary")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
