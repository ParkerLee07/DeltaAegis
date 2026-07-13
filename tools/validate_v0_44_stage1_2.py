#!/usr/bin/env python3
"""Validate the v0.44 characterization, config, and DB-boundary checkpoint."""

from __future__ import annotations

import ast
import hashlib
import importlib
import inspect
import json
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "deltaaegis.py"
CHARACTERIZATION = ROOT / "docs/v0.44-stage1-2-characterization.json"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load_characterization() -> dict[str, object]:
    try:
        data = json.loads(CHARACTERIZATION.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid characterization fixture: {exc}")
    require(
        data.get("schema_version")
        == "deltaaegis-v0.44-stage1-2-characterization-v1",
        "unexpected characterization schema",
    )
    require(data.get("source_release") == "0.43.0", "characterization source drift")
    contracts = data.get("contracts")
    require(isinstance(contracts, dict), "characterization contracts are missing")
    return contracts


def root_assignment(tree: ast.Module, name: str) -> ast.AST | None:
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            return node.value
    return None


def validate_package_boundary(tree: ast.Module) -> None:
    require((ROOT / "deltaaegis_core/__init__.py").is_file(), "missing internal package")
    require((ROOT / "deltaaegis_core/config.py").is_file(), "missing config module")
    require((ROOT / "deltaaegis_core/db.py").is_file(), "missing DB module")
    require(not (ROOT / "deltaaegis").exists(), "deltaaegis package would shadow deltaaegis.py")

    imported_modules: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module)
    require("deltaaegis_core.config" in imported_modules, "facade does not import config")
    require("deltaaegis_core.db" in imported_modules, "facade does not import DB boundary")

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import deltaaegis, pathlib; "
            "print(pathlib.Path(deltaaegis.__file__).resolve()); "
            "print(deltaaegis.DEFAULT_DB)",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    require(completed.returncode == 0, completed.stderr.strip() or "facade import failed")
    lines = completed.stdout.splitlines()
    require(lines and Path(lines[0]) == SOURCE.resolve(), "import deltaaegis is shadowed")
    print("PASS: non-conflicting internal package and root compatibility facade")


def validate_config(contracts: dict[str, object]) -> None:
    module = importlib.import_module("deltaaegis_core.config")
    facade = importlib.import_module("deltaaegis")
    expected = contracts.get("default_suffixes")
    require(isinstance(expected, dict), "default path characterization is missing")
    home = Path.home()
    for name, suffix in expected.items():
        value = getattr(module, name, None)
        require(isinstance(value, Path), f"{name} is not a Path")
        actual = str(value).replace(str(home), "~", 1)
        require(actual == suffix, f"{name} changed: {actual!r} != {suffix!r}")
        require(getattr(facade, name, None) == value, f"facade does not re-export {name}")

    isolated = Path("/tmp/deltaaegis-v044-characterized-home")
    paths = module.runtime_paths(isolated)
    require(paths.database == isolated / "DeltaAegis/data/deltaaegis.db", "custom home DB")
    require(paths.netsniper == isolated / "NetSniper/netsniper.sh", "custom home NetSniper")
    require(paths.trueaegis == isolated / "TrueAegis/trueaegis.py", "custom home TrueAegis")
    print("PASS: characterized runtime path defaults and compatibility aliases")


def validate_schema_and_connection(tree: ast.Module, contracts: dict[str, object]) -> None:
    schema_node = root_assignment(tree, "SCHEMA_SQL")
    require(
        isinstance(schema_node, ast.Constant) and isinstance(schema_node.value, str),
        "SCHEMA_SQL must remain a facade-owned literal before the migration ledger",
    )
    actual_hash = hashlib.sha256(schema_node.value.encode("utf-8")).hexdigest()
    require(actual_hash == contracts.get("schema_sha256"), "SCHEMA_SQL contract changed")

    db_source = (ROOT / "deltaaegis_core/db.py").read_text(encoding="utf-8")
    require("SCHEMA_SQL" not in db_source, "DB boundary prematurely owns schema")
    require("executescript" not in db_source, "low-level DB boundary mutates schema")

    facade = importlib.import_module("deltaaegis")
    db_module = importlib.import_module("deltaaegis_core.db")
    require(str(inspect.signature(facade.connect)) == contracts.get("connect_signature"), "connect signature changed")

    with tempfile.TemporaryDirectory(prefix="deltaaegis-v044-stage12-") as temp_name:
        root = Path(temp_name)
        raw_path = root / "raw" / "connection.db"
        raw = db_module.open_database_connection(raw_path)
        require(raw_path.is_file(), "low-level DB boundary did not create database")
        require(raw.row_factory is sqlite3.Row, "row factory changed")
        raw_tables = raw.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        require(raw_tables == [], "low-level DB boundary initialized schema")
        raw.close()

        application = facade.connect(root / "application" / "deltaaegis.db")
        tables = [
            row[0]
            for row in application.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        foreign_keys = application.execute("PRAGMA foreign_keys").fetchone()[0]
        require(tables == contracts.get("tables"), "initialized table inventory changed")
        require(foreign_keys == contracts.get("foreign_keys"), "foreign-key policy changed")
        require(application.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "integrity check failed")
        require(application.execute("PRAGMA foreign_key_check").fetchall() == [], "foreign-key violations")
        application.close()
    print("PASS: characterized schema and extracted low-level connection policy")


def validate_architecture() -> None:
    overview = (ROOT / "docs/architecture/overview.md").read_text(encoding="utf-8")
    adr = (ROOT / "docs/architecture/decisions/0010-internal-package-compatibility-facade.md").read_text(encoding="utf-8")
    for marker in (
        "deltaaegis_core/config.py",
        "deltaaegis_core/db.py",
        "repository-root `deltaaegis.py` remains",
        "ADR 0010",
    ):
        require(marker in overview, f"architecture overview is missing {marker!r}")
    for marker in (
        "- Status: Accepted",
        "## Context",
        "## Decision",
        "## Consequences",
        "import deltaaegis",
        "SCHEMA_SQL",
    ):
        require(marker in adr, f"ADR 0010 is missing {marker!r}")
    print("PASS: package-collision decision and extraction map")


def main() -> int:
    print("DeltaAegis v0.44 Stage 1-2 Validator")
    print("========================================")
    source = SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(SOURCE))
    contracts = load_characterization()
    validate_package_boundary(tree)
    validate_config(contracts)
    validate_schema_and_connection(tree, contracts)
    validate_architecture()
    print("PASS: DeltaAegis v0.44 characterization, config, and DB boundary")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
