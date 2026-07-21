#!/usr/bin/env python3
"""Read-only, deterministic DeltaAegis v0.44 repository inventory."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "deltaaegis-repository-audit-v2"
REPORT_PATH = Path("docs/repository-audit.md")
CORE_DIR = Path("deltaaegis_core")
EXCLUDED_PARTS = {
    ".git", "__pycache__", "backups", "data", "events", "reports",
    "restore-rehearsals", "scan-logs", "trueaegis-logs",
}
TEXT_SUFFIXES = {
    ".css", ".html", ".js", ".json", ".md", ".py", ".sh",
    ".txt", ".yaml", ".yml",
}


def repository_root(value: str | None = None) -> Path:
    root = Path(value).expanduser() if value else Path(__file__).resolve().parents[1]
    root = root.resolve()
    if not (root / "deltaaegis.py").is_file():
        raise SystemExit(f"not a DeltaAegis repository: {root}")
    return root


def relative_files(root: Path) -> list[Path]:
    completed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=False,
        capture_output=True,
    )
    if completed.returncode:
        details = completed.stderr.decode("utf-8", errors="replace").strip()
        raise SystemExit(f"could not inventory Git candidate files: {details}")
    files: list[Path] = []
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SystemExit(f"repository contains a non-UTF-8 path: {exc}") from exc
        rel = Path(value)
        if rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.parts):
            raise SystemExit(f"unsafe path returned by Git inventory: {value!r}")
        path = root / rel
        if not path.is_file() or path.is_symlink():
            continue
        if rel == REPORT_PATH or any(part in EXCLUDED_PARTS for part in rel.parts):
            continue
        files.append(rel)
    return sorted(files, key=lambda item: item.as_posix())


def read_text(root: Path, rel: Path) -> str:
    try:
        return (root / rel).read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return ""


def call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def string_literals(tree: ast.AST) -> Iterable[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.value


def command_names(tree: ast.AST) -> list[str]:
    commands: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or call_name(node.func) != "add_parser":
            continue
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            commands.add(node.args[0].value)
    return sorted(commands)


def core_dependencies(tree: ast.Module) -> tuple[list[str], list[str]]:
    internal: set[str] = set()
    root_imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        else:
            continue
        for name in names:
            if name == "deltaaegis" or name.startswith("deltaaegis."):
                root_imports.add(name)
            if name == "deltaaegis_core":
                continue
            if name.startswith("deltaaegis_core."):
                internal.add(name.split(".", 1)[1].split(".", 1)[0])
    return sorted(internal), sorted(root_imports)


def module_inventory(root: Path) -> tuple[list[dict[str, Any]], dict[str, list[str]], list[str]]:
    modules: list[dict[str, Any]] = []
    graph: dict[str, list[str]] = {}
    root_imports: list[str] = []
    for path in sorted((root / CORE_DIR).glob("*.py"), key=lambda item: item.name):
        if path.name == "__init__.py":
            continue
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        dependencies, forbidden = core_dependencies(tree)
        name = path.stem
        graph[name] = dependencies
        root_imports.extend(f"{name}: {value}" for value in forbidden)
        modules.append(
            {
                "module": name,
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
                "lines": len(source.splitlines()),
                "functions": sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in tree.body),
                "classes": sum(isinstance(node, ast.ClassDef) for node in tree.body),
                "internal_dependencies": dependencies,
            }
        )
    return modules, graph, sorted(root_imports)


def source_inventory(root: Path, files: list[Path]) -> dict[str, Any]:
    source = read_text(root, Path("deltaaegis.py"))
    tree = ast.parse(source, filename="deltaaegis.py")
    functions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    definitions: dict[str, list[int]] = defaultdict(list)
    for node in functions:
        definitions[node.name].append(node.lineno)
    duplicates = {name: lines for name, lines in sorted(definitions.items()) if len(lines) > 1}

    route_sources = [source]
    web_path = root / CORE_DIR / "web.py"
    if web_path.is_file():
        route_sources.append(web_path.read_text(encoding="utf-8"))
    routes: set[str] = set()
    for route_source in route_sources:
        route_tree = ast.parse(route_source)
        for value in string_literals(route_tree):
            for match in re.findall(r"/api/[A-Za-z0-9_{}?=&./:-]+", value):
                route = match.split("?", 1)[0].rstrip("/.,);`'\"")
                if route:
                    routes.add(route)

    tables = sorted(set(re.findall(
        r"CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+[`\"']?([A-Za-z_][A-Za-z0-9_]*)",
        source,
        flags=re.IGNORECASE,
    )))
    modules, graph, forbidden_root_imports = module_inventory(root)

    suffix_counts = Counter((rel.suffix.lower() or "[none]") for rel in files)
    line_counts: dict[str, int] = {}
    for rel in files:
        if rel.suffix.lower() in TEXT_SUFFIXES:
            line_counts[rel.as_posix()] = len(read_text(root, rel).splitlines())

    validators = [
        rel.as_posix() for rel in files
        if rel.parts[0:1] == ("tools",) and rel.name.startswith("validate")
    ]
    validator_versions = Counter()
    for name in validators:
        match = re.search(r"validate_v(\d+)_(\d+)", Path(name).name)
        validator_versions[f"v{match.group(1)}.{match.group(2)}" if match else "unversioned"] += 1

    retirement: dict[str, Any] | None = None
    retirement_path = root / "docs/v0.44.1-validator-retirement.json"
    if retirement_path.is_file():
        retirement = json.loads(retirement_path.read_text(encoding="utf-8"))

    stale_docs: list[dict[str, str]] = []
    legacy_arch = root / "docs/architecture.md"
    if legacy_arch.is_file() and "v0.8.5" in legacy_arch.read_text(encoding="utf-8", errors="replace"):
        stale_docs.append({
            "path": "docs/architecture.md",
            "reason": "Historical v0.8.5 narrative; docs/architecture/overview.md is current.",
            "disposition": "Retain as historical context until a dedicated documentation cleanup owns it.",
        })

    return {
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "source_lines": len(source.splitlines()),
        "top_level_functions": len(functions),
        "top_level_classes": len(classes),
        "duplicate_top_level_functions": duplicates,
        "cli_commands": command_names(tree),
        "api_routes": sorted(routes),
        "schema_tables": tables,
        "core_modules": modules,
        "core_dependency_graph": graph,
        "forbidden_root_imports": forbidden_root_imports,
        "file_count": len(files),
        "file_suffix_counts": dict(sorted(suffix_counts.items())),
        "text_line_counts": dict(sorted(line_counts.items())),
        "validator_files": validators,
        "validator_versions": dict(sorted(validator_versions.items())),
        "validator_retirement": retirement,
        "stale_documents": stale_docs,
    }


def findings(inventory: dict[str, Any]) -> list[dict[str, str]]:
    duplicate_names = ", ".join(inventory["duplicate_top_level_functions"]) or "none"
    core_lines = sum(item["lines"] for item in inventory["core_modules"])
    return [
        {
            "id": "DA044-001", "severity": "MEDIUM", "area": "compatibility facade",
            "evidence": f"deltaaegis.py remains {inventory['source_lines']} lines with {inventory['top_level_functions']} top-level functions; the eight core modules contain {core_lines} lines.",
            "disposition": "Retain the facade through the planned migration/API releases; continue only owned incremental extraction.",
        },
        {
            "id": "DA044-002", "severity": "MEDIUM", "area": "source-order coupling",
            "evidence": f"Repeated top-level function names in the compatibility facade: {duplicate_names}.",
            "disposition": "Remove only with characterization evidence and explicit compatibility ownership.",
        },
        {
            "id": "DA044-003", "severity": "MEDIUM", "area": "storage migrations",
            "evidence": f"{len(inventory['schema_tables'])} table names remain declared through the root-owned schema bootstrap.",
            "disposition": "Complete the remaining forward-only migration-ledger and supported-upgrade roadmap after v0.45.0.",
        },
        {
            "id": "DA044-004", "severity": "MEDIUM", "area": "HTTP/API contract",
            "evidence": f"{len(inventory['api_routes'])} unversioned /api route literals remain implementation endpoints.",
            "disposition": "Introduce /api/v1, OpenAPI, CSRF, and deprecation policy implementation in v0.46.",
        },
        {
            "id": "DA044-005", "severity": "LOW", "area": "validation estate",
            "evidence": (
                f"{len(inventory['validator_files'])} validator scripts span "
                f"{len(inventory['validator_versions'])} version groups; "
                f"{(inventory.get('validator_retirement') or {}).get('retired_validator_count', 0)} "
                "historical validators are preserved by a byte-verified retirement manifest."
            ),
            "disposition": "Retain the current compatibility floor and require manifest-backed replacement evidence for any further validator retirement.",
        },
        {
            "id": "DA044-006", "severity": "MEDIUM", "area": "TrueAegis compatibility",
            "evidence": "TrueAegis remains contract-validated but not pinned to a published semantic-version range.",
            "disposition": "Publish or pin the supported TrueAegis range before v1.0.",
        },
        {
            "id": "DA044-007", "severity": "LOW", "area": "documentation",
            "evidence": f"{len(inventory['stale_documents'])} known historical architecture document marker remains.",
            "disposition": "Keep docs/architecture/overview.md authoritative and clean historical prose only in an owned documentation change.",
        },
    ]


def build_audit(root: Path) -> dict[str, Any]:
    files = relative_files(root)
    inventory = source_inventory(root, files)
    return {
        "schema_version": SCHEMA_VERSION,
        "scope": "DeltaAegis v0.45.0 Telemetry Trust release candidate",
        "inventory": inventory,
        "findings": findings(inventory),
        "constraints": [
            "The audit is read-only except when explicitly writing its deterministic Markdown report.",
            "Counts use Git cached and non-ignored untracked candidate files and exclude runtime data roots and the generated report.",
            "v0.45.0 adds deterministic telemetry-quality decisions, immutable decision and review ledgers, state-aware ingestion effects, replayable current-state projection, and authenticated quality review while preserving the v0.44 modular boundaries.",
            "Historical validator retirement is allowed only when exact prior bytes remain verified at an immutable release tag, current behavior has replacement-contract evidence, and the retained execution graph is complete.",
        ],
    }


def markdown_list(values: list[str]) -> str:
    return ", ".join(f"`{value}`" for value in values) if values else "None"


def render_markdown(audit: dict[str, Any]) -> str:
    inv = audit["inventory"]
    lines = [
        "# DeltaAegis v0.45.0 Repository Audit", "",
        f"Schema: `{audit['schema_version']}`", "",
        "This deterministic inventory describes the v0.45.0 Telemetry Trust release candidate. Regenerate it with `python3 tools/audit_v0_44_repository.py --write`.", "",
        "## Inventory summary", "", "| Measure | Count |", "|---|---:|",
        f"| Repository files in audit scope | {inv['file_count']} |",
        f"| `deltaaegis.py` lines | {inv['source_lines']} |",
        f"| Root top-level functions | {inv['top_level_functions']} |",
        f"| Root top-level classes | {inv['top_level_classes']} |",
        f"| Internal core modules | {len(inv['core_modules'])} |",
        f"| Distinct CLI commands | {len(inv['cli_commands'])} |",
        f"| Distinct `/api` route literals | {len(inv['api_routes'])} |",
        f"| Declared schema tables | {len(inv['schema_tables'])} |",
        f"| Validator scripts | {len(inv['validator_files'])} |",
        f"| Validator version groups | {len(inv['validator_versions'])} |", "",
        f"Root source SHA-256: `{inv['source_sha256']}`", "",
        "## Modular core inventory", "",
        "| Module | Lines | Functions | Classes | Internal dependencies | SHA-256 |",
        "|---|---:|---:|---:|---|---|",
    ]
    for item in inv["core_modules"]:
        deps = markdown_list(item["internal_dependencies"])
        lines.append(f"| `{item['path']}` | {item['lines']} | {item['functions']} | {item['classes']} | {deps} | `{item['sha256']}` |")
    lines.extend(["", "Forbidden imports of the root `deltaaegis` module from internal core modules: " + (markdown_list(inv["forbidden_root_imports"]) if inv["forbidden_root_imports"] else "None detected."), ""])

    lines.extend(["## Findings and disposition", "", "| ID | Severity | Area | Evidence | Planned disposition |", "|---|---|---|---|---|"])
    for finding in audit["findings"]:
        lines.append(f"| {finding['id']} | {finding['severity']} | {finding['area']} | {finding['evidence']} | {finding['disposition']} |")

    lines.extend(["", "## Duplicate root definitions", ""])
    duplicates = inv["duplicate_top_level_functions"]
    if duplicates:
        lines.extend(["| Name | Definition lines |", "|---|---|"])
        for name, numbers in duplicates.items():
            lines.append(f"| `{name}` | {', '.join(str(number) for number in numbers)} |")
    else:
        lines.append("None detected.")

    lines.extend([
        "", "## Command, route, and schema catalogs", "",
        f"### CLI commands ({len(inv['cli_commands'])})", "", markdown_list(inv["cli_commands"]), "",
        f"### API route literals ({len(inv['api_routes'])})", "", markdown_list(inv["api_routes"]), "",
        f"### Schema tables ({len(inv['schema_tables'])})", "", markdown_list(inv["schema_tables"]), "",
        "## Validator inventory", "", "| Version group | Scripts |", "|---|---:|",
    ])
    for version, count in inv["validator_versions"].items():
        lines.append(f"| {version} | {count} |")

    retirement = inv.get("validator_retirement")
    lines.extend(["", "## Validator retirement evidence", ""])
    if retirement:
        lines.extend([
            "- Manifest: `docs/v0.44.1-validator-retirement.json`",
            f"- Archive tag: `{retirement.get('archive_tag')}`",
            f"- Retired tool files: {retirement.get('retired_file_count')}",
            f"- Retired validator scripts: {retirement.get('retired_validator_count')}",
            f"- Retained validator scripts: {retirement.get('expected_retained_validator_count')}",
            f"- Retained shell-validator inventory: {retirement.get('expected_shell_validator_count')}",
            f"- Replacement report contract: `{retirement.get('replacement_contract')}`",
            "- Policy: `docs/validation-retention-policy.md`",
        ])
    else:
        lines.append("No validator-retirement manifest is present.")

    lines.extend(["", "## Stale and historical documents", ""])
    if inv["stale_documents"]:
        lines.extend(["| Path | Evidence | Disposition |", "|---|---|---|"])
        for item in inv["stale_documents"]:
            lines.append(f"| `{item['path']}` | {item['reason']} | {item['disposition']} |")
    else:
        lines.append("No known stale architecture-document marker was found.")

    lines.extend([
        "", "## Deferred work map", "", "| Release | Owned work after v0.44 |", "|---|---|",
        "| v0.46+ | Remaining migration-ledger, supported-upgrade, and backup-integrated recovery work not delivered by v0.45.0 |",
        "| v0.46 | `/api/v1`, OpenAPI, CSRF, sessions/tokens, and web security headers |",
        "| v0.47 | Sensor/scope identity and overlapping CIDRs |",
        "| v0.48 | Versioned deterministic detection rules |",
        "| v0.49 | Health/readiness, diagnostics, performance targets, failure tests, and soak |",
        "", "## Audit constraints", "",
    ])
    lines.extend(f"- {item}" for item in audit["constraints"])
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", help="DeltaAegis repository root")
    parser.add_argument("--json", action="store_true", help="Print structured audit JSON")
    parser.add_argument("--write", action="store_true", help=f"Write {REPORT_PATH}")
    parser.add_argument("--check", action="store_true", help="Fail if the tracked report is stale")
    args = parser.parse_args()
    root = repository_root(args.repo)
    audit = build_audit(root)
    rendered = render_markdown(audit)
    if args.write:
        output = root / REPORT_PATH
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        print(f"WROTE: {output}")
    if args.check:
        output = root / REPORT_PATH
        if not output.is_file():
            print(f"FAIL: missing {REPORT_PATH}", file=sys.stderr)
            return 1
        if output.read_text(encoding="utf-8") != rendered:
            print(f"FAIL: {REPORT_PATH} is stale; run this tool with --write", file=sys.stderr)
            return 1
        print(f"PASS: {REPORT_PATH} matches the deterministic audit")
    if args.json:
        print(json.dumps(audit, indent=2, sort_keys=True))
    elif not args.write and not args.check:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
