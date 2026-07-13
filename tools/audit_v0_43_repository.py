#!/usr/bin/env python3
"""Read-only, deterministic DeltaAegis v0.43 repository inventory."""

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


SCHEMA_VERSION = "deltaaegis-repository-audit-v1"
REPORT_PATH = Path("docs/repository-audit.md")
EXCLUDED_PARTS = {
    ".git",
    "__pycache__",
    "backups",
    "data",
    "events",
    "reports",
    "restore-rehearsals",
    "scan-logs",
    "trueaegis-logs",
}
TEXT_SUFFIXES = {
    ".css",
    ".html",
    ".js",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".txt",
    ".yaml",
    ".yml",
}


def repository_root(value: str | None = None) -> Path:
    root = Path(value).expanduser() if value else Path(__file__).resolve().parents[1]
    root = root.resolve()
    if not (root / "deltaaegis.py").is_file():
        raise SystemExit(f"not a DeltaAegis repository: {root}")
    return root


def relative_files(root: Path) -> list[Path]:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
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


def string_literals(tree: ast.AST) -> Iterable[tuple[str, int]]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.value, getattr(node, "lineno", 0)


def call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def top_level_imports(tree: ast.Module) -> list[str]:
    modules: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module.split(".", 1)[0])
    return sorted(modules)


def command_names(tree: ast.AST) -> list[str]:
    commands: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or call_name(node.func) != "add_parser":
            continue
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            commands.add(node.args[0].value)
    return sorted(commands)


def source_inventory(root: Path, files: list[Path]) -> dict[str, Any]:
    source = read_text(root, Path("deltaaegis.py"))
    tree = ast.parse(source, filename="deltaaegis.py")
    functions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    definitions: dict[str, list[int]] = defaultdict(list)
    for node in functions:
        definitions[node.name].append(node.lineno)
    duplicates = {name: lines for name, lines in sorted(definitions.items()) if len(lines) > 1}

    routes: set[str] = set()
    for value, _ in string_literals(tree):
        for match in re.findall(r"/api/[A-Za-z0-9_{}?=&./:-]+", value):
            route = match.split("?", 1)[0].rstrip("/.,);`'\"")
            if route:
                routes.add(route)

    tables = sorted(
        set(
            re.findall(
                r"CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+[`\"']?([A-Za-z_][A-Za-z0-9_]*)",
                source,
                flags=re.IGNORECASE,
            )
        )
    )

    suffix_counts = Counter((rel.suffix.lower() or "[none]") for rel in files)
    line_counts: dict[str, int] = {}
    for rel in files:
        if rel.suffix.lower() in TEXT_SUFFIXES:
            text = read_text(root, rel)
            line_counts[rel.as_posix()] = len(text.splitlines())

    validators = [rel.as_posix() for rel in files if rel.parts[0:1] == ("tools",) and rel.name.startswith("validate")]
    validator_versions = Counter()
    for name in validators:
        match = re.search(r"validate_v(\d+)_(\d+)", Path(name).name)
        validator_versions[f"v{match.group(1)}.{match.group(2)}" if match else "unversioned"] += 1

    stale_docs: list[dict[str, str]] = []
    legacy_arch = root / "docs/architecture.md"
    if legacy_arch.is_file() and "v0.8.5" in legacy_arch.read_text(encoding="utf-8", errors="replace"):
        stale_docs.append(
            {
                "path": "docs/architecture.md",
                "reason": "Historical v0.8.5 architecture narrative; superseded as the current map by docs/architecture/overview.md.",
                "disposition": "Retain as historical context until v0.44 decides whether to archive or merge it.",
            }
        )

    sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
    return {
        "source_sha256": sha,
        "source_lines": len(source.splitlines()),
        "top_level_functions": len(functions),
        "top_level_classes": len(classes),
        "duplicate_top_level_functions": duplicates,
        "cli_commands": command_names(tree),
        "api_routes": sorted(routes),
        "schema_tables": tables,
        "top_level_imports": top_level_imports(tree),
        "file_count": len(files),
        "file_suffix_counts": dict(sorted(suffix_counts.items())),
        "text_line_counts": dict(sorted(line_counts.items())),
        "validator_files": validators,
        "validator_versions": dict(sorted(validator_versions.items())),
        "stale_documents": stale_docs,
    }


def findings(inventory: dict[str, Any]) -> list[dict[str, str]]:
    duplicate_names = ", ".join(inventory["duplicate_top_level_functions"]) or "none"
    return [
        {
            "id": "DA043-001",
            "severity": "HIGH",
            "area": "module boundaries",
            "evidence": f"deltaaegis.py has {inventory['source_lines']} lines and {inventory['top_level_functions']} top-level functions.",
            "disposition": "Map and incrementally extract responsibilities in v0.44; do not perform a broad v0.43 rewrite.",
        },
        {
            "id": "DA043-002",
            "severity": "HIGH",
            "area": "source-order coupling",
            "evidence": f"Repeated top-level function names: {duplicate_names}.",
            "disposition": "Preserve behavior with characterization tests, then remove late overrides during owned v0.44 extractions.",
        },
        {
            "id": "DA043-003",
            "severity": "MEDIUM",
            "area": "storage ownership",
            "evidence": f"{len(inventory['schema_tables'])} table names are declared from the monolithic source bootstrap/migration path.",
            "disposition": "Introduce the migration ledger in v0.45 after the v0.44 database boundary is extracted.",
        },
        {
            "id": "DA043-004",
            "severity": "MEDIUM",
            "area": "HTTP/API ownership",
            "evidence": f"{len(inventory['api_routes'])} distinct /api route literals occur in the application source.",
            "disposition": "Inventory current routes now; introduce the stable /api/v1 contract in v0.46.",
        },
        {
            "id": "DA043-005",
            "severity": "MEDIUM",
            "area": "validation estate",
            "evidence": f"{len(inventory['validator_files'])} validator scripts span {len(inventory['validator_versions'])} version groups.",
            "disposition": "Record contract ownership before retiring any validator; the v0.43 gate must compose focused validators exactly once.",
        },
        {
            "id": "DA043-006",
            "severity": "MEDIUM",
            "area": "documentation",
            "evidence": f"{len(inventory['stale_documents'])} known stale current-architecture document was identified.",
            "disposition": "Use docs/architecture/overview.md as current authority and reconcile historical prose during v0.44.",
        },
        {
            "id": "DA043-007",
            "severity": "MEDIUM",
            "area": "TrueAegis compatibility",
            "evidence": "TrueAegis is enforced by an execution/output contract but has no pinned semantic-version range in the current repository.",
            "disposition": "Publish or pin a TrueAegis semantic version and fixture contract before DeltaAegis v1.0.",
        },
    ]


def build_audit(root: Path) -> dict[str, Any]:
    files = relative_files(root)
    inventory = source_inventory(root, files)
    return {
        "schema_version": SCHEMA_VERSION,
        "scope": "DeltaAegis v0.43.0 architecture and stability release candidate",
        "inventory": inventory,
        "findings": findings(inventory),
        "constraints": [
            "No runtime source or database schema is changed by this audit.",
            "Counts use Git cached and non-ignored untracked candidate files, excluding runtime data roots and this generated report.",
            "A finding is architecture debt unless a focused defect reproduction proves otherwise.",
            "No historical validator is removed without replacement-contract evidence.",
        ],
    }


def markdown_list(values: list[str]) -> str:
    return ", ".join(f"`{value}`" for value in values) if values else "None"


def render_markdown(audit: dict[str, Any]) -> str:
    inv = audit["inventory"]
    lines = [
        "# DeltaAegis v0.43 Repository Audit",
        "",
        f"Schema: `{audit['schema_version']}`",
        "",
        "This is a deterministic, read-only inventory of the v0.43.0 release candidate and its architecture-baseline artifacts. Regenerate it with `python3 tools/audit_v0_43_repository.py --write`.",
        "",
        "## Inventory summary",
        "",
        "| Measure | Count |",
        "|---|---:|",
        f"| Repository files in audit scope | {inv['file_count']} |",
        f"| `deltaaegis.py` lines | {inv['source_lines']} |",
        f"| Top-level functions | {inv['top_level_functions']} |",
        f"| Top-level classes | {inv['top_level_classes']} |",
        f"| Distinct CLI commands | {len(inv['cli_commands'])} |",
        f"| Distinct `/api` route literals | {len(inv['api_routes'])} |",
        f"| Declared schema tables | {len(inv['schema_tables'])} |",
        f"| Validator scripts | {len(inv['validator_files'])} |",
        f"| Validator version groups | {len(inv['validator_versions'])} |",
        "",
        f"Source SHA-256: `{inv['source_sha256']}`",
        "",
        "## Findings and disposition",
        "",
        "| ID | Severity | Area | Evidence | Planned disposition |",
        "|---|---|---|---|---|",
    ]
    for finding in audit["findings"]:
        lines.append(
            f"| {finding['id']} | {finding['severity']} | {finding['area']} | "
            f"{finding['evidence']} | {finding['disposition']} |"
        )

    lines.extend(["", "## Duplicate top-level definitions", ""])
    duplicates = inv["duplicate_top_level_functions"]
    if duplicates:
        lines.extend(["| Name | Definition lines |", "|---|---|"])
        for name, numbers in duplicates.items():
            lines.append(f"| `{name}` | {', '.join(str(number) for number in numbers)} |")
    else:
        lines.append("None detected.")

    lines.extend(
        [
            "",
            "These definitions are classified as source-order coupling. The audit does not assume that the earlier definitions are unreachable or safe to delete.",
            "",
            "## Command, route, and schema catalogs",
            "",
            f"### CLI commands ({len(inv['cli_commands'])})",
            "",
            markdown_list(inv["cli_commands"]),
            "",
            f"### API route literals ({len(inv['api_routes'])})",
            "",
            markdown_list(inv["api_routes"]),
            "",
            f"### Schema tables ({len(inv['schema_tables'])})",
            "",
            markdown_list(inv["schema_tables"]),
            "",
            "## Validator inventory",
            "",
            "| Version group | Scripts |",
            "|---|---:|",
        ]
    )
    for version, count in inv["validator_versions"].items():
        lines.append(f"| {version} | {count} |")

    lines.extend(["", "## Stale and historical documents", ""])
    if inv["stale_documents"]:
        lines.extend(["| Path | Evidence | Disposition |", "|---|---|---|"])
        for item in inv["stale_documents"]:
            lines.append(f"| `{item['path']}` | {item['reason']} | {item['disposition']} |")
    else:
        lines.append("No known stale architecture document marker was found.")

    lines.extend(
        [
            "",
            "## Dependency surface",
            "",
            "Top-level Python imports: " + markdown_list(inv["top_level_imports"]),
            "",
            "The runtime remains standard-library based. NetSniper, TrueAegis, Node.js, Git, browsers, and supported platform expectations are defined in `SUPPORTED_VERSIONS.md`.",
            "",
            "## Deferred work map",
            "",
            "| Release | Owned work from this audit |",
            "|---|---|",
            "| v0.44 | Incremental module extraction and removal of characterized source-order overrides |",
            "| v0.45 | Migration ledger, supported upgrades, and backup-integrated recovery |",
            "| v0.46 | `/api/v1`, OpenAPI, CSRF, sessions/tokens, and web security headers |",
            "| v0.47 | Sensor/scope identity and overlapping CIDRs |",
            "| v0.48 | Versioned deterministic detection rules |",
            "| v0.49 | Health/readiness, diagnostics, performance targets, failure tests, and soak |",
            "",
            "## Audit constraints",
            "",
        ]
    )
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
