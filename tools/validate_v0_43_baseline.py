#!/usr/bin/env python3
"""Focused validator for DeltaAegis v0.43 checkpoints 1 through 5."""

from __future__ import annotations

import ast
import json
import py_compile
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def require_file(relative: str) -> Path:
    path = ROOT / relative
    if not path.is_file():
        fail(f"missing required file: {relative}")
    return path


def require_markers(relative: str, markers: list[str]) -> str:
    text = require_file(relative).read_text(encoding="utf-8")
    missing = [marker for marker in markers if marker not in text]
    if missing:
        fail(f"{relative} is missing marker(s): {', '.join(missing)}")
    return text


def run(command: list[str], *, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def validate_unchanged_runtime() -> None:
    source = require_file("deltaaegis.py").read_text(encoding="utf-8")
    tree = ast.parse(source, filename="deltaaegis.py")
    version = None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(isinstance(target, ast.Name) and target.id == "DELTAAEGIS_VERSION" for target in node.targets):
                if isinstance(node.value, ast.Constant):
                    version = node.value.value
                break
    if version != "0.42.2":
        fail(f"stages 1-5 must observe the unchanged v0.42.2 runtime, found {version!r}")
    diff = run(["git", "diff", "--", "deltaaegis.py"])
    cached = run(["git", "diff", "--cached", "--", "deltaaegis.py"])
    if diff.returncode or cached.returncode:
        fail("could not verify deltaaegis.py Git state")
    if diff.stdout or cached.stdout:
        fail("stages 1-5 must not modify deltaaegis.py")
    print("PASS: unchanged v0.42.2 runtime boundary")


def validate_repository_audit() -> None:
    require_file("tools/audit_v0_43_repository.py")
    require_markers(
        "docs/repository-audit.md",
        [
            "deltaaegis-repository-audit-v1",
            "DA043-001",
            "DA043-007",
            "## Duplicate top-level definitions",
            "## Deferred work map",
        ],
    )
    completed = run([sys.executable, "tools/audit_v0_43_repository.py", "--check"])
    if completed.returncode:
        fail((completed.stdout + completed.stderr).strip())
    print("PASS: deterministic repository inventory and audit report")


def validate_scope_and_support() -> None:
    require_markers(
        "V1_SCOPE.md",
        [
            "## v1.0 promises",
            "### Stable storage and upgrades",
            "### Stable API",
            "### Identity and evidence",
            "### Deterministic detection",
            "### Security",
            "### Operations and recovery",
            "## Explicit v1.0 exclusions",
            "## Definition of done",
        ],
    )
    require_markers(
        "SUPPORTED_VERSIONS.md",
        [
            "Debian 12 and 13",
            "Ubuntu 22.04 LTS and 24.04 LTS",
            "CPython 3.10 through 3.14",
            "SQLite",
            "NetSniper",
            "v2.0.0",
            "TrueAegis",
            "Node.js",
            "Browser",
            "## Unsupported configurations",
        ],
    )
    require_markers(
        "CONTRIBUTING.md",
        [
            "## Validation expectations",
            "## Review priorities",
            "## Licensing boundary",
            "does not add a contributor agreement",
        ],
    )
    print("PASS: v1.0 scope, support matrix, and contribution governance")


def validate_architecture() -> None:
    require_markers(
        "docs/architecture/overview.md",
        [
            "## Current repository components",
            "## Runtime process model",
            "## Storage model",
            "## Evidence flow and trust boundaries",
            "## Current API boundary",
            "## v0.44 extraction map",
            "## Architecture decision index",
            "NetSniper",
            "TrueAegis",
            "SQLite",
        ],
    )
    decision_dir = ROOT / "docs/architecture/decisions"
    decisions = sorted(decision_dir.glob("[0-9][0-9][0-9][0-9]-*.md"))
    expected = [f"{number:04d}" for number in range(1, 10)]
    actual = [path.name[:4] for path in decisions]
    if actual != expected:
        fail(f"expected ADR sequence {expected}, found {actual}")
    required_sections = ["- Status: Accepted", "- Date:", "- Applies to:", "## Context", "## Decision", "## Consequences"]
    for path in decisions:
        text = path.read_text(encoding="utf-8")
        missing = [section for section in required_sections if section not in text]
        if missing:
            fail(f"{path.relative_to(ROOT)} is missing {', '.join(missing)}")
    combined = "\n".join(path.read_text(encoding="utf-8") for path in decisions)
    for topic in ("SQLite", "migration", "/api/v1", "sensor_id", "authentication", "durable job", "backup", "compatibility", "deprecation"):
        if topic.casefold() not in combined.casefold():
            fail(f"ADR set does not cover required topic: {topic}")
    print("PASS: architecture map and complete, non-conflicting ADR set")


def validate_performance() -> None:
    data_path = require_file("docs/performance-baseline.json")
    require_markers(
        "docs/performance-baseline.md",
        [
            "deltaaegis-performance-baseline-v1",
            "## Environment",
            "## Synthetic fixture",
            "## Measurements",
            "## Method",
            "Release-gate status: `passed`",
            "Real operator data used: **no**",
        ],
    )
    try:
        data = json.loads(data_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid performance baseline JSON: {exc}")
    if data.get("schema_version") != "deltaaegis-performance-baseline-v1":
        fail("unexpected performance baseline schema")
    if data.get("mode") != "full":
        fail("tracked performance baseline must use full mode")
    if data.get("fixture", {}).get("real_operator_data_used") is not False:
        fail("performance baseline must use synthetic data only")
    measurements = data.get("measurements") or {}
    required = {
        "cold_module_import",
        "fresh_schema_initialization",
        "synthetic_database_bytes",
        "dashboard_summary_payload",
        "dashboard_assets_payload",
        "markdown_report_generation_ms",
        "release_gate",
    }
    if required - set(measurements):
        fail("performance baseline is missing required measurements")
    if measurements.get("sqlite_integrity_check") != "ok":
        fail("baseline SQLite integrity evidence is not ok")
    if measurements.get("sqlite_foreign_key_violations") != 0:
        fail("baseline contains SQLite foreign-key violations")
    if measurements.get("release_gate", {}).get("status") != "passed":
        fail("complete predecessor release-gate baseline did not pass")
    self_test = run([sys.executable, "tools/benchmark_v0_43.py", "--self-test"], timeout=240)
    if self_test.returncode:
        fail("benchmark self-test failed:\n" + (self_test.stdout + self_test.stderr)[-5000:])
    print("PASS: reproducible synthetic performance and release-gate baseline")


def validate_hygiene() -> None:
    scripts = [
        "tools/audit_v0_43_repository.py",
        "tools/benchmark_v0_43.py",
        "tools/validate_v0_43_baseline.py",
    ]
    for relative in scripts:
        try:
            py_compile.compile(str(require_file(relative)), doraise=True)
        except py_compile.PyCompileError as exc:
            fail(f"Python syntax failure in {relative}: {exc}")
    diff_check = run(["git", "diff", "--check"])
    if diff_check.returncode:
        fail("Git whitespace check failed:\n" + diff_check.stdout + diff_check.stderr)
    release_note_candidates = list(ROOT.glob("*v0.43*Release*Notes*")) + list(ROOT.glob("*v0.43*CHECKLIST*"))
    if release_note_candidates:
        fail("tracked version-specific release notes/checklists are not allowed")
    print("PASS: syntax, repository hygiene, and release-document policy")


def main() -> int:
    print("DeltaAegis v0.43 Architecture and Stability Baseline Validator")
    print("================================================================")
    validate_unchanged_runtime()
    validate_scope_and_support()
    validate_architecture()
    validate_performance()
    validate_repository_audit()
    validate_hygiene()
    print("PASS: DeltaAegis v0.43 checkpoints 1 through 5")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
