#!/usr/bin/env python3
"""Validate DeltaAegis v0.43.0 source, release, and gate metadata."""

from __future__ import annotations

import ast
import hashlib
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ALLOWED_BRANCHES = {"feature/v0.43-architecture-stability-baseline", "main"}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def read(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file():
        fail(f"missing required release file: {relative}")
    return path.read_text(encoding="utf-8")


def main() -> int:
    print("DeltaAegis v0.43 Release Metadata Validator")
    print("=============================================")

    branch = subprocess.run(
        ["git", "-C", str(ROOT), "branch", "--show-current"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if branch not in ALLOWED_BRANCHES:
        fail(f"unsupported v0.43 release branch: {branch}")

    source = read("deltaaegis.py")
    tree = ast.parse(source, filename="deltaaegis.py")
    assignments = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = node.value.value
    if assignments.get("DELTAAEGIS_VERSION") != "0.43.0":
        fail("DELTAAEGIS_VERSION is not 0.43.0")
    if not (ast.get_docstring(tree, clean=False) or "").startswith(
        "DeltaAegis v0.43.0: Architecture and Stability Baseline."
    ):
        fail("module docstring does not identify the v0.43.0 release")

    for marker in (
        'DELTAAEGIS_VERSION = "0.43.0"',
        'server_version = "DeltaAegisDashboard/0.43.0"',
        "DeltaAegis v0.43.0 — Architecture and Stability Baseline",
        "v0.43 Architecture and Stability Baseline",
        "SPDX-License-Identifier: AGPL-3.0-only",
        'data-deltaaegis-license="AGPL-3.0-only"',
    ):
        if marker not in source:
            fail(f"deltaaegis.py is missing release marker: {marker}")

    help_text = subprocess.run(
        [sys.executable, str(ROOT / "deltaaegis.py"), "--help"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if "DeltaAegis v0.43.0 — Architecture and Stability Baseline" not in help_text:
        fail("CLI help does not identify v0.43.0")

    readme = read("README.md")
    changelog = read("CHANGELOG.md")
    for marker in (
        "## Current Release — v0.43.0",
        "**DeltaAegis v0.43.0 — Architecture and Stability Baseline**",
        "tools/validate_v0_43_release_gate.sh",
        "AGPL-3.0-only",
    ):
        if marker not in readme:
            fail(f"README is missing release marker: {marker}")
    if not changelog.startswith("## DeltaAegis v0.43.0 — Architecture and Stability Baseline"):
        fail("CHANGELOG top release is not v0.43.0")

    approved_license = "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0"
    if hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest() != approved_license:
        fail("LICENSE is not the approved AGPL-3.0 text")

    required_files = (
        "V1_SCOPE.md",
        "SUPPORTED_VERSIONS.md",
        "CONTRIBUTING.md",
        "docs/architecture/overview.md",
        "docs/repository-audit.md",
        "docs/performance-baseline.md",
        "docs/performance-baseline.json",
        "tools/audit_v0_43_repository.py",
        "tools/benchmark_v0_43.py",
        "tools/validate_v0_43_baseline.py",
        "tools/validate_v0_43_documentation.py",
        "tools/validate_v0_43_release_metadata.py",
        "tools/validate_v0_43_v0_42_compatibility.py",
        "tools/validate_v0_43_release_gate.sh",
    )
    for relative in required_files:
        if not (ROOT / relative).is_file():
            fail(f"release inventory is missing: {relative}")

    decisions = sorted((ROOT / "docs/architecture/decisions").glob("[0-9][0-9][0-9][0-9]-*.md"))
    if len(decisions) != 9:
        fail(f"release inventory requires nine ADRs, found {len(decisions)}")

    gate = read("tools/validate_v0_43_release_gate.sh")
    gate_invocations = (
        "python3 tools/validate_v0_43_baseline.py",
        "python3 tools/validate_v0_43_documentation.py",
        "python3 tools/validate_v0_43_release_metadata.py",
        "python3 tools/validate_v0_43_v0_42_compatibility.py",
    )
    for invocation in gate_invocations:
        if gate.count(invocation) != 1:
            fail(f"release gate must invoke exactly once: {invocation}")
    for marker in (
        "feature/v0.43-architecture-stability-baseline|main",
        "git status --short",
        "git diff --check",
        "Parker's explicit approval",
    ):
        if marker not in gate:
            fail(f"release gate is missing policy marker: {marker}")
    if "validate_v0_43_baseline_all.sh" in gate:
        fail("release gate must invoke the baseline validator directly, not through its checkpoint wrapper")

    individual_validators = (
        "tools/validate_v0_43_baseline.py",
        "tools/validate_v0_43_documentation.py",
        "tools/validate_v0_43_release_metadata.py",
        "tools/validate_v0_43_v0_42_compatibility.py",
    )
    for relative in individual_validators:
        validator_tree = ast.parse(read(relative), filename=relative)
        nested = []
        for node in ast.walk(validator_tree):
            if not isinstance(node, ast.Call):
                continue
            function_name = ""
            if isinstance(node.func, ast.Name):
                function_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                function_name = node.func.attr
            if function_name not in {"run", "Popen", "check_call", "check_output"}:
                continue
            for child in ast.walk(node):
                if (
                    isinstance(child, ast.Constant)
                    and isinstance(child.value, str)
                    and child.value.startswith("tools/validate_v0_43_")
                ):
                    nested.append(child.value)
        if nested:
            fail(f"focused v0.43 validator is not flat: {relative}: {nested}")

    tracked_manual = subprocess.run(
        [
            "git",
            "-C",
            str(ROOT),
            "ls-files",
            "--",
            "RELEASE_CHECKLIST.md",
            "RELEASE_NOTES_v*.md",
            "MANUAL_VERIFICATION_v*.md",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    if tracked_manual:
        fail("manual/version-specific release documents remain tracked")

    print("PASS: v0.43.0 source, CLI, dashboard, README, and CHANGELOG metadata")
    print("PASS: complete architecture-baseline release inventory")
    print("PASS: flat focused-validator composition and feature/main paths")
    print("PASS: explicit approval hold and operator-managed release verification")
    print("PASS: DeltaAegis v0.43 release metadata")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
