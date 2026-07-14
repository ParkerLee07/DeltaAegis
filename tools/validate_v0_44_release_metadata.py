#!/usr/bin/env python3
"""Validate DeltaAegis v0.44.0 source, release, and gate metadata."""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_BRANCHES = {"feature/v0.44-module-boundary-extraction", "main"}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def read(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file():
        fail(f"missing required release file: {relative}")
    return path.read_text(encoding="utf-8")


def main() -> int:
    print("DeltaAegis v0.44 Release Metadata Validator")
    print("=============================================")
    branch = subprocess.run(
        ["git", "-C", str(ROOT), "branch", "--show-current"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if branch not in ALLOWED_BRANCHES:
        fail(f"unsupported v0.44 release branch: {branch}")

    source = read("deltaaegis.py")
    tree = ast.parse(source, filename="deltaaegis.py")
    assignments = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = node.value.value
    if assignments.get("DELTAAEGIS_VERSION") != "0.44.0":
        fail("DELTAAEGIS_VERSION is not 0.44.0")
    if not (ast.get_docstring(tree, clean=False) or "").startswith("DeltaAegis v0.44.0: Modular Core Foundation."):
        fail("module docstring does not identify v0.44.0")
    for marker in (
        'DELTAAEGIS_VERSION = "0.44.0"',
        "DeltaAegis v0.44.0 — Modular Core Foundation",
        "v0.44 Modular Core Foundation",
        "SPDX-License-Identifier: AGPL-3.0-only",
        'data-deltaaegis-license="AGPL-3.0-only"',
    ):
        if marker not in source:
            fail(f"deltaaegis.py is missing release marker: {marker}")
    web = read("deltaaegis_core/web.py")
    if 'server_version = "DeltaAegisDashboard/0.44.0"' not in web:
        fail("dashboard server version is not 0.44.0")

    help_text = subprocess.run(
        [sys.executable, str(ROOT / "deltaaegis.py"), "--help"],
        check=True, capture_output=True, text=True,
    ).stdout
    if "DeltaAegis v0.44.0 — Modular Core Foundation" not in help_text:
        fail("CLI help does not identify v0.44.0")

    release = json.loads(read("docs/v0.44-release-characterization.json"))
    if release.get("source_checkpoint") != "b5dc440079278a01d7ecea0c4b588663a495d52c":
        fail("release hardening is not pinned to the Stage 8 checkpoint")
    if release.get("base_tag_target") != "6061b0cdee43e076b662fe85b3e8e92672c64206":
        fail("v0.43.0 base tag target changed")
    if release.get("schema_change") is not False or release.get("operator_workflow_change") is not False:
        fail("release metadata overclaims behavior or schema changes")

    required_files = (
        "docs/v0.44-release-characterization.json",
        "tools/audit_v0_44_repository.py",
        "tools/validate_v0_44_architecture.py",
        "tools/validate_v0_44_documentation.py",
        "tools/validate_v0_44_release_metadata.py",
        "tools/validate_v0_44_release_gate.sh",
    )
    for relative in required_files:
        if not (ROOT / relative).is_file():
            fail(f"release inventory is missing: {relative}")

    decisions = sorted((ROOT / "docs/architecture/decisions").glob("[0-9][0-9][0-9][0-9]-*.md"))
    if len(decisions) != 10:
        fail(f"v0.44 release inventory requires ten ADRs, found {len(decisions)}")

    gate = read("tools/validate_v0_44_release_gate.sh")
    invocations = (
        "python3 tools/validate_v0_44_stage1_2.py",
        "python3 tools/validate_v0_44_stage3_auth.py",
        "python3 tools/validate_v0_44_stage4_ingest.py",
        "python3 tools/validate_v0_44_stage5_7.py",
        "python3 tools/validate_v0_44_stage8_web.py",
        "python3 tools/validate_v0_44_architecture.py",
        "python3 tools/audit_v0_44_repository.py --check",
        "python3 tools/validate_v0_44_documentation.py",
        "python3 tools/validate_v0_44_release_metadata.py",
        "python3 tools/validate_v0_43_v0_42_compatibility.py",
    )
    for invocation in invocations:
        if gate.count(invocation) != 1:
            fail(f"release gate must invoke exactly once: {invocation}")
    for marker in (
        "feature/v0.44-module-boundary-extraction|main",
        "git status --short", "git diff --check", "Parker's explicit approval",
    ):
        if marker not in gate:
            fail(f"release gate is missing policy marker: {marker}")
    for wrapper in (
        "validate_v0_44_stage1_2_all.sh", "validate_v0_44_stage3_all.sh",
        "validate_v0_44_stage4_all.sh", "validate_v0_44_stage5_7_all.sh",
        "validate_v0_44_stage8_all.sh",
    ):
        if wrapper in gate:
            fail(f"release gate must compose focused validators directly, not {wrapper}")

    for relative in (
        "tools/validate_v0_44_architecture.py",
        "tools/validate_v0_44_documentation.py",
    ):
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
                    and child.value.startswith("tools/validate_v0_44_")
                ):
                    nested.append(child.value)
        if nested:
            fail(f"focused validator contains nested v0.44 validator invocation: {relative}: {nested}")

    for wrapper in (
        "tools/validate_v0_44_stage1_2_all.sh",
        "tools/validate_v0_44_stage3_all.sh",
        "tools/validate_v0_44_stage4_all.sh",
        "tools/validate_v0_44_stage5_7_all.sh",
        "tools/validate_v0_44_stage8_all.sh",
    ):
        content = read(wrapper)
        if "python3 tools/audit_v0_44_repository.py --check" not in content:
            fail(f"checkpoint gate does not use the v0.44 audit: {wrapper}")
        if "python3 tools/audit_v0_43_repository.py --check" in content:
            fail(f"checkpoint gate still uses the v0.43 audit: {wrapper}")

    approved_license = "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0"
    if hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest() != approved_license:
        fail("LICENSE is not the approved AGPL-3.0 text")

    if "0.43.0" not in read("tools/validate_v0_43_release_metadata.py"):
        fail("historical v0.43 release validator was rewritten")
    if json.loads(read("docs/v0.44-stage1-2-characterization.json")).get("source_release") != "0.43.0":
        fail("historical source-release characterization was rewritten")

    tracked_manual = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--", "RELEASE_CHECKLIST.md", "RELEASE_NOTES_v*.md", "MANUAL_VERIFICATION_v*.md"],
        check=True, capture_output=True, text=True,
    ).stdout.splitlines()
    if tracked_manual:
        fail("manual/version-specific release documents remain tracked")

    print("PASS: v0.44.0 source, CLI, dashboard, and characterization metadata")
    print("PASS: complete modular-core release inventory and ten ADRs")
    print("PASS: flat focused-validator composition and feature/main paths")
    print("PASS: historical v0.43 evidence and AGPL licensing boundary preserved")
    print("PASS: explicit approval hold and operator-managed release verification")
    print("PASS: DeltaAegis v0.44 release metadata")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
