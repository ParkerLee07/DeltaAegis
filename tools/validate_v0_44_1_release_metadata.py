#!/usr/bin/env python3
"""Validate DeltaAegis v0.44.1 maintenance release metadata and gate composition."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_BRANCHES = {"maintenance/v0.44.1-repository-hygiene", "main"}
TITLE = "DeltaAegis v0.44.1 — Repository Hygiene and Validation Retention"


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def read(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file():
        fail(f"missing required maintenance file: {relative}")
    return path.read_text(encoding="utf-8")


def main() -> int:
    print("DeltaAegis v0.44.1 Release Metadata Validator")
    print("================================================")

    branch = subprocess.run(
        ["git", "-C", str(ROOT), "branch", "--show-current"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if branch not in ALLOWED_BRANCHES:
        fail(f"unsupported v0.44.1 release branch: {branch}")

    source = read("deltaaegis.py")
    tree = ast.parse(source, filename="deltaaegis.py")
    assignments = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = node.value.value
    if assignments.get("DELTAAEGIS_VERSION") != "0.44.1":
        fail("DELTAAEGIS_VERSION is not 0.44.1")
    if not (ast.get_docstring(tree, clean=False) or "").startswith(
        "DeltaAegis v0.44.1: Repository Hygiene and Validation Retention."
    ):
        fail("module docstring does not identify v0.44.1")
    for marker in (
        'DELTAAEGIS_VERSION = "0.44.1"',
        TITLE,
        "v0.44.1 Repository Hygiene",
        "SPDX-License-Identifier: AGPL-3.0-only",
    ):
        if marker not in source:
            fail(f"deltaaegis.py is missing maintenance marker: {marker}")

    web = read("deltaaegis_core/web.py")
    if 'server_version = "DeltaAegisDashboard/0.44.1"' not in web:
        fail("dashboard server version is not 0.44.1")

    help_text = subprocess.run(
        [sys.executable, str(ROOT / "deltaaegis.py"), "--help"],
        check=True, capture_output=True, text=True,
    ).stdout
    if TITLE not in help_text:
        fail("CLI help does not identify v0.44.1")

    readme = read("README.md")
    changelog = read("CHANGELOG.md")
    if "## Current Release — v0.44.1" not in readme or f"**{TITLE}**" not in readme:
        fail("README does not identify the v0.44.1 current release")
    if "./tools/validate_v0_44_1_release_gate.sh" not in readme:
        fail("README does not identify the v0.44.1 release gate")
    if not changelog.startswith(f"## {TITLE}\n"):
        fail("CHANGELOG does not begin with the v0.44.1 maintenance release")
    if "Introduced no database-schema, stable-API, detection, or operator-workflow change." not in changelog:
        fail("CHANGELOG does not state the maintenance behavior boundary")
    if "exact-target atomic moves" not in changelog:
        fail("CHANGELOG omits managed-launcher replacement hardening")
    if "exact-target atomic replacement" not in readme:
        fail("README omits managed-launcher replacement hardening")
    if "current through DeltaAegis v0.44.1" not in read("V1_SCOPE.md"):
        fail("V1_SCOPE.md is not current through v0.44.1")
    if "Status: v0.44.1 repository hygiene and validation retention" not in read("SUPPORTED_VERSIONS.md"):
        fail("SUPPORTED_VERSIONS.md is not current through v0.44.1")
    audit_source = read("tools/audit_v0_44_repository.py")
    for marker in (
        "DeltaAegis v0.44.1 Repository Hygiene and Validation Retention maintenance candidate",
        "# DeltaAegis v0.44.1 Repository Audit",
    ):
        if marker not in audit_source:
            fail(f"deterministic audit metadata is stale: {marker}")

    manifest = json.loads(read("docs/v0.44.1-validator-retirement.json"))
    expected_manifest = {
        "maintenance_release": "0.44.1",
        "source_release": "0.44.0",
        "archive_tag": "v0.44.0",
        "current_release_gate": "tools/validate_v0_44_1_release_gate.sh",
        "expected_retained_validator_count": 68,
        "expected_shell_validator_count": 51,
    }
    for key, value in expected_manifest.items():
        if manifest.get(key) != value:
            fail(f"retirement manifest {key} changed: {manifest.get(key)!r}")
    if "v0.41 data durability and recovery" not in manifest.get("retained_compatibility_floor", []):
        fail("retirement manifest omits retained v0.41 durability coverage")
    if manifest.get("format") != "deltaaegis-validator-retirement-v2":
        fail("retirement manifest is not the final v0.44.1 format")
    if "v0.40-v0.44 release-only" not in manifest.get("retirement_scope", ""):
        fail("retirement manifest omits final release-only scope")

    gate = read("tools/validate_v0_44_1_release_gate.sh")
    invocations = (
        "python3 tools/validate_v0_44_1_repository_hygiene.py",
        "python3 tools/validate_v0_44_1_report_contracts.py",
        "python3 tools/validate_v0_44_1_validator_retirement.py",
        "python3 tools/validate_v0_44_1_data_durability_compatibility.py",
        "python3 tools/validate_v0_44_stage1_2.py",
        "python3 tools/validate_v0_44_stage3_auth.py",
        "python3 tools/validate_v0_44_stage4_ingest.py",
        "python3 tools/validate_v0_44_stage5_7.py",
        "python3 tools/validate_v0_44_stage8_web.py",
        "python3 tools/validate_v0_44_architecture.py",
        "python3 tools/audit_v0_44_repository.py --check",
        "python3 tools/validate_v0_44_1_release_metadata.py",
        "python3 tools/validate_v0_43_v0_42_compatibility.py",
    )
    for invocation in invocations:
        if gate.count(invocation) != 1:
            fail(f"release gate must invoke exactly once: {invocation}")
    retired_names = {
        Path(entry["path"]).name
        for entry in manifest.get("retired_files", [])
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    }
    delegated_retired = sorted(name for name in retired_names if name in gate)
    if delegated_retired:
        fail(
            "v0.44.1 gate delegates to retired tooling: "
            f"{delegated_retired[:5]}"
        )
    for marker in (
        "maintenance/v0.44.1-repository-hygiene|main",
        "git status --short",
        "git diff --check",
        "git show --check --format= HEAD",
        "unresolved conflict marker found",
        "mapfile -t tool_python",
        "mapfile -t shell_validators",
        'for shell_source in install.sh uninstall.sh "${shell_validators[@]}"',
        'bash -n "$shell_source"',
        "Parker's explicit approval",
    ):
        if marker not in gate:
            fail(f"release gate is missing policy marker: {marker}")

    install = read("install.sh")
    for marker in (
        "replace_launcher_atomically()",
        'mv -fT -- "$temporary" "$target"',
        "Some overlay filesystems can transiently report",
    ):
        if marker not in install:
            fail(f"install.sh is missing v0.44.1 launcher hardening marker: {marker}")

    durability = read("tools/validate_v0_44_1_data_durability_compatibility.py")
    durability_roots = (
        "validate_v0_41_backup_foundation.sh",
        "validate_v0_41_backup_manifest.sh",
        "validate_v0_41_restore_rehearsal.sh",
        "validate_v0_41_backup_catalog.sh",
        "validate_v0_41_backup_retention_preview.sh",
        "validate_v0_41_backup_retention_execution.sh",
        "validate_v0_41_restore_cutover_preview.sh",
        "validate_v0_41_restore_cutover_execution.sh",
    )
    for validator in durability_roots:
        if durability.count(validator) != 1:
            fail(f"durability composition must list exactly once: {validator}")

    troubleshooter = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/deltaaegis_troubleshooter.py"),
            "--repo", str(ROOT), "--self-check", "--strict-graph", "--json",
        ],
        check=True, capture_output=True, text=True,
    )
    payload = json.loads(troubleshooter.stdout)
    if payload.get("current_release_gate") != "tools/validate_v0_44_1_release_gate.sh":
        fail("troubleshooter does not select the v0.44.1 gate")
    if payload.get("validator_count") != 51 or payload.get("graph_ok") is not True:
        fail(f"troubleshooter inventory or graph changed: {payload}")

    for required in (
        "tools/validate_v0_44_1_release_gate.sh",
        "tools/validate_v0_44_1_release_metadata.py",
        "tools/validate_v0_44_1_data_durability_compatibility.py",
    ):
        path = ROOT / required
        if not path.is_file() or not path.stat().st_mode & 0o111:
            fail(f"missing or non-executable v0.44.1 release tool: {required}")

    print("PASS: v0.44.1 source, CLI, dashboard, README, and CHANGELOG metadata")
    print("PASS: v0.44.1 retention inventory and durability floor")
    print("PASS: flat v0.44.1 release-gate composition")
    print("PASS: troubleshooter selects the v0.44.1 release gate")
    print("PASS: DeltaAegis v0.44.1 release metadata")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
