#!/usr/bin/env python3
# Validate DeltaAegis v1.0.1 maintenance-release metadata.

from __future__ import annotations

import ast
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_BRANCHES = {
    "release/v1.0.1-metadata-finalization",
    "main",
}
HOTFIX_COMMIT = "b0dbe7e45346253bc18df7eb063bf9866b25e44c"
MERGE_COMMIT = "836b2ac25e27c344f292e2a9cacbe0a4f757fe1f"
MAIN_CI_RUN = "30393445773"
BASE_MATRIX_RUN = "30291887915"


def fail(message: str) -> None:
    raise SystemExit(f"[FAIL] v1.0.1 release metadata: {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def read(relative: str) -> str:
    path = ROOT / relative
    require(path.is_file(), f"missing required file: {relative}")
    return path.read_text(encoding="utf-8")


def resolve_branch() -> str:
    branch = subprocess.check_output(
        ["git", "-C", str(ROOT), "branch", "--show-current"],
        text=True,
    ).strip()
    if branch:
        return branch
    if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
        for key in ("GITHUB_HEAD_REF", "GITHUB_REF_NAME"):
            value = os.environ.get(key, "").strip()
            if value and not value.endswith("/merge"):
                return value
        ref = os.environ.get("GITHUB_REF", "").strip()
        if ref.startswith("refs/heads/"):
            return ref.removeprefix("refs/heads/")
    return ""


def assignment(source: str, name: str) -> object:
    tree = ast.parse(source)
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == name:
                return ast.literal_eval(node.value)
    fail(f"missing assignment: {name}")


def section(text: str, start: str, end: str) -> str:
    require(text.count(start) == 1, f"section start is not unique: {start!r}")
    require(text.count(end) == 1, f"section end is not unique: {end!r}")
    return text.split(start, 1)[1].split(end, 1)[0]


def main() -> int:
    print("DeltaAegis v1.0.1 Release Metadata Validator")
    print("==============================================")

    branch = resolve_branch()
    require(
        branch in ALLOWED_BRANCHES,
        "unsupported release branch: "
        f"{branch or '(detached without CI branch context)'}",
    )

    runtime = read("deltaaegis.py")
    require(
        assignment(runtime, "DELTAAEGIS_VERSION") == "1.0.1",
        "runtime version is not 1.0.1",
    )
    require(
        'DeltaAegis v1.0.1 maintenance release.' in runtime,
        "runtime module status is stale",
    )
    require(
        '<span>Build</span><span>v1.0.1</span>' in runtime,
        "dashboard Build pill does not identify v1.0.1",
    )
    require(
        "v1.0 Stage 3–5 Candidate" not in runtime,
        "stale dashboard candidate label remains",
    )

    troubleshooter = read("tools/deltaaegis_troubleshooter.py")
    require(
        'TOOL_VERSION = "1.0.1"' in troubleshooter,
        "troubleshooter version is not 1.0.1",
    )

    openapi = json.loads(read("contracts/v1/openapi.json"))
    require(
        (openapi.get("info") or {}).get("version") == "1.0.1",
        "tracked OpenAPI version is not 1.0.1",
    )
    runtime_openapi_source = read("deltaaegis_core/api_v1.py")
    require(
        runtime_openapi_source.count('            "version": "1.0.1",') == 1,
        "runtime OpenAPI provider does not identify v1.0.1 exactly once",
    )
    require(
        '            "version": "1.0.0",' not in runtime_openapi_source,
        "runtime OpenAPI provider still identifies v1.0.0",
    )

    readme = read("README.md")
    release = section(
        readme,
        "## Current Release — v1.0.1\n",
        "## What DeltaAegis Does\n",
    )
    for marker in (
        "DeltaAegis v1.0.1 — Dashboard SQLite Reliability",
        HOTFIX_COMMIT,
        MERGE_COMMIT,
        MAIN_CI_RUN,
        BASE_MATRIX_RUN,
        "32 concurrent runtime",
        "48 concurrent live `/api/summary` requests",
        "zero `database is locked` errors or",
        "No additional 24-hour soak was required",
    ):
        require(marker in release, f"README release marker: {marker}")
    require(
        "## Current Release — v1.0.0" not in readme,
        "README still identifies v1.0.0 as current",
    )
    require(
        "Run the v1.0.1 maintenance release gate" in readme,
        "README validation command status is stale",
    )

    changelog = read("CHANGELOG.md")
    require(
        changelog.startswith(
            "## DeltaAegis v1.0.1 — Dashboard SQLite Reliability — 2026-07-28\n"
        ),
        "CHANGELOG does not begin with v1.0.1",
    )
    maintenance = changelog.split(
        "## DeltaAegis v1.0.0 — General Availability",
        1,
    )[0]
    for marker in (
        HOTFIX_COMMIT,
        MERGE_COMMIT,
        MAIN_CI_RUN,
        "32 concurrent runtime reads",
        "48 concurrent live dashboard summary requests",
        "No additional 24-hour soak was required",
    ):
        require(marker in maintenance, f"CHANGELOG marker: {marker}")

    supported = read("SUPPORTED_VERSIONS.md")
    for marker in (
        "Status: DeltaAegis v1.0.1 Maintenance Release",
        "supported DeltaAegis v1.0.1 environment",
        "Production v1.0.1 support is qualified",
        MERGE_COMMIT,
        MAIN_CI_RUN,
        BASE_MATRIX_RUN,
        "Debian 12 and 13",
        "Ubuntu 22.04 LTS and 24.04 LTS",
        "CPython 3.10 through 3.14",
    ):
        require(marker in supported, f"supported-version marker: {marker}")

    scope = read("V1_SCOPE.md")
    for marker in (
        "Status: finalized for DeltaAegis v1.0.1 Maintenance Release",
        "## Maintenance status — 2026-07-28",
        MERGE_COMMIT,
        MAIN_CI_RUN,
        "does not expand the v1.0 product scope",
        "All ten definition-of-done items are complete",
    ):
        require(marker in scope, f"V1_SCOPE marker: {marker}")
    require(scope.count("[x]") == 10, "V1_SCOPE completion count changed")
    require("[ ]" not in scope, "V1_SCOPE contains an incomplete item")

    architecture = read("docs/architecture/overview.md")
    for marker in (
        "Status: DeltaAegis v1.0.1 Maintenance Release",
        "## Dashboard connection lifecycle",
        "Forward migrations run once",
        "connections never invoke the migration runner",
        "DeltaAegis v1.0.1 exposes the stable `/api/v1` boundary",
        MERGE_COMMIT,
        MAIN_CI_RUN,
    ):
        require(marker in architecture, f"architecture marker: {marker}")

    checklist = read("docs/V1_STAGE3_5_RELEASE_CHECKLIST.md")
    require(
        checklist.startswith(
            "# DeltaAegis v1.0.1 Maintenance Release checklist\n"
        ),
        "checklist title is stale",
    )
    require("- [ ]" not in checklist, "checklist contains an incomplete item")
    require(
        checklist.count("- [x]") >= 45,
        "checklist maintenance inventory is incomplete",
    )
    for marker in (
        HOTFIX_COMMIT,
        MERGE_COMMIT,
        MAIN_CI_RUN,
        "32 concurrent runtime reads",
        "48 concurrent live dashboard requests",
        "Release metadata identifies v1.0.1",
    ):
        require(marker in checklist, f"checklist marker: {marker}")

    implementation = read("docs/v1-stage3-5-implementation.md")
    for marker in (
        "maintained by DeltaAegis v1.0.1",
        "## v1.0.1 dashboard connection-lifecycle maintenance",
        "Forward migrations execute once",
        "connections do not enter the migration runner",
        MERGE_COMMIT,
        MAIN_CI_RUN,
    ):
        require(marker in implementation, f"implementation marker: {marker}")

    audit_source = read("tools/audit_v0_44_repository.py")
    for marker in (
        'SCHEMA_VERSION = "deltaaegis-repository-audit-v4"',
        '"scope": "DeltaAegis v1.0.1 maintenance release"',
        "# DeltaAegis v1.0.1 Repository Audit",
        "| v1.0.1 maintenance gate | Completed |",
    ):
        require(marker in audit_source, f"audit generator marker: {marker}")

    audit = read("docs/repository-audit.md")
    require(
        audit.startswith("# DeltaAegis v1.0.1 Repository Audit\n"),
        "generated audit title is stale",
    )
    for marker in (
        "deltaaegis-repository-audit-v4",
        "v1.0.1 maintenance release tree",
        "| v1.0.1 maintenance gate | Completed |",
    ):
        require(marker in audit, f"generated audit marker: {marker}")

    historical = read("tools/validate_v1_0_release_metadata.py")
    require(
        "DeltaAegis v1.0.0 Release Metadata Validator" in historical,
        "historical v1.0.0 metadata validator was not preserved",
    )

    stage1 = read("tools/validate_v1_stage1_migrations.py")
    stage2 = read("tools/validate_v1_stage2_api_security.py")
    architecture_guard = read("tools/validate_v1_stage1_2_architecture.py")
    performance_guard = read("tools/measure_v1_stage5_performance.py")
    stage35_guard = read("tools/validate_v1_stage3_5.py")
    approved_sequence = 'in {"1.0.0-stage12", "1.0.0", "1.0.1"}'
    require(
        stage1.count(approved_sequence) == 1,
        "Stage 1 validator does not admit the v1.0.1 maintenance runtime",
    )
    require(
        stage2.count(approved_sequence) == 1,
        "Stage 2 validator does not admit the v1.0.1 maintenance runtime",
    )
    require(
        "assert deltaaegis.DELTAAEGIS_VERSION == '1.0.1'; "
        in architecture_guard,
        "architecture validator still requires v1.0.0",
    )
    require(
        "assert deltaaegis.DELTAAEGIS_VERSION == '1.0.1'"
        in performance_guard,
        "performance validator still requires v1.0.0",
    )
    require(
        'deltaaegis.DELTAAEGIS_VERSION == "1.0.1"' in stage35_guard
        and "maintenance release version is not 1.0.1" in stage35_guard,
        "Stage 3-5 validator still requires v1.0.0",
    )

    ci = read(".github/workflows/ci.yml")
    for marker in (
        "release/v1.0.1-metadata-finalization",
        "tools/validate_v1_0_1_release_metadata.py",
        "Run DeltaAegis v1.0.1 release gate",
    ):
        require(marker in ci, f"CI marker: {marker}")
    require(
        ci.count("tools/validate_v1_0_1_release_metadata.py") == 1,
        "CI v1.0.1 metadata-validator inventory count changed",
    )

    all_gate = read("tools/validate_v1_0_stage3_5_all.sh")
    require(
        all_gate.count(
            "python3 tools/validate_v1_0_1_release_metadata.py"
        ) == 1,
        "combined gate must run v1.0.1 metadata exactly once",
    )
    require(
        "python3 tools/validate_v1_0_release_metadata.py" not in all_gate,
        "combined gate still executes historical v1.0.0 metadata",
    )
    require(
        "DeltaAegis v1.0.1 maintenance implementation and metadata validation"
        in all_gate,
        "combined gate v1.0.1 marker is missing",
    )

    gate = read("tools/validate_v1_0_stage3_5_gate.sh")
    for marker in (
        "release/v1.0.1-metadata-finalization",
        "DeltaAegis v1.0.1 Maintenance Release Gate",
        "[PASS] DeltaAegis v1.0.1 maintenance release gate",
    ):
        require(marker in gate, f"release-gate marker: {marker}")
    require(
        gate.count("./tools/validate_v1_0_stage3_5_all.sh") == 1,
        "release gate must invoke combined validation exactly once",
    )
    require(
        gate.count("python3 tools/audit_v0_44_repository.py --check") == 1,
        "release gate must check deterministic audit exactly once",
    )

    print("[PASS] runtime, troubleshooter, tracked/runtime OpenAPI, and dashboard Build pill identify v1.0.1")
    print("[PASS] maintenance notes identify exact hotfix and validation evidence")
    print("[PASS] support, scope, architecture, checklist, and implementation are current")
    print("[PASS] deterministic audit identifies the v1.0.1 maintenance tree")
    print("[PASS] all gate-reachable runtime-version guards admit v1.0.1")
    print("[PASS] CI and release-gate composition enforce v1.0.1 metadata")
    print("[PASS] DeltaAegis v1.0.1 release metadata")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
