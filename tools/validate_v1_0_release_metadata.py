#!/usr/bin/env python3
# Validate DeltaAegis v1.0.0 General Availability release metadata.

from __future__ import annotations

import ast
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_BRANCHES = {
    "feature/v1.0-stages-3-5",
    "release/v1.0-metadata-finalization",
    "main",
}
MERGE_COMMIT = "338f6ed44e9db330fd7f67f3242fd682fab11fab"
MAIN_CI_RUN = "30290071519"
MATRIX_RUN = "30291887915"


def fail(message: str) -> None:
    raise SystemExit(f"[FAIL] v1.0 release metadata: {message}")


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
    print("DeltaAegis v1.0.0 Release Metadata Validator")
    print("==============================================")

    branch = resolve_branch()
    require(
        branch in ALLOWED_BRANCHES,
        "unsupported release branch: "
        f"{branch or '(detached without CI branch context)'}",
    )

    runtime = read("deltaaegis.py")
    require(
        assignment(runtime, "DELTAAEGIS_VERSION") == "1.0.0",
        "runtime version is not 1.0.0",
    )

    troubleshooter = read("tools/deltaaegis_troubleshooter.py")
    require(
        'TOOL_VERSION = "1.0.0"' in troubleshooter,
        "troubleshooter version is not 1.0.0",
    )

    openapi = json.loads(read("contracts/v1/openapi.json"))
    require(
        (openapi.get("info") or {}).get("version") == "1.0.0",
        "OpenAPI version is not 1.0.0",
    )

    readme = read("README.md")
    readme_release = section(
        readme,
        "## Current Release — v1.0.0\n",
        "## What DeltaAegis Does\n",
    )
    for marker in (
        "DeltaAegis v1.0.0 — General Availability",
        "1,431 samples",
        MERGE_COMMIT,
        MAIN_CI_RUN,
        MATRIX_RUN,
        "zero integrity, readiness, or unplanned-worker",
        "No additional 24-hour soak was required",
    ):
        require(marker in readme_release, f"README release marker: {marker}")
    for stale in (
        "Development Candidate",
        "not v1.0 GA",
        "mandatory 24-hour soak receipt and final release-blocker",
    ):
        require(stale not in readme_release, f"stale README marker: {stale}")

    changelog = read("CHANGELOG.md")
    require(
        changelog.startswith(
            "## DeltaAegis v1.0.0 — General Availability — 2026-07-27\n"
        ),
        "CHANGELOG does not begin with v1.0.0 GA",
    )
    v1_changelog = changelog.split(
        "## DeltaAegis v0.45.0 — Telemetry Trust\n",
        1,
    )[0]
    for marker in (
        "1,431",
        MERGE_COMMIT,
        MAIN_CI_RUN,
        MATRIX_RUN,
        "runtime, schema, API, detection, database, or integration change",
    ):
        require(marker in v1_changelog, f"CHANGELOG marker: {marker}")
    for stale in ("(unreleased)", "This candidate does not declare v1.0 GA"):
        require(stale not in v1_changelog, f"stale CHANGELOG marker: {stale}")

    supported = read("SUPPORTED_VERSIONS.md")
    for marker in (
        "Status: DeltaAegis v1.0.0 General Availability",
        "Production v1.0.0 support is qualified",
        MAIN_CI_RUN,
        MATRIX_RUN,
        "Debian 12 and 13",
        "Ubuntu 22.04 LTS and 24.04 LTS",
        "CPython 3.10 through 3.14",
    ):
        require(marker in supported, f"supported-version marker: {marker}")
    require(
        "release-candidate-only" not in supported,
        "SUPPORTED_VERSIONS still claims candidate-only support",
    )

    scope = read("V1_SCOPE.md")
    for marker in (
        "Status: finalized for DeltaAegis v1.0.0 General Availability",
        "## Delivery status — 2026-07-27",
        "All ten definition-of-done items are complete",
        "1,431 samples",
    ):
        require(marker in scope, f"V1_SCOPE marker: {marker}")
    require(scope.count("[x]") == 10, "V1_SCOPE does not mark ten completed items")
    require("[ ]" not in scope, "V1_SCOPE contains an incomplete item")
    for stale in (
        "implementation evidence, not a v1.0 GA declaration",
        "must remain a release candidate",
    ):
        require(stale not in scope, f"stale V1_SCOPE marker: {stale}")

    architecture = read("docs/architecture/overview.md")
    for marker in (
        "Status: DeltaAegis v1.0.0 General Availability",
        "DeltaAegis v1.0.0 exposes the stable `/api/v1` boundary",
        "the uninterrupted 24-hour soak and final blocker audit passed",
    ):
        require(marker in architecture, f"architecture marker: {marker}")
    require(
        "This candidate is not v1.0 GA" not in architecture,
        "architecture still denies GA",
    )

    checklist = read("docs/V1_STAGE3_5_RELEASE_CHECKLIST.md")
    require(
        checklist.startswith(
            "# DeltaAegis v1.0.0 General Availability checklist\n"
        ),
        "checklist title is not GA",
    )
    require("- [ ]" not in checklist, "checklist contains an incomplete item")
    require(checklist.count("- [x]") >= 30, "checklist completion inventory is incomplete")
    for marker in (
        MERGE_COMMIT,
        MAIN_CI_RUN,
        MATRIX_RUN,
        "Release metadata identifies v1.0.0 GA",
    ):
        require(marker in checklist, f"checklist marker: {marker}")

    implementation = read("docs/v1-stage3-5-implementation.md")
    for marker in (
        "Status: delivered in DeltaAegis v1.0.0 General Availability",
        "release-evidence soak completed on 2026-07-24",
        "1,431 samples",
        "`release_eligible: true`",
    ):
        require(marker in implementation, f"implementation marker: {marker}")
    require(
        "the 24-hour GA soak is not yet claimed" not in implementation,
        "implementation status still denies completed soak",
    )

    audit_source = read("tools/audit_v0_44_repository.py")
    for marker in (
        'SCHEMA_VERSION = "deltaaegis-repository-audit-v4"',
        '"scope": "DeltaAegis v1.0.0 General Availability release"',
        "# DeltaAegis v1.0.0 Repository Audit",
        "| Final GA gate | Completed |",
    ):
        require(marker in audit_source, f"audit generator marker: {marker}")

    audit = read("docs/repository-audit.md")
    require(
        audit.startswith("# DeltaAegis v1.0.0 Repository Audit\n"),
        "generated audit title is stale",
    )
    for marker in (
        "deltaaegis-repository-audit-v4",
        "v1.0.0 GA release tree",
        "| Final GA gate | Completed |",
    ):
        require(marker in audit, f"generated audit marker: {marker}")
    require(
        "candidate evidence and does not declare v1.0 GA" not in audit,
        "generated audit still denies GA",
    )

    ci = read(".github/workflows/ci.yml")
    for marker in (
        "release/v1.0-metadata-finalization",
        "tools/validate_v1_0_release_metadata.py",
        "Run DeltaAegis v1.0.0 release gate",
    ):
        require(marker in ci, f"CI marker: {marker}")
    require(
        ci.count("tools/validate_v1_0_release_metadata.py") == 1,
        "CI metadata-validator inventory count changed",
    )

    all_gate = read("tools/validate_v1_0_stage3_5_all.sh")
    require(
        all_gate.count(
            "python3 tools/validate_v1_0_release_metadata.py"
        ) == 1,
        "combined validation must run metadata validator exactly once",
    )
    require(
        "DeltaAegis v1.0.0 GA implementation and metadata validation"
        in all_gate,
        "combined validation GA marker is missing",
    )

    gate = read("tools/validate_v1_0_stage3_5_gate.sh")
    for marker in (
        "release/v1.0-metadata-finalization",
        "DeltaAegis v1.0.0 General Availability Release Gate",
        "[PASS] DeltaAegis v1.0.0 General Availability release gate",
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

    print("[PASS] runtime, troubleshooter, and OpenAPI identify v1.0.0")
    print("[PASS] README, CHANGELOG, support, scope, and architecture identify GA")
    print("[PASS] checklist and implementation record completed evidence")
    print("[PASS] deterministic audit identifies the v1.0.0 release tree")
    print("[PASS] CI and release-gate composition enforce finalized metadata")
    print("[PASS] DeltaAegis v1.0.0 release metadata")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
