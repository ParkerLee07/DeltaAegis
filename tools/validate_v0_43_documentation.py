#!/usr/bin/env python3
"""Validate DeltaAegis v0.43 release documentation and frozen evidence."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def text(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file():
        fail(f"missing required documentation: {relative}")
    return path.read_text(encoding="utf-8")


def require(relative: str, markers: tuple[str, ...]) -> str:
    content = text(relative)
    missing = [marker for marker in markers if marker not in content]
    if missing:
        fail(f"{relative} is missing marker(s): {', '.join(missing)}")
    return content


def main() -> int:
    print("DeltaAegis v0.43 Documentation Accuracy Validator")
    print("===================================================")

    readme = require(
        "README.md",
        (
            "## Current Release — v0.43.0",
            "**DeltaAegis v0.43.0 — Architecture and Stability Baseline**",
            "without adding another operator workflow or changing the database schema",
            "V1_SCOPE.md",
            "SUPPORTED_VERSIONS.md",
            "docs/architecture/overview.md",
            "nine architecture decisions",
            "deterministic repository audit",
            "synthetic performance harness",
            "NetSniper remains pinned to v2.0.0",
            "tools/validate_v0_43_release_gate.sh",
            "AGPL-3.0-only",
            "LICENSING.md",
        ),
    )
    current_start = readme.index("## Current Release")
    current_end = readme.find("\n## ", current_start + 4)
    current = readme[current_start:] if current_end < 0 else readme[current_start:current_end]
    if "v0.42.2 — Authorization and Integrity Hardening" in current:
        fail("README current-release section still presents v0.42.2 as current")

    changelog = require(
        "CHANGELOG.md",
        (
            "## DeltaAegis v0.43.0 — Architecture and Stability Baseline",
            "nine architecture decisions",
            "forward-only migrations",
            "`/api/v1`",
            "deterministic repository audit",
            "synthetic performance harness",
            "frozen v0.43 comparison baseline",
            "flat v0.43 release gate",
            "NetSniper at v2.0.0",
            "AGPL-3.0-only",
        ),
    )
    if not changelog.startswith("## DeltaAegis v0.43.0 — Architecture and Stability Baseline"):
        fail("CHANGELOG does not begin with v0.43.0")

    require(
        "V1_SCOPE.md",
        (
            "## v1.0 promises",
            "## Explicit v1.0 exclusions",
            "## Definition of done",
            "## Scope change control",
        ),
    )
    require(
        "SUPPORTED_VERSIONS.md",
        (
            "CPython 3.10 through 3.14",
            "Debian 12 and 13",
            "Ubuntu 22.04 LTS and 24.04 LTS",
            "NetSniper",
            "v2.0.0",
            "TrueAegis",
            "Node.js",
            "## Unsupported configurations",
        ),
    )
    require(
        "CONTRIBUTING.md",
        (
            "## Validation expectations",
            "## Licensing boundary",
            "does not add a contributor agreement",
        ),
    )
    require(
        "docs/architecture/overview.md",
        (
            "## Current repository components",
            "## Runtime process model",
            "## Storage model",
            "## Evidence flow and trust boundaries",
            "## v0.44 extraction map",
            "## Architecture decision index",
        ),
    )

    decisions = sorted((ROOT / "docs/architecture/decisions").glob("[0-9][0-9][0-9][0-9]-*.md"))
    if [item.name[:4] for item in decisions] != [f"{number:04d}" for number in range(1, 10)]:
        fail("architecture decisions are not the complete 0001 through 0009 set")
    for decision in decisions:
        body = decision.read_text(encoding="utf-8")
        for marker in ("- Status: Accepted", "## Context", "## Decision", "## Consequences"):
            if marker not in body:
                fail(f"{decision.relative_to(ROOT)} is missing {marker}")

    audit = require(
        "docs/repository-audit.md",
        (
            "deltaaegis-repository-audit-v1",
            "v0.43.0 release candidate",
            "DA043-001",
            "DA043-007",
            "## Deferred work map",
        ),
    )
    if "broad v0.43 rewrite" not in audit:
        fail("repository audit does not preserve the no-broad-rewrite boundary")

    performance = json.loads(text("docs/performance-baseline.json"))
    if performance.get("schema_version") != "deltaaegis-performance-baseline-v1":
        fail("unexpected performance-baseline schema")
    if performance.get("mode") != "full":
        fail("performance baseline is not a full measurement")
    if performance.get("source", {}).get("deltaaegis_version") != "0.42.2":
        fail("performance baseline no longer preserves the measured v0.42.2 runtime")
    if performance.get("source", {}).get("git_tree") != "e491383d59c6f93a34001f5e1060d62d3c944405":
        fail("performance baseline no longer references the published v0.42.2 tree")
    if performance.get("measurements", {}).get("release_gate", {}).get("status") != "passed":
        fail("performance baseline lacks a passing predecessor release-gate measurement")
    require(
        "docs/performance-baseline.md",
        (
            "This baseline measures the unchanged v0.42.2 runtime",
            "Real operator data used: **no**",
            "Release-gate status: `passed`",
            "descriptive v0.43 baselines, not release thresholds",
        ),
    )

    approved_license = "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0"
    if hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest() != approved_license:
        fail("LICENSE is not the approved AGPL-3.0 text")
    require(
        "LICENSING.md",
        (
            "# DeltaAegis Licensing",
            "AGPL-3.0-only",
            "Alternative commercial licensing",
            "already distributed under the MIT License",
        ),
    )

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
        fail("manual/version-specific release documents remain tracked: " + ", ".join(tracked_manual))

    print("PASS: README and cumulative CHANGELOG identify v0.43.0")
    print("PASS: v1.0 scope, support, contribution, architecture, and ADR documentation")
    print("PASS: deterministic audit and frozen synthetic performance evidence")
    print("PASS: AGPL/commercial-licensing and operator-managed verification policy")
    print("PASS: DeltaAegis v0.43 documentation accuracy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
