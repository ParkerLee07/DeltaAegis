#!/usr/bin/env python3
"""Validate DeltaAegis v0.44 release documentation and frozen evidence."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def read(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file():
        fail(f"missing documentation file: {relative}")
    return path.read_text(encoding="utf-8")


def require(relative: str, markers: tuple[str, ...]) -> str:
    content = read(relative)
    for marker in markers:
        if marker not in content:
            fail(f"{relative} is missing: {marker}")
    return content


def main() -> int:
    print("DeltaAegis v0.44 Documentation Validator")
    print("==========================================")
    readme = require("README.md", (
        "## Current Release — v0.44.0",
        "**DeltaAegis v0.44.0 — Modular Core Foundation**",
        "deltaaegis_core/auth.py", "deltaaegis_core/config.py", "deltaaegis_core/db.py",
        "deltaaegis_core/ingest.py", "deltaaegis_core/jobs.py", "deltaaegis_core/reports.py",
        "deltaaegis_core/sites.py", "deltaaegis_core/web.py",
        "./tools/validate_v0_44_release_gate.sh",
        "introduced no stable `/api/v1` contract or database migration framework",
    ))
    if "## Current Release — v0.43.0" in readme:
        fail("README still identifies v0.43.0 as the current release")
    print("PASS: README identifies the completed modular core and current gate")

    changelog = read("CHANGELOG.md")
    if not changelog.startswith("## DeltaAegis v0.44.0 — Modular Core Foundation\n"):
        fail("CHANGELOG does not begin with the v0.44.0 release")
    for marker in (
        "## DeltaAegis v0.43.0 — Architecture and Stability Baseline",
        "Introduced no stable `/api/v1`, migration ledger, detection redesign, or new operator workflow",
        "Preserved v0.43/v0.42 security and component behavior",
    ):
        if marker not in changelog:
            fail(f"CHANGELOG is missing: {marker}")
    print("PASS: cumulative CHANGELOG preserves v0.43 and records v0.44 boundaries")

    overview = require("docs/architecture/overview.md", (
        "Status: v0.44.0 modular core foundation and v1.0 boundary map",
        "## v0.44 modular boundary result",
        "deltaaegis_core/web.py",
        "repository-root compatibility facade",
        "The completed extraction did not mix functional redesign with file movement.",
    ))
    if "implemented by the local handler in `deltaaegis.py`" in overview:
        fail("architecture overview still assigns HTTP implementation to the root facade")
    print("PASS: architecture overview reflects completed ownership boundaries")

    require("SUPPORTED_VERSIONS.md", (
        "Status: v0.44.0 modular core foundation",
        "Node 20, 22, and 24 are the v0.44 validation range",
        "authoritative technical CIDR key through v0.44",
    ))
    require("CONTRIBUTING.md", ("tools/validate_v0_44_release_gate.sh",))
    require("docs/repository-audit.md", (
        "# DeltaAegis v0.44 Repository Audit",
        "deltaaegis-repository-audit-v2",
        "Modular core inventory",
        "Forbidden imports of the root `deltaaegis` module",
    ))
    print("PASS: support, contribution, and deterministic audit documentation")

    release = json.loads(read("docs/v0.44-release-characterization.json"))
    if release.get("format") != "deltaaegis-v0.44-release-characterization-v1":
        fail("release characterization format changed")
    if release.get("release") != "0.44.0" or release.get("base_release") != "0.43.0":
        fail("release characterization version lineage changed")
    if release.get("source_checkpoint") != "b5dc440079278a01d7ecea0c4b588663a495d52c":
        fail("release characterization source checkpoint changed")
    if release.get("schema_change") is not False or release.get("stable_api_introduced") is not False:
        fail("release characterization overclaims schema or stable API work")
    if tuple(release.get("modules", ())) != ("auth", "config", "db", "ingest", "jobs", "reports", "sites", "web"):
        fail("release characterization module inventory changed")
    stage12 = json.loads(read("docs/v0.44-stage1-2-characterization.json"))
    if stage12.get("source_release") != "0.43.0":
        fail("historical extraction source release was rewritten")
    print("PASS: release and historical characterization evidence is coherent")

    require("docs/architecture/decisions/0010-internal-package-compatibility-facade.md", (
        "compatibility facade", "deltaaegis_core",
    ))
    print("PASS: ADR 0010 and v1.0 planning documentation remain present")
    print("PASS: DeltaAegis v0.44 release documentation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
