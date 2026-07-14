#!/usr/bin/env python3
"""Validate the v0.44.1 repository-hygiene foundation."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def read(path: str) -> str:
    target = ROOT / path
    if not target.is_file():
        fail(f"missing required file: {path}")
    return target.read_text(encoding="utf-8")


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def main() -> int:
    print("DeltaAegis v0.44.1 Repository Hygiene Foundation Validator")
    print("============================================================")

    if (ROOT / "docs/architecture.md").exists():
        fail("obsolete docs/architecture.md remains")
    overview = read("docs/architecture/overview.md")
    if "Status: v0.44.0 modular core foundation and v1.0 boundary map" not in overview:
        fail("authoritative architecture overview marker changed")
    print("PASS: one authoritative architecture document")

    scope = read("V1_SCOPE.md")
    required_scope = "Status: approved at v0.43.0 and current through DeltaAegis v0.44.0"
    if required_scope not in scope:
        fail("V1_SCOPE.md does not identify its current planning status")
    print("PASS: v1.0 scope status is current without rewriting the approved baseline")

    troubleshooter_path = ROOT / "tools/deltaaegis_troubleshooter.py"
    troubleshooter = read("tools/deltaaegis_troubleshooter.py")
    for forbidden in (
        "payload_b64",
        "SOURCE_CURRENT_BRANCH",
        "Run v0.42 component diagnostics",
        "newest embedded release gate",
    ):
        if forbidden in troubleshooter:
            fail(f"troubleshooter retains stale embedded marker: {forbidden}")
    for marker in (
        'TOOL_FORMAT = "deltaaegis-repository-troubleshooter-v4"',
        "def validator_inventory(",
        "def current_release_gate(",
        "def sqlite_read_only_checks(",
        '"main", head',
    ):
        if marker not in troubleshooter:
            fail(f"troubleshooter is missing dynamic marker: {marker}")
    if troubleshooter_path.stat().st_size >= 100_000:
        fail("repository-aware troubleshooter unexpectedly exceeds 100 KB")

    completed = run([
        sys.executable,
        "tools/deltaaegis_troubleshooter.py",
        "--repo",
        str(ROOT),
        "--self-check",
        "--json",
    ])
    if completed.returncode:
        fail(f"troubleshooter self-check failed: {completed.stderr or completed.stdout}")
    payload = json.loads(completed.stdout)
    if payload.get("format") != "deltaaegis-repository-troubleshooter-v4":
        fail("troubleshooter self-check format changed")
    if payload.get("current_release_gate") != "tools/validate_v0_44_release_gate.sh":
        fail("troubleshooter does not select the v0.44 release gate")
    if payload.get("validator_count", 0) < 250 or payload.get("integrity_ok") is not True:
        fail("troubleshooter did not inventory the repository validators")
    if payload.get("graph_ok") is not True:
        fail(
            "troubleshooter execution graph is not clean: "
            f"cycles={payload.get('cycles')} "
            f"missing={payload.get('missing_references')}"
        )
    if payload.get("cycles") != [] or payload.get("missing_references") != {}:
        fail("troubleshooter graph payload is internally inconsistent")

    strict = run([
        sys.executable,
        "tools/deltaaegis_troubleshooter.py",
        "--repo",
        str(ROOT),
        "--self-check",
        "--strict-graph",
        "--json",
    ])
    if strict.returncode:
        fail(f"strict troubleshooter graph check failed: {strict.stderr or strict.stdout}")
    strict_payload = json.loads(strict.stdout)
    if strict_payload.get("graph_ok") is not True:
        fail("strict troubleshooter graph check did not report graph_ok=true")

    listed = run([
        sys.executable,
        "tools/deltaaegis_troubleshooter.py",
        "--repo",
        str(ROOT),
        "--mode",
        "current",
        "--list",
    ])
    if listed.returncode or "tools/validate_v0_44_release_gate.sh" not in listed.stdout:
        fail("current release gate is absent from troubleshooter listing")
    print("PASS: repository-aware troubleshooter selects current v0.44 diagnostics")

    readme = read("README.md")
    trouble_doc = read("docs/TROUBLESHOOTER.md")
    for content, name in ((readme, "README.md"), (trouble_doc, "docs/TROUBLESHOOTER.md")):
        for forbidden in ("embedded release gate", "v0.42 component diagnostics", "--match 'v0_42'"):
            if forbidden in content:
                fail(f"{name} retains stale troubleshooter wording: {forbidden}")
    for marker in (
        "repository-aware troubleshooting tool",
        "--mode stages",
        "--match 'v0_44' --list",
    ):
        if marker not in readme:
            fail(f"README is missing troubleshooter marker: {marker}")
    if "reads validators from the selected checkout" not in trouble_doc:
        fail("troubleshooter documentation does not describe live repository inventory")
    print("PASS: troubleshooter documentation matches current behavior")

    ci = read(".github/workflows/ci.yml")
    for marker in (
        "find deltaaegis_core -maxdepth 1 -type f -name '*.py'",
        "tools/deltaaegis_troubleshooter.py",
        "tools/validate_v0_44_1_repository_hygiene.py",
        "python3 -m unittest discover -s tests -p 'test*.py' -v",
    ):
        if marker not in ci:
            fail(f"CI is missing: {marker}")
    print("PASS: CI compiles the modular core and validates repository hygiene")

    install = read("install.sh")
    if "Running non-mutating syntax and troubleshooter checks" not in install:
        fail("install.sh still describes the old embedded bundle check")

    audit = run([sys.executable, "tools/audit_v0_44_repository.py", "--check"])
    if audit.returncode:
        fail(f"deterministic repository audit failed: {audit.stderr or audit.stdout}")
    audit_doc = read("docs/repository-audit.md")
    if "`docs/architecture.md`" in audit_doc:
        fail("repository audit still records the removed architecture document")
    print("PASS: deterministic audit reflects the cleaned repository")

    diff = run(["git", "diff", "--check"])
    if diff.returncode:
        fail(f"whitespace check failed: {diff.stderr or diff.stdout}")
    print("PASS: repository hygiene foundation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
