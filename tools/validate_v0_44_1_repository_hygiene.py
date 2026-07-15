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
    required_scope = "Status: approved at v0.43.0 and current through DeltaAegis v0.44.1"
    if required_scope not in scope:
        fail("V1_SCOPE.md does not identify its current planning status")
    print("PASS: v1.0 scope status is current without rewriting the approved baseline")

    source = read("deltaaegis.py")
    if "_deltaaegis_operator_session_shell_html_v036_telemetry_cleanup_base" in source:
        fail("dead telemetry-cleanup operator wrapper alias remains")
    if source.count("def dashboard_operator_session_shell_html() -> str:") != 2:
        fail("operator-session renderer definition count changed")
    if source.count("def dashboard_operator_reset_shell_html() -> str:") != 1:
        fail("operator reset renderer definition count changed")

    behavior = run([
        sys.executable,
        "-c",
        (
            "import hashlib, json, deltaaegis; "
            "operator = deltaaegis.dashboard_operator_session_shell_html(); "
            "reset = deltaaegis.dashboard_operator_reset_shell_html(); "
            "print(json.dumps({"
            "'operator_sha256': hashlib.sha256(operator.encode()).hexdigest(), "
            "'reset_sha256': hashlib.sha256(reset.encode()).hexdigest(), "
            "'operator_has_reset': 'href=\"/operator/reset\"' in operator, "
            "'operator_has_cleanup_panel': 'id=\"deltaaegis-telemetry-cleanup-panel\"' in operator, "
            "'reset_has_receipt': 'function cleanupReceiptText(receipt, fallbackMessage)' in reset, "
            "'reset_has_audit_refresh': 'loadTelemetryResetAuditEvents();' in reset"
            "}))"
        ),
    ])
    if behavior.returncode:
        fail(f"operator/reset rendering characterization failed: {behavior.stderr or behavior.stdout}")
    rendering = json.loads(behavior.stdout)
    expected_rendering = {
        "operator_sha256": "56760638e3e0fe926fed574cbe9f623e3797e7345d1a351cb7591eb139e95218",
        "reset_sha256": "d4311b30e31dbd49a0e3f854c60eee8ed08d11796e13aacd914bf94e6b959b52",
        "operator_has_reset": True,
        "operator_has_cleanup_panel": False,
        "reset_has_receipt": True,
        "reset_has_audit_refresh": True,
    }
    if rendering != expected_rendering:
        fail(f"operator/reset rendering changed: {rendering}")
    print("PASS: dead operator wrapper removed without changing rendered behavior")

    legacy_test = ROOT / "tests/test_deltaaegis_v02.py"
    current_test = ROOT / "tests/test_deltaaegis_core_regressions.py"
    if legacy_test.exists() or not current_test.is_file():
        fail("core regression test file was not renamed")
    test_source = current_test.read_text(encoding="utf-8")
    if "DeltaAegisV02Tests" in test_source or "test_deltaaegis_v02" in test_source:
        fail("core regression tests retain release-specific names")
    if "class DeltaAegisCoreRegressionTests(unittest.TestCase):" not in test_source:
        fail("core regression test class name changed")
    print("PASS: core regression tests use release-neutral names")

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
    if payload.get("current_release_gate") != "tools/validate_v0_44_1_release_gate.sh":
        fail("troubleshooter does not select the v0.44.1 release gate")
    manifest = json.loads(read("docs/v0.44.1-validator-retirement.json"))
    expected_shell = manifest.get("expected_shell_validator_count")
    if payload.get("validator_count") != expected_shell or payload.get("integrity_ok") is not True:
        fail(
            "troubleshooter validator inventory differs from the retirement manifest: "
            f"expected {expected_shell}, found {payload.get('validator_count')}"
        )
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
    if listed.returncode or "tools/validate_v0_44_1_release_gate.sh" not in listed.stdout:
        fail("current release gate is absent from troubleshooter listing")
    print("PASS: repository-aware troubleshooter selects current v0.44.1 diagnostics")

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
        "tools/validate_v0_44_1_report_contracts.py",
        "tools/validate_v0_44_1_validator_retirement.py",
        "tools/validate_v0_44_1_data_durability_compatibility.py",
        "tools/validate_v0_44_1_release_metadata.py",
        "tools/validate_v0_44_1_release_gate.sh",
        "python3 -m unittest discover -s tests -p 'test*.py' -v",
    ):
        if marker not in ci:
            fail(f"CI is missing: {marker}")
    print("PASS: CI compiles the modular core and validates repository hygiene")

    install = read("install.sh")
    if "Running non-mutating syntax and troubleshooter checks" not in install:
        fail("install.sh still describes the old embedded bundle check")
    for marker in (
        "replace_launcher_atomically()",
        '[[ -e "$target" || -L "$target" ]]',
        'mv -fT -- "$temporary" "$target"',
        "Some overlay filesystems can transiently report",
        'Refusing to replace unmanaged launcher: $target',
    ):
        if marker not in install:
            fail(f"install.sh is missing atomic launcher marker: {marker}")
    lifecycle = read("tools/validate_v0_42_install_uninstall_lifecycle.sh")
    for marker in (
        "launcher destination confinement",
        "installer replaced an unmanaged launcher directory",
        "launcher destination confinement and atomic replacement",
    ):
        if marker not in lifecycle:
            fail(f"install lifecycle is missing launcher hardening coverage: {marker}")
    print("PASS: managed launchers use exact-target atomic replacement")

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
