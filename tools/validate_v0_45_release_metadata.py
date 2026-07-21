#!/usr/bin/env python3
from __future__ import annotations
import ast
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {"feature/v0.45-telemetry-trust", "main"}

def require(ok: bool, message: str) -> None:
    if not ok:
        raise SystemExit(f"[FAIL] {message}")

def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

def assigned(source: str, name: str):
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return ast.literal_eval(node.value)
    raise SystemExit(f"[FAIL] missing assignment {name}")

def main() -> int:
    branch = subprocess.check_output(
        ["git", "branch", "--show-current"], cwd=ROOT, text=True
    ).strip()
    require(branch in ALLOWED, f"unsupported release branch: {branch}")

    root = read("deltaaegis.py")
    web = read("deltaaegis_core/web.py")
    readme = read("README.md")
    changelog = read("CHANGELOG.md")
    checklist = read("docs/V0_45_RELEASE_CHECKLIST.md")
    ci = read(".github/workflows/ci.yml")
    gate = read("tools/validate_v0_45_release_gate.sh")
    audit = read("docs/repository-audit.md")
    audit_tool = read("tools/audit_v0_44_repository.py")
    scope = read("V1_SCOPE.md")
    supported = read("SUPPORTED_VERSIONS.md")
    architecture = read("docs/architecture/overview.md")
    trouble = read("tools/deltaaegis_troubleshooter.py")
    trouble_doc = read("docs/TROUBLESHOOTER.md")

    require(assigned(root, "DELTAAEGIS_VERSION") == "0.45.0", "runtime version")
    module_docstring = ast.get_docstring(ast.parse(root), clean=False) or ""
    require(module_docstring.startswith("DeltaAegis v0.45.0: Telemetry Trust."),
            "module docstring")
    require("v0.45.0 Telemetry Trust" in root, "dashboard badge")
    require("DeltaAegis v0.45.0 — Telemetry Trust," in root, "CLI description")
    require('server_version = "DeltaAegisDashboard/0.45.0"' in web,
            "dashboard server version")
    require('TOOL_VERSION = "0.45.0-telemetry-trust"' in trouble,
            "troubleshooter version")

    match = re.search(
        r"^## Current Release — v0\.45\.0\n(.*?)(?=^## What DeltaAegis Does\n)",
        readme, flags=re.M | re.S
    )
    require(match is not None, "README current release")
    section = match.group(1)
    for marker in (
        "DeltaAegis v0.45.0 — Telemetry Trust",
        "ACCEPTED`, `DEGRADED`, `QUARANTINED`, and `REJECTED",
        "immutable automated-decision records",
        "state-aware ingestion effects",
        "replayable current-state projection",
        "Telemetry Quality Center",
        "NetSniper v2.1",
    ):
        require(marker in section, f"README marker {marker!r}")

    require(changelog.startswith("## DeltaAegis v0.45.0 — Telemetry Trust\n"),
            "CHANGELOG opening")
    require("broader migration-ledger, supported-upgrade,\n"
            "  or backup-integrated recovery roadmap" in changelog,
            "deferred-roadmap boundary")
    require("current through DeltaAegis v0.45.0" in scope, "V1 scope status")
    require("Status: v0.45.0 telemetry trust" in supported, "support status")
    require("Status: v0.45.0 telemetry trust on the v0.44 modular core foundation"
            in architecture, "architecture status")
    require(audit.startswith("# DeltaAegis v0.45.0 Repository Audit\n"),
            "audit title")
    require("Telemetry Trust release candidate" in audit, "audit scope")
    require("Remaining migration-ledger, supported-upgrade, and "
            "backup-integrated recovery work not delivered by v0.45.0" in audit,
            "audit deferred work")
    require("DeltaAegis v0.45.0 Repository Audit" in audit_tool,
            "audit generator title")

    for marker in (
        "Manual dashboard verification",
        "Staging and committing",
        "Pushing the feature branch",
        "Creating or updating the pull request",
        "Merging the pull request",
        "Creating or moving the annotated `v0.45.0` tag",
        "Publishing the GitHub Release",
        "Deleting the local or remote feature branch",
    ):
        require(marker in checklist, f"checklist marker {marker!r}")

    require("tools/validate_v0_45_release_gate.sh" in readme,
            "README release gate")
    require("tools/validate_v0_45_release_gate.sh" in trouble_doc,
            "troubleshooter release gate")
    require(ci.count("./tools/validate_v0_45_release_gate.sh") == 1,
            "CI release-gate count")
    require("tools/validate_v0_45_release_metadata.py" in ci,
            "CI metadata syntax")
    require("deltaaegis_core/current_state.py" in ci and
            "deltaaegis_core/telemetry_quality.py" in ci,
            "CI v0.45 modules")
    require("validate_v0_44_1_release_gate.sh" not in ci,
            "obsolete CI gate")
    require(gate.count("./tools/validate_v0_45_checkpoints_1_5_all.sh") == 1,
            "focused gate composition")
    require(gate.count("./tools/validate_v0_45_v0_44_compatibility_all.sh") == 1,
            "compatibility composition")
    require(gate.count("python3 tools/validate_v0_45_release_metadata.py") == 1,
            "metadata execution count")
    require("git status --porcelain" in gate, "clean-tree enforcement")
    require("python3 -m unittest discover -s tests -p 'test*.py' -v" in gate, "regression tests")

    print("[PASS] finalized v0.45.0 runtime, CLI, dashboard, and server metadata")
    print("[PASS] README, CHANGELOG, support status, and checklist")
    print("[PASS] deferred roadmap is not represented as delivered")
    print("[PASS] flat release-gate and CI composition")
    print("[PASS] deterministic repository audit")
    print("[PASS] DeltaAegis v0.45.0 release metadata")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
