#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "DeltaAegis v0.42 Release Metadata Validator"
echo "============================================="

branch="$(git branch --show-current)"

case "$branch" in
  feature/v0.42-logical-site-scopes|release/v0.42.1|main)
    ;;
  *)
    echo "ERROR: unsupported v0.42 release branch: $branch" >&2
    exit 1
    ;;
esac

python3 - <<'PY'
from pathlib import Path
import ast
import hashlib
import re
import subprocess
import sys

source = Path("deltaaegis.py").read_text(encoding="utf-8")
tree = ast.parse(source)

version = None
for node in tree.body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id == "DELTAAEGIS_VERSION"
                and isinstance(node.value, ast.Constant)
            ):
                version = node.value.value
    elif isinstance(node, ast.AnnAssign):
        if (
            isinstance(node.target, ast.Name)
            and node.target.id == "DELTAAEGIS_VERSION"
            and isinstance(node.value, ast.Constant)
        ):
            version = node.value.value

if version != "0.42.1":
    raise SystemExit(
        f"DELTAAEGIS_VERSION is {version!r}, expected '0.42.1'"
    )

module_docstring = ast.get_docstring(tree, clean=False) or ""
if not module_docstring.startswith(
    "DeltaAegis v0.42.1: Security and Integrity Maintenance."
):
    raise SystemExit(
        "module docstring does not identify v0.42.1"
    )

for marker in (
    'DELTAAEGIS_VERSION = "0.42.1"',
    "v0.42 Logical Site Scopes",
    'server_version = "DeltaAegisDashboard/0.42.1"',
    "DeltaAegis v0.42.1 — Security and Integrity Maintenance",
    "SPDX-License-Identifier: AGPL-3.0-only",
    'data-deltaaegis-license="AGPL-3.0-only"',
):
    if marker not in source:
        raise SystemExit(
            f"deltaaegis.py missing v0.42 source metadata: {marker}"
        )

help_text = subprocess.run(
    [sys.executable, "deltaaegis.py", "--help"],
    check=True,
    capture_output=True,
    text=True,
).stdout

if "DeltaAegis v0.42.1 — Security and Integrity Maintenance" not in help_text:
    raise SystemExit("CLI help does not identify v0.42.1")

readme = Path("README.md").read_text(encoding="utf-8")
changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
licensing = Path("LICENSING.md").read_text(encoding="utf-8")
license_bytes = Path("LICENSE").read_bytes()
all_in = Path("tools/validate_v0_42_all.sh").read_text(
    encoding="utf-8"
)
release_gate = Path(
    "tools/validate_v0_42_release_gate.sh"
).read_text(encoding="utf-8")

for marker in (
    "## Current Release — v0.42.1",
    "**DeltaAegis v0.42.1 — Security and Integrity Maintenance**",
    "tools/validate_v0_42_release_gate.sh",
    "AGPL-3.0-only",
    "LICENSING.md",
):
    if marker not in readme:
        raise SystemExit(f"README missing release marker: {marker}")

if not changelog.startswith(
    "## DeltaAegis v0.42.1 — Security and Integrity Maintenance"
):
    raise SystemExit("CHANGELOG top release is not v0.42.1")

if hashlib.sha256(license_bytes).hexdigest() != (
    "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0"
):
    raise SystemExit("LICENSE is not the approved AGPL-3.0 text")

for marker in (
    "# DeltaAegis Licensing",
    "AGPL-3.0-only",
    "Alternative commercial licensing",
):
    if marker not in licensing:
        raise SystemExit(f"LICENSING.md missing marker: {marker}")

component_validators = (
    "tools/validate_v0_42_logical_site_foundation.sh",
    "tools/validate_v0_42_dashboard_lan_flag.sh",
    "tools/validate_v0_42_scan_watchdog.sh",
    "tools/validate_v0_42_sites_management.sh",
    "tools/validate_v0_42_dashboard_freshness_foundation.sh",
    "tools/validate_v0_42_dashboard_asset_selector_completeness.sh",
    "tools/validate_v0_42_trueaegis_tab_containment.sh",
    "tools/validate_v0_42_schedule_finalization_recovery.sh",
    "tools/validate_v0_42_logical_site_cli.sh",
    "tools/validate_v0_42_logical_site_dashboard_foundation.sh",
    "tools/validate_v0_42_logical_site_aggregation.sh",
    "tools/validate_v0_42_install_uninstall_lifecycle.sh",
    "tools/validate_v0_42_license_policy.sh",
)

for validator in component_validators:
    if all_in.count(validator) != 1:
        raise SystemExit(
            f"v0.42 all-in validator must invoke exactly once: {validator}"
        )

if release_gate.count("tools/validate_v0_42_all.sh") != 1:
    raise SystemExit(
        "release gate must invoke validate_v0_42_all.sh exactly once"
    )

for required in (
    "tools/validate_v0_42_documentation_accuracy.sh",
    "tools/validate_v0_42_release_metadata.sh",
    "tools/validate_v0_40_dashboard_javascript_syntax.sh",
    "tools/validate_v0_40_broken_pipe_response.sh",
    "tools/validate_v0_42_security_hotfix.py",
    "tools/validate_v0_41_v0_40_compatibility.sh",
    "tools/validate_v0_40_v0_39_compatibility.sh",
    "Parker's explicit approval",
):
    if required not in release_gate:
        raise SystemExit(
            f"release gate missing required check: {required}"
        )

if "RELEASE_CHECKLIST.md" in release_gate:
    raise SystemExit(
        "release gate still depends on a tracked manual checklist"
    )

for validator in component_validators:
    body = Path(validator).read_text(encoding="utf-8")
    nested = re.findall(
        r'(?:\./)?tools/validate_v0_42_[A-Za-z0-9_]+\.sh',
        body,
    )
    if nested:
        raise SystemExit(
            f"component validator is not flat: {validator}: {nested}"
        )

tracked_manual_docs = subprocess.run(
    [
        "git",
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

if tracked_manual_docs:
    raise SystemExit(
        "manual/version-specific release documents remain tracked: "
        + ", ".join(tracked_manual_docs)
    )

print("PASS: stable v0.42.1 source and CLI metadata")
print("PASS: README, CHANGELOG, and licensing metadata")
print("PASS: flat thirteen-validator all-in composition")
print("PASS: feature, release, and main branch paths")
print("PASS: release gate dependencies and explicit approval hold")
print("PASS: operator-managed release verification policy")
PY

echo "PASS: DeltaAegis v0.42 release metadata validator"
