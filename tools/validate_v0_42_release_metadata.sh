#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "DeltaAegis v0.42 Release Metadata Validator"
echo "============================================="

branch="$(git branch --show-current)"

case "$branch" in
  feature/v0.42-logical-site-scopes|main)
    ;;
  *)
    echo "ERROR: unsupported v0.42 release branch: $branch" >&2
    exit 1
    ;;
esac

python3 - <<'PY'
from pathlib import Path
import ast
import re
import subprocess
import sys

source_path = Path("deltaaegis.py")
source = source_path.read_text(encoding="utf-8")
tree = ast.parse(source)

version = None
for node in tree.body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "DELTAAEGIS_VERSION":
                if isinstance(node.value, ast.Constant):
                    version = node.value.value
    elif isinstance(node, ast.AnnAssign):
        target = node.target
        if isinstance(target, ast.Name) and target.id == "DELTAAEGIS_VERSION":
            if isinstance(node.value, ast.Constant):
                version = node.value.value

if version != "0.42.0":
    raise SystemExit(
        f"DELTAAEGIS_VERSION is {version!r}, expected '0.42.0'"
    )

module_docstring = ast.get_docstring(tree, clean=False) or ""

if not module_docstring.startswith(
    "DeltaAegis v0.42.0: Logical Site Scopes."
):
    raise SystemExit(
        "module docstring does not identify v0.42.0"
    )

required_source_metadata = (
    'DELTAAEGIS_VERSION = "0.42.0"',
    "v0.42 Logical Site Scopes",
    'server_version = "DeltaAegisDashboard/0.42.0"',
    "DeltaAegis v0.42.0 — Logical Site Scopes",
)

for marker in required_source_metadata:
    if marker not in source:
        raise SystemExit(
            f"deltaaegis.py missing v0.42 source metadata: {marker}"
        )

for stale in (
    'DELTAAEGIS_VERSION = "0.41.0"',
    "v0.41 Data Durability &amp; Recovery",
    'server_version = "DeltaAegisDashboard/0.41.0"',
    "DeltaAegis v0.41.0 — Data Durability & Recovery,",
):
    if stale in source:
        raise SystemExit(
            f"stale v0.41 source metadata remains: {stale}"
        )

help_text = subprocess.run(
    [sys.executable, "deltaaegis.py", "--help"],
    check=True,
    capture_output=True,
    text=True,
).stdout

if "DeltaAegis v0.42.0 — Logical Site Scopes" not in help_text:
    raise SystemExit("CLI help does not identify v0.42.0")

readme = Path("README.md").read_text(encoding="utf-8")
changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
notes = Path("RELEASE_NOTES_v0.42.0.md").read_text(
    encoding="utf-8"
)
manual = Path("MANUAL_VERIFICATION_v0.42.0.md").read_text(
    encoding="utf-8"
)
all_in = Path("tools/validate_v0_42_all.sh").read_text(
    encoding="utf-8"
)
release_gate = Path(
    "tools/validate_v0_42_release_gate.sh"
).read_text(encoding="utf-8")

for marker in (
    "## Current Release — v0.42.0",
    "**DeltaAegis v0.42.0 — Logical Site Scopes**",
    "tools/validate_v0_42_release_gate.sh",
    "MANUAL_VERIFICATION_v0.42.0.md",
):
    if marker not in readme:
        raise SystemExit(f"README missing release marker: {marker}")

if not changelog.startswith(
    "## DeltaAegis v0.42.0 — Logical Site Scopes"
):
    raise SystemExit("CHANGELOG top release is not v0.42.0")

if not notes.startswith(
    "# DeltaAegis v0.42.0 — Logical Site Scopes"
):
    raise SystemExit("release notes title is incorrect")

if not manual.startswith(
    "# DeltaAegis v0.42.0 Manual Verification"
):
    raise SystemExit("manual verification title is incorrect")

component_validators = (
    "tools/validate_v0_42_logical_site_foundation.sh",
    "tools/validate_v0_42_dashboard_lan_flag.sh",
    "tools/validate_v0_42_scan_watchdog.sh",
    "tools/validate_v0_42_logical_site_cli.sh",
    "tools/validate_v0_42_logical_site_dashboard_foundation.sh",
    "tools/validate_v0_42_logical_site_aggregation.sh",
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
    "tools/validate_v0_41_v0_40_compatibility.sh",
    "tools/validate_v0_40_v0_39_compatibility.sh",
    "MANUAL_VERIFICATION_v0.42.0.md",
):
    if required not in release_gate:
        raise SystemExit(
            f"release gate missing required check: {required}"
        )

for forbidden in (
    "validate_v0_41_release_gate.sh",
    "validate_v0_41_release_metadata.sh",
    "validate_v0_40_release_metadata.sh",
):
    if forbidden in release_gate:
        raise SystemExit(
            f"release gate must not invoke stale metadata gate: {forbidden}"
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

if "Site-wide SIEM aggregation is not enabled" in source:
    raise SystemExit("stale pre-aggregation dashboard warning remains")

print("PASS: stable v0.42.0 source and CLI metadata")
print("PASS: README, CHANGELOG, release notes, and manual metadata")
print("PASS: flat six-validator all-in composition")
print("PASS: feature-branch and main release paths")
print("PASS: release gate dependencies and stale-gate exclusion")
PY

echo "PASS: DeltaAegis v0.42 release metadata validator"
