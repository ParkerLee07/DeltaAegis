#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "DeltaAegis v0.41 Release Metadata Validator"
echo "============================================"

python3 -W error::SyntaxWarning - <<'PY'
from pathlib import Path
import ast
import subprocess

BASELINE = "2a2ca3424517fe83cedf253998830a269d061e7b"


def fail(message: str) -> None:
    raise SystemExit(message)


def git_lines(*args: str) -> set[str]:
    completed = subprocess.run(
        ["git", *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return {
        line.strip()
        for line in completed.stdout.splitlines()
        if line.strip()
    }


readme = Path("README.md").read_text(encoding="utf-8")
changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
source = Path("deltaaegis.py").read_text(encoding="utf-8")
notes_path = Path("RELEASE_NOTES_v0.41.0.md")
manual_path = Path("MANUAL_VERIFICATION_v0.41.0.md")
manifest_validator_path = Path(
    "tools/validate_v0_41_backup_manifest.sh"
)

for required_path in (
    notes_path,
    manual_path,
    manifest_validator_path,
):
    if not required_path.is_file():
        fail(f"missing v0.41 release file: {required_path}")

notes = notes_path.read_text(encoding="utf-8")
manual = manual_path.read_text(encoding="utf-8")
manifest_validator = manifest_validator_path.read_text(
    encoding="utf-8"
)

required_readme = (
    "## Current Release — v0.41.0",
    "**DeltaAegis v0.41.0 — Data Durability & Recovery**",
    "## Data Durability and Recovery",
    "./tools/validate_v0_41_release_gate.sh",
    "MANUAL_VERIFICATION_v0.41.0.md",
)

for marker in required_readme:
    if marker not in readme:
        fail(f"README missing v0.41 release marker: {marker}")

required_changelog = (
    "## DeltaAegis v0.41.0 — Data Durability & Recovery",
    "SQLite-consistent database backup",
    "guarded active restore execution",
    "automatic rollback",
    "release gate",
)

for marker in required_changelog:
    if marker.lower() not in changelog.lower():
        fail(f"CHANGELOG missing v0.41 release marker: {marker}")

if not changelog.startswith(
    "## DeltaAegis v0.41.0 — Data Durability & Recovery"
):
    fail("CHANGELOG does not start with the v0.41 release entry")

required_source = (
    "\"\"\"DeltaAegis v0.41.0: Data Durability & Recovery.",
    'DELTAAEGIS_VERSION = "0.41.0"',
    "v0.41 Data Durability &amp; Recovery",
    'server_version = "DeltaAegisDashboard/0.41.0"',
    "DeltaAegis v0.41.0 — Data Durability & Recovery",
    '"deltaaegis-backup-manifest-v1"',
    '"deltaaegis-restore-cutover-plan-v1"',
    '"deltaaegis-restore-cutover-receipt-v1"',
)

for marker in required_source:
    if marker not in source:
        fail(f"deltaaegis.py missing v0.41 release marker: {marker}")

for forbidden in (
    "\"\"\"DeltaAegis v0.40.0:",
    'server_version = "DeltaAegisDashboard/0.40.0"',
    'description="DeltaAegis v0.40.0',
    'DELTAAEGIS_VERSION = "0.41.0-dev"',
):
    if forbidden in source:
        fail(f"stale or prerelease source copy remains: {forbidden}")

if "0.41.0-dev" in manifest_validator:
    fail("backup manifest validator still expects a development version")

if 'DELTAAEGIS_VERSION = "0.41.0"' not in manifest_validator:
    fail("backup manifest validator does not expect stable v0.41.0")

if '"version": "0.41.0"' not in manifest_validator:
    fail("backup manifest fixture does not expect stable v0.41.0")

required_notes = (
    "# DeltaAegis v0.41.0 — Data Durability & Recovery",
    "SQLite-consistent backup bundles",
    "Guarded retention",
    "Guarded active restore and rollback",
    "RESTORE ACTIVE DELTAAEGIS DATABASE",
)

for marker in required_notes:
    if marker not in notes:
        fail(f"release notes missing v0.41 detail: {marker}")

required_manual = (
    "# DeltaAegis v0.41.0 Manual Verification",
    "HOLD — do not push, merge, tag, or publish",
    "Parker explicitly authorizes pushing",
)

for marker in required_manual:
    if marker not in manual:
        fail(f"manual checklist missing required item: {marker}")

expected_executable_validators = (
    "tools/validate_v0_41_backup_foundation.sh",
    "tools/validate_v0_41_backup_manifest.sh",
    "tools/validate_v0_41_restore_rehearsal.sh",
    "tools/validate_v0_41_backup_catalog.sh",
    "tools/validate_v0_41_backup_retention_preview.sh",
    "tools/validate_v0_41_backup_retention_execution.sh",
    "tools/validate_v0_41_restore_cutover_preview.sh",
    "tools/validate_v0_41_restore_cutover_execution.sh",
    "tools/validate_v0_41_documentation_accuracy.sh",
    "tools/validate_v0_41_release_metadata.sh",
    "tools/validate_v0_41_release_gate.sh",
    "tools/validate_v0_41_v0_40_compatibility.sh",
)

for name in expected_executable_validators:
    validator = Path(name)
    if (
        not validator.is_file()
        or not validator.stat().st_mode & 0o111
    ):
        fail(f"missing or non-executable v0.41 validator: {name}")

expected_release_paths = {
    ".gitignore",
    "deltaaegis.py",
    "README.md",
    "CHANGELOG.md",
    "RELEASE_NOTES_v0.41.0.md",
    "MANUAL_VERIFICATION_v0.41.0.md",
    *expected_executable_validators,
}

try:
    changed_paths = git_lines(
        "diff",
        "--name-only",
        f"{BASELINE}..HEAD",
    )
except subprocess.CalledProcessError as exc:
    fail(f"could not compare against v0.41 baseline: {exc}")

unexpected_paths = sorted(
    changed_paths - expected_release_paths
)
missing_paths = sorted(
    expected_release_paths - changed_paths
)

if unexpected_paths:
    fail(
        "unexpected paths in the v0.41 release diff: "
        + ", ".join(unexpected_paths)
    )

if missing_paths:
    fail(
        "expected v0.41 release paths are missing: "
        + ", ".join(missing_paths)
    )

if git_lines("ls-files", "deltaaegis.db"):
    fail("legacy root-level deltaaegis.db must not be tracked")

ignore_check = subprocess.run(
    [
        "git",
        "check-ignore",
        "-q",
        "--no-index",
        "--",
        "deltaaegis.db",
    ],
    check=False,
)

if ignore_check.returncode != 0:
    fail("legacy root-level deltaaegis.db is not ignored")

tree = ast.parse(source)
assignments = {
    node.targets[0].id: node.value.value
    for node in ast.walk(tree)
    if isinstance(node, ast.Assign)
    and len(node.targets) == 1
    and isinstance(node.targets[0], ast.Name)
    and isinstance(node.value, ast.Constant)
    and isinstance(node.value.value, str)
}

if assignments.get("DELTAAEGIS_VERSION") != "0.41.0":
    fail("DELTAAEGIS_VERSION AST value is not stable v0.41.0")

print("PASS: README v0.41 release metadata")
print("PASS: CHANGELOG v0.41 release history")
print("PASS: source and dashboard v0.41 metadata")
print("PASS: stable backup-manifest version metadata")
print("PASS: release notes and manual hold")
print("PASS: v0.41 validator inventory")
print("PASS: v0.41 baseline-to-release path audit")
print("PASS: legacy root database remains ignored and untracked")
PY

echo "[v0.41 metadata] CLI help smoke test"

python3 - <<'PY'
import subprocess

completed = subprocess.run(
    ["python3", "deltaaegis.py", "--help"],
    check=True,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
)

normalized = " ".join(completed.stdout.split())
expected = "DeltaAegis v0.41.0 — Data Durability & Recovery"

if expected not in normalized:
    raise SystemExit(
        f"CLI help missing v0.41 release title: {expected}\n"
        f"Normalized output:\n{normalized}"
    )

for command in (
    "backup",
    "restore-rehearsal",
    "backup-catalog",
    "backup-verify",
    "backup-retention-preview",
    "backup-retention-execute",
    "restore-cutover-preview",
    "restore-cutover-execute",
):
    if command not in normalized:
        raise SystemExit(
            f"CLI help missing v0.41 command: {command}"
        )

print("PASS: CLI help v0.41 release title and command inventory")
PY

echo "PASS: DeltaAegis v0.41 release metadata validator"
