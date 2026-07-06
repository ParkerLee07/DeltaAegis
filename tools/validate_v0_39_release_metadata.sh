#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "DeltaAegis v0.39 Release Metadata Validator"
echo "============================================="

python3 - <<'PY'
from pathlib import Path
import subprocess


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
release_notes_path = Path("RELEASE_NOTES_v0.39.0.md")

if not release_notes_path.is_file():
    fail("missing RELEASE_NOTES_v0.39.0.md")

release_notes = release_notes_path.read_text(encoding="utf-8")

required_readme = [
    "## Current Release — v0.39.0",
    "**DeltaAegis v0.39.0 — Scan Job Lifecycle Observability**",
    "live stdout and stderr",
    "authenticated cancellation",
    "Schedule deletion preserves",
    "./tools/validate_v0_39_release_gate.sh",
    "Treat schedule deletion as scan cancellation",
]

for needle in required_readme:
    if needle not in readme:
        fail(f"README missing v0.39 release marker: {needle}")

if readme.find("## Current Release — v0.39.0") < 0:
    fail("README does not contain the v0.39 current-release heading")

old_current = readme.find("## Current Release — v0.38.0")
new_current = readme.find("## Current Release — v0.39.0")

if old_current >= 0 and old_current < new_current:
    fail("README still presents v0.38 before the v0.39 current release")

if not changelog.startswith(
    "## DeltaAegis v0.39.0 — Scan Job Lifecycle Observability"
):
    fail("CHANGELOG does not begin with the v0.39 release section")

required_changelog = [
    "persistent scan-job lifecycle",
    "live stdout and stderr",
    "authenticated cancellation API",
    "worker-owned process-group termination",
    "schedule-deletion tombstone",
    "linked jobs remain unchanged",
    "validate_v0_39_release_gate.sh",
]

for needle in required_changelog:
    if needle not in changelog:
        fail(f"CHANGELOG missing v0.39 release detail: {needle}")

if "## DeltaAegis v0.38.0 — TrueAegis Follow-Up Automation" not in changelog:
    fail("v0.38 changelog history was not preserved")

required_source = [
    '"""DeltaAegis v0.39.0: Scan Job Lifecycle Observability.',
    "v0.39 Scan Job Lifecycle Observability",
    'server_version = "DeltaAegisDashboard/0.39.0"',
    "DeltaAegis v0.39.0 — Scan Job Lifecycle Observability",
    "netsniper-live-job-cancel-form",
    "/api/netsniper/scan-cancel",
    "scan_schedule_deletions",
]

for needle in required_source:
    if needle not in source:
        fail(f"deltaaegis.py missing v0.39 release marker: {needle}")

for forbidden in [
    '"""DeltaAegis v0.38.0:',
    "Release</span><span>v0.38",
    'server_version = "DeltaAegisDashboard/0.5.0"',
    'description="DeltaAegis v0.38.0',
    "v0.39.0-dev",
]:
    if forbidden in source:
        fail(f"stale or prerelease source copy remains: {forbidden}")

required_notes = [
    "# DeltaAegis v0.39.0 — Scan Job Lifecycle Observability",
    "Live execution evidence",
    "Authenticated cancellation",
    "Non-destructive schedule deletion",
    "browser-supplied PID",
    "validate_v0_39_release_gate.sh",
]

for needle in required_notes:
    if needle not in release_notes:
        fail(f"release notes missing v0.39 detail: {needle}")

expected_executable_validators = [
    "tools/validate_v0_39_scan_lifecycle_storage.sh",
    "tools/validate_v0_39_live_scan_execution.sh",
    "tools/validate_v0_39_scan_job_detail_api.sh",
    "tools/validate_v0_39_dashboard_live_viewer.sh",
    "tools/validate_v0_39_dashboard_http_smoke.sh",
    "tools/validate_v0_39_cancellation_backend.sh",
    "tools/validate_v0_39_cancellation_api.sh",
    "tools/validate_v0_39_dashboard_cancellation_ux.sh",
    "tools/validate_v0_39_dashboard_cancellation_http_smoke.sh",
    "tools/validate_v0_39_schedule_deletion_semantics.sh",
    "tools/validate_v0_39_schedule_deletion_http_smoke.sh",
    "tools/validate_v0_39_v0_38_compatibility.sh",
    "tools/validate_v0_39_release_metadata.sh",
    "tools/validate_v0_39_release_gate.sh",
]

for name in expected_executable_validators:
    path = Path(name)
    if not path.is_file() or not path.stat().st_mode & 0o111:
        fail(f"missing or non-executable v0.39 validator: {name}")

allowed_branch_paths = {
    "deltaaegis.py",
    "README.md",
    "CHANGELOG.md",
    "RELEASE_NOTES_v0.39.0.md",
    "tools/validate_v0_39_cancellation_api.py",
    "tools/validate_v0_39_cancellation_api.sh",
    "tools/validate_v0_39_cancellation_backend.sh",
    "tools/validate_v0_39_dashboard_cancellation_http_smoke.py",
    "tools/validate_v0_39_dashboard_cancellation_http_smoke.sh",
    "tools/validate_v0_39_dashboard_cancellation_ux.sh",
    "tools/validate_v0_39_dashboard_http_smoke.py",
    "tools/validate_v0_39_dashboard_http_smoke.sh",
    "tools/validate_v0_39_dashboard_live_viewer.sh",
    "tools/validate_v0_39_live_scan_execution.sh",
    "tools/validate_v0_39_scan_job_detail_api.sh",
    "tools/validate_v0_39_scan_lifecycle_storage.sh",
    "tools/validate_v0_39_schedule_deletion_http_smoke.py",
    "tools/validate_v0_39_schedule_deletion_http_smoke.sh",
    "tools/validate_v0_39_schedule_deletion_semantics.sh",
    "tools/validate_v0_39_v0_38_compatibility.sh",
    "tools/validate_v0_39_release_metadata.sh",
    "tools/validate_v0_39_release_gate.sh",
}

changed_paths: set[str] = set()

try:
    changed_paths |= git_lines("diff", "--name-only", "main...HEAD")
except subprocess.CalledProcessError:
    fail("could not compare the branch against main")

changed_paths |= git_lines("diff", "--name-only")
changed_paths |= git_lines("ls-files", "--others", "--exclude-standard")

unexpected_paths = sorted(changed_paths - allowed_branch_paths)
missing_branch_paths = sorted(allowed_branch_paths - changed_paths)

if unexpected_paths:
    fail(
        "unexpected paths are present in the v0.39 branch diff: "
        + ", ".join(unexpected_paths)
    )

if missing_branch_paths:
    fail(
        "expected v0.39 release paths are missing from the branch diff: "
        + ", ".join(missing_branch_paths)
    )

print("PASS: README v0.39 release metadata")
print("PASS: CHANGELOG v0.39 release history")
print("PASS: source and dashboard v0.39 metadata")
print("PASS: release-note accuracy")
print("PASS: validator inventory")
print("PASS: branch-diff allowed-path audit")
PY

echo "[v0.39 metadata] CLI help smoke test"

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
expected = "DeltaAegis v0.39.0 — Scan Job Lifecycle Observability"

if expected not in normalized:
    raise SystemExit(
        f"CLI help missing v0.39 release title: {expected}\n"
        f"Normalized output:\n{normalized}"
    )

print("PASS: CLI help v0.39 release title")
PY

echo "PASS: DeltaAegis v0.39 release metadata validator"
