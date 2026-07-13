#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "DeltaAegis v0.42 Documentation Accuracy Validator"
echo "==================================================="

python3 - <<'PY'
from pathlib import Path
import subprocess

readme = Path("README.md").read_text(encoding="utf-8")
changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
licensing = Path("LICENSING.md").read_text(encoding="utf-8")

required_readme = (
    "## Current Release — v0.42.2",
    "**DeltaAegis v0.42.2 — Authorization and Integrity Hardening**",
    "## Scan Watchdog and Scheduler Recovery",
    "## Scheduled Scan Finalization Recovery",
    "## TrueAegis Tab Containment",
    "## Sites Dashboard Management",
    "## Logical Site Scopes",
    "one logical site -> many private CIDR subnet scopes",
    "one subnet scope -> zero or one logical site",
    "NetSniper scans remain CIDR-targeted",
    "TrueAegis execution remains subnet-specific",
    "dashboard --lan --port 8090",
    "--db /tmp/deltaaegis-site-rehearsal.db",
    "tools/validate_v0_42_release_gate.sh",
    "AGPL-3.0-only",
    "LICENSING.md",
)

for marker in required_readme:
    if marker not in readme:
        raise SystemExit(f"README missing v0.42 claim: {marker}")

current_start = readme.index("## Current Release")
current_end = readme.find("\n## ", current_start + 4)
current = (
    readme[current_start:]
    if current_end < 0
    else readme[current_start:current_end]
)

if "v0.41.0" in current:
    raise SystemExit(
        "README Current Release section still contains v0.41.0"
    )

if not changelog.startswith(
    "## DeltaAegis v0.42.2 — Authorization and Integrity Hardening"
):
    raise SystemExit("CHANGELOG does not begin with v0.42.2")

required_changelog = (
    "dead-scan watchdog",
    "Reconciled orphaned successful scheduled scans",
    "Sites dashboard",
    "TrueAegis",
    "one logical site per subnet",
    "NetSniper",
    "guarded LAN dashboard binding",
    "evidence-freshness strip",
    "thirteen focused v0.42 component validators",
    "operator-managed release verification",
    "AGPL-3.0-only",
)

for marker in required_changelog:
    if marker.casefold() not in changelog.casefold():
        raise SystemExit(
            f"CHANGELOG missing consolidated v0.42 claim: {marker}"
        )

for marker in (
    "# DeltaAegis Licensing",
    "AGPL-3.0-only",
    "Alternative commercial licensing",
    "already distributed under the MIT License",
):
    if marker not in licensing:
        raise SystemExit(
            f"LICENSING.md missing required documentation: {marker}"
        )

for forbidden in (
    Path("RELEASE_CHECKLIST.md"),
    *Path(".").glob("RELEASE_NOTES_v*.md"),
    *Path(".").glob("MANUAL_VERIFICATION_v*.md"),
):
    if forbidden.exists():
        raise SystemExit(
            f"version-specific or manual checklist file remains: {forbidden}"
        )

tracked = subprocess.run(
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

if tracked:
    raise SystemExit(
        "manual/version-specific release documents remain tracked: "
        + ", ".join(tracked)
    )

for filename, content in (
    ("README.md", readme),
    ("CHANGELOG.md", changelog),
):
    if "RELEASE_CHECKLIST.md" in content:
        raise SystemExit(
            f"{filename} still points to a tracked manual checklist"
        )

print("PASS: README current release and logical-site documentation")
print("PASS: CHANGELOG is the cumulative tracked release history")
print("PASS: v0.42 AGPL and commercial-licensing documentation")
print("PASS: manual verification is operator-managed, not repository-tracked")
print("PASS: version-specific release documents are not tracked")
PY

echo "PASS: DeltaAegis v0.42 documentation accuracy validator"
echo "PASS: dashboard evidence freshness documentation"
