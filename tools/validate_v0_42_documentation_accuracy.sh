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
checklist = Path("RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
licensing = Path("LICENSING.md").read_text(encoding="utf-8")

required_readme = (
    "## Current Release — v0.42.0",
    "**DeltaAegis v0.42.0 — Logical Site Scopes**",
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
    "RELEASE_CHECKLIST.md",
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
    "## DeltaAegis v0.42.0 — Logical Site Scopes"
):
    raise SystemExit("CHANGELOG does not begin with v0.42.0")

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
    "rolling release checklist",
    "AGPL-3.0-only",
)

for marker in required_changelog:
    if marker.casefold() not in changelog.casefold():
        raise SystemExit(
            f"CHANGELOG missing consolidated v0.42 claim: {marker}"
        )

required_checklist = (
    "# DeltaAegis Release Checklist",
    "Current candidate: **DeltaAegis v0.42.0 — Logical Site Scopes**",
    "## Release documentation policy",
    "## License transition checks",
    "Use a temporary database.",
    "## 7. Dead-scan watchdog and scheduler recovery",
    "## 7B. Sites dashboard management",
    "## 7C. TrueAegis tab containment",
    "## 7D. Scheduled scan finalization recovery",
    "## 7F. Dashboard evidence freshness",
    '--db "$tmp_db"',
    "scope` and `site_id",
    "0.0.0.0:8092",
    "Run the clean release gate again on merged `main`.",
    "GitHub Release body",
    "canonical detailed release narrative",
    "Parker's explicit approval",
    "DeltaAegis v0.42.0 — Logical Site Scopes",
    "AGPL-3.0-only",
    "LICENSING.md",
)

for marker in required_checklist:
    if marker not in checklist:
        raise SystemExit(
            f"release checklist missing required item: {marker}"
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

versioned_patterns = (
    "RELEASE_NOTES_v*.md",
    "MANUAL_VERIFICATION_v*.md",
)

tracked = subprocess.run(
    ["git", "ls-files", "--", *versioned_patterns],
    check=True,
    capture_output=True,
    text=True,
).stdout.splitlines()

if tracked:
    raise SystemExit(
        "version-specific release documents remain tracked: "
        + ", ".join(tracked)
    )

present = sorted(
    str(path)
    for pattern in versioned_patterns
    for path in Path(".").glob(pattern)
)

if present:
    raise SystemExit(
        "version-specific release documents remain in the tree: "
        + ", ".join(present)
    )

for filename, content in (
    ("README.md", readme),
    ("RELEASE_CHECKLIST.md", checklist),
):
    for stale_prefix in (
        "RELEASE_NOTES_v",
        "MANUAL_VERIFICATION_v",
    ):
        if stale_prefix in content:
            raise SystemExit(
                f"{filename} still points to a version-specific "
                f"release document: {stale_prefix}"
            )

print("PASS: README current release and logical-site documentation")
print("PASS: CHANGELOG is the cumulative tracked release history")
print("PASS: rolling release checklist and publication hold")
print("PASS: v0.42 AGPL and commercial-licensing documentation")
print("PASS: version-specific release documents are not tracked")
PY

echo "PASS: DeltaAegis v0.42 documentation accuracy validator"
echo "PASS: dashboard evidence freshness documentation"
