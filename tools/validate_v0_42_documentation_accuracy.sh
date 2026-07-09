#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "DeltaAegis v0.42 Documentation Accuracy Validator"
echo "==================================================="

python3 - <<'PY'
from pathlib import Path

readme = Path("README.md").read_text(encoding="utf-8")
changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
notes = Path("RELEASE_NOTES_v0.42.0.md").read_text(encoding="utf-8")
manual = Path("MANUAL_VERIFICATION_v0.42.0.md").read_text(
    encoding="utf-8"
)

required_readme = (
    "## Current Release — v0.42.0",
    "**DeltaAegis v0.42.0 — Logical Site Scopes**",
    "## Scan Watchdog and Scheduler Recovery",
    "## Logical Site Scopes",
    "one logical site -> many private CIDR subnet scopes",
    "one subnet scope -> zero or one logical site",
    "NetSniper scans remain CIDR-targeted",
    "TrueAegis execution remains subnet-specific",
    "dashboard --lan --port 8090",
    "--db /tmp/deltaaegis-site-rehearsal.db",
    "tools/validate_v0_42_release_gate.sh",
    "MANUAL_VERIFICATION_v0.42.0.md",
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

required_notes = (
    "# DeltaAegis v0.42.0 — Logical Site Scopes",
    "## Dead-scan watchdog and scheduler self-healing",
    "Canonical CIDR `network_scope` values remain authoritative.",
    "one subnet scope -> zero or one logical site",
    "NetSniper scan creation remains CIDR-targeted.",
    "TrueAegis execution also remains subnet-specific.",
    "No logical-site dashboard mutation endpoint is included",
    "Unathenticated LAN exposure is rejected.",
    "tools/validate_v0_42_release_gate.sh",
    "Parker's explicit approval",
)

# Keep the source wording grammatical while accepting the intended exact claim.
if "Unauthenticated LAN exposure is rejected." not in notes:
    raise SystemExit(
        "release notes do not document unauthenticated LAN rejection"
    )

for marker in required_notes:
    if marker == "Unathenticated LAN exposure is rejected.":
        continue
    if marker not in notes:
        raise SystemExit(
            f"release notes missing required claim: {marker}"
        )

required_manual = (
    "# DeltaAegis v0.42.0 Manual Verification",
    "Use a temporary database.",
    "## 7. Dead-scan watchdog and scheduler recovery",
    "--db \"$tmp_db\"",
    "scope` and `site_id",
    "0.0.0.0:8092",
    "Run the clean release gate again on merged `main`.",
    "Parker's explicit approval",
    "DeltaAegis v0.42.0 — Logical Site Scopes",
)

for marker in required_manual:
    if marker not in manual:
        raise SystemExit(
            f"manual verification missing required item: {marker}"
        )

print("PASS: README current release and logical-site documentation")
print("PASS: CHANGELOG v0.42 release entry")
print("PASS: release-note scope and safety boundaries")
print("PASS: manual verification and publication hold")
PY

echo "PASS: DeltaAegis v0.42 documentation accuracy validator"
