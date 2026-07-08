#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "DeltaAegis v0.41 Documentation Accuracy Validator"
echo "=================================================="

python3 - <<'PY'
from pathlib import Path

readme = Path("README.md").read_text(encoding="utf-8")
notes = Path("RELEASE_NOTES_v0.41.0.md").read_text(
    encoding="utf-8"
)
manual = Path("MANUAL_VERIFICATION_v0.41.0.md").read_text(
    encoding="utf-8"
)

required_readme = (
    "## Current Release — v0.41.0",
    "**DeltaAegis v0.41.0 — Data Durability & Recovery**",
    "## Data Durability and Recovery",
    "data/deltaaegis.db",
    "backup-catalog",
    "backup-verify",
    "restore-rehearsal",
    "backup-retention-preview",
    "backup-retention-execute",
    "restore-cutover-preview",
    "restore-cutover-execute",
    "DELETE ELIGIBLE BACKUP BUNDLES",
    "RESTORE ACTIVE DELTAAEGIS DATABASE",
    "ignored root-level `deltaaegis.db`",
    "./tools/validate_v0_41_release_gate.sh",
    "MANUAL_VERIFICATION_v0.41.0.md",
)

for marker in required_readme:
    if marker not in readme:
        raise SystemExit(
            f"README missing v0.41 documentation marker: {marker}"
        )

current_section = readme.split(
    "## What DeltaAegis Does",
    1,
)[0]

for stale in (
    "## Current Release — v0.40.0",
    "**DeltaAegis v0.40.0 — Human-Readable Operator Actions**",
):
    if stale in current_section:
        raise SystemExit(
            f"README current-release section is stale: {stale}"
        )

validation_section = readme.split(
    "## Validation",
    1,
)[1].split(
    "## Scope and Limitations",
    1,
)[0]

if "validate_v0_40_release_gate.sh" in validation_section:
    raise SystemExit(
        "README validation section still points to the v0.40 gate"
    )

required_notes = (
    "# DeltaAegis v0.41.0 — Data Durability & Recovery",
    "SQLite-consistent backup bundles",
    "Verification, catalog, and restore rehearsal",
    "Guarded retention",
    "Active restore cutover planning",
    "Guarded active restore and rollback",
    "Database path policy",
    "Security boundaries",
    "validate_v0_41_release_gate.sh",
)

for marker in required_notes:
    if marker not in notes:
        raise SystemExit(
            f"release notes missing v0.41 marker: {marker}"
        )

required_manual = (
    "# DeltaAegis v0.41.0 Manual Verification",
    "HOLD — do not push, merge, tag, or publish",
    "Paths and legacy database state",
    "Backup creation and manifests",
    "Retention execution",
    "Active restore preview",
    "Active restore execution and rollback",
    "Parker explicitly authorizes pushing",
)

for marker in required_manual:
    if marker not in manual:
        raise SystemExit(
            f"manual verification missing marker: {marker}"
        )

print("PASS: README durability and recovery accuracy")
print("PASS: release-note durability and recovery accuracy")
print("PASS: manual-verification publication hold")
PY

echo "PASS: DeltaAegis v0.41 documentation accuracy"
