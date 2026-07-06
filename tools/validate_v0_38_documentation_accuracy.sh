#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

echo "[DeltaAegis documentation accuracy] checking README"

python3 - <<'PY'
from pathlib import Path

text = Path("README.md").read_text(encoding="utf-8")

required = [
    "run_trueaegis_after_ingest",
    "./tools/validate_v0_38_release.sh",
    "183 imported observations",
    "711 refreshed correlations",
    "guarded scan launch",
    "## Related Projects",
    "**NetSniper**",
    "**TrueAegis**",
]

for marker in required:
    if marker not in text:
        raise SystemExit(f"README missing current marker: {marker}")

for stale in [
    "NetSniper schedules run NetSniper and optional auto-ingest only",
    "./tools/validate_v0_28_release.sh",
    "Useful v0.28 validators",
    "Launch NetSniper scans from the dashboard through a guarded job runner.",
    "## Related Project\n",
]:
    if stale in text:
        raise SystemExit(f"README still contains stale claim: {stale}")

print("DeltaAegis documentation accuracy checks passed")
PY
