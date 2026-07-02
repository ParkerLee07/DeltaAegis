#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

python3 - <<'PY'
from pathlib import Path
import re

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = [
    "DeltaAegis v0.36.0",
    "function dashboardLocalTimeZone()",
    "function parseDashboardDateTime(value)",
    "function dashboardTimeZoneAbbreviation(dateValue)",
    "function formatDashboardDateTime(value)",
    "function formatDashboardDateTimeCell(value)",
    "Intl.DateTimeFormat().resolvedOptions().timeZone",
    'timeZoneName: "short"',
    '<time datetime="${esc(raw)}" title="${esc(raw)}">${esc(formatted)}</time>',
    "formatDashboardDateTimeCell(job.completed_at || job.started_at || job.created_at)",
]

for needle in required:
    if needle not in text:
        raise SystemExit(f"[FAIL] missing local time formatting requirement: {needle}")

scan_start = text.find("function scanTimestamp(scan)")
if scan_start < 0:
    raise SystemExit("[FAIL] could not inspect scanTimestamp block")
scan_end = text.find("function formatPercent", scan_start)
if scan_end < 0:
    raise SystemExit("[FAIL] could not bound scanTimestamp block")
scan_block = text[scan_start:scan_end]
if "formatDashboardDateTime(" not in scan_block:
    raise SystemExit("[FAIL] scanTimestamp must use local dashboard time formatting")

job_start = text.find("function deltaAegisTrueAegisJobRows(jobs)")
if job_start < 0:
    raise SystemExit("[FAIL] TrueAegis job renderer missing")
job_end = text.find("function deltaAegisTrueAegisOrchestrationRender", job_start)
if job_end < 0:
    raise SystemExit("[FAIL] could not bound TrueAegis job renderer")
job_block = text[job_start:job_end]
if "formatDashboardDateTimeCell(job.completed_at || job.started_at || job.created_at)" not in job_block:
    raise SystemExit("[FAIL] TrueAegis job renderer must use formatted local time cells")
if "job.completed_at || job.started_at || job.created_at || \"-\"" in job_block:
    raise SystemExit("[FAIL] TrueAegis job renderer still has raw fallback timestamp rendering")


taxonomy_required = [
    "formatDashboardDateTimeCell(asset.first_seen_at)",
    "formatDashboardDateTimeCell(asset.last_seen_at)",
    "formatDashboardDateTimeCell(row.last_seen_at)",
]

for needle in taxonomy_required:
    if needle not in text:
        raise SystemExit(f"[FAIL] missing taxonomy/asset local time formatting: {needle}")

raw_frontend_timestamp_patterns = [
    "${esc(asset.first_seen_at)}",
    "${esc(asset.last_seen_at)}",
    "${esc(row.last_seen_at)}",
]

for needle in raw_frontend_timestamp_patterns:
    if needle in text:
        raise SystemExit(f"[FAIL] raw frontend timestamp render remains: {needle}")


print("[PASS] v0.36 local dashboard time formatting python checks passed")
PY

echo "[PASS] DeltaAegis v0.36 local dashboard time formatting validation passed"
