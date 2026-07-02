#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[INFO] Running DeltaAegis v0.37 release validation..."

python3 -m py_compile deltaaegis.py

required_source_strings=(
  'DeltaAegis v0.37.0'
  'v0.37 Operator Evidence Review'
  'Operator evidence review'
  '"/api/netsniper/schedule-history"'
  '"/api/telemetry-cleanup/audit-events"'
  '"/api/latest-network-changes"'
  '"/api/scan-freshness"'
  'Recent Telemetry Reset Audit Events'
  'Latest Network Changes'
  'Scan Freshness'
  'TELEMETRY_CLEANUP_CLEAR_ALL'
  'NO_ACCEPTED_SCAN'
  'FRESH'
  'AGING'
  'STALE'
)

for needle in "${required_source_strings[@]}"; do
  if ! grep -Fq "$needle" deltaaegis.py; then
    echo "[FAIL] missing required v0.37 source string: $needle" >&2
    exit 1
  fi
done

required_readme_strings=(
  '## Current Release — v0.37.0'
  '**DeltaAegis v0.37.0 — Operator Evidence Review**'
  'schedule-driven NetSniper run history'
  'telemetry reset audit visibility'
  'latest-network-change summaries'
  'scan-freshness warnings'
  '/operator/reset'
  'does not expose arbitrary shell command execution'
  'Automatic TrueAegis execution from scheduled NetSniper scans is not enabled by default.'
)

for needle in "${required_readme_strings[@]}"; do
  if ! grep -Fq "$needle" README.md; then
    echo "[FAIL] missing required v0.37 README string: $needle" >&2
    exit 1
  fi
done

required_changelog_strings=(
  '## DeltaAegis v0.37.0 — Operator Evidence Review'
  'validate_v0_37_release.sh'
  '/api/netsniper/schedule-history'
  '/api/telemetry-cleanup/audit-events'
  '/api/latest-network-changes'
  '/api/scan-freshness'
  'FRESH'
  'AGING'
  'STALE'
  'NO_ACCEPTED_SCAN'
)

for needle in "${required_changelog_strings[@]}"; do
  if ! grep -Fq "$needle" CHANGELOG.md; then
    echo "[FAIL] missing required v0.37 CHANGELOG string: $needle" >&2
    exit 1
  fi
done

for stale in \
  '## Current Release — v0.36.0' \
  '**DeltaAegis v0.36.0 — Dashboard Operations Automation**' \
  'v0.36 Dashboard Operations Automation' \
  'description="DeltaAegis v0.36.0' \
  'Raw NetSniper scan execution from the dashboard is intentionally deferred'
do
  if grep -Fq "$stale" deltaaegis.py README.md; then
    echo "[FAIL] stale current-release/security text remains: $stale" >&2
    exit 1
  fi
done

if grep -Fq 'shell=True' deltaaegis.py; then
  echo "[FAIL] v0.37 release must not use shell=True" >&2
  exit 1
fi

echo "[INFO] Running v0.37 checkpoint validators..."
time tools/validate_v0_37_schedule_id_migration_order.sh
time tools/validate_v0_37_stale_scan_recovery.sh
time tools/validate_v0_37_schedule_history.sh
time tools/validate_v0_37_reset_audit_visibility.sh
time tools/validate_v0_37_latest_change_summary.sh
time tools/validate_v0_37_scan_freshness.sh

echo "[INFO] Running v0.37-safe preserved operations checks..."

preserved_operations_strings=(
  'parseScanTime(timestamp)'
  'DASHBOARD_SCHEDULE_WORKER_INTERVAL_SECONDS = 60'
  'ADMIN-only telemetry reset'
  '"/operator/reset"'
  '"/api/telemetry-cleanup/preview"'
  '"/api/telemetry-cleanup/clear-all"'
  'TELEMETRY_CLEANUP_CONFIRMATION = "DELETE TELEMETRY"'
  'action="TELEMETRY_CLEANUP_CLEAR_ALL"'
  'DASHBOARD_SCHEDULE_WORKER_INTERVAL_SECONDS = 60'
  'dashboard_run_due_schedule_tick'
  'run_due_scan_schedules'
  'Scheduler: enabled'
)

for needle in "${preserved_operations_strings[@]}"; do
  if ! grep -Fq "$needle" deltaaegis.py; then
    echo "[FAIL] missing preserved v0.36 operation marker: $needle" >&2
    exit 1
  fi
done

preserved_readme_strings=(
  'does not expose arbitrary shell command execution'
  'fixed argument-vector execution'
  'ADMIN-only `/operator/reset`'
  'Automatic TrueAegis execution from scheduled NetSniper scans is not enabled by default.'
)

for needle in "${preserved_readme_strings[@]}"; do
  if ! grep -Fq "$needle" README.md; then
    echo "[FAIL] missing preserved security/operations README marker: $needle" >&2
    exit 1
  fi
done

echo "[PASS] DeltaAegis v0.37 release validation passed"
