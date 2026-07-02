#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[INFO] Running DeltaAegis v0.36 release validation..."

python3 -m py_compile deltaaegis.py

required_source_strings=(
  'DeltaAegis v0.36.0'
  'v0.36 Dashboard Operations Automation'
  'Dashboard operations automation'
  'automatic scheduled NetSniper worker controls'
  'ADMIN-only telemetry reset'
  '"/operator/reset"'
  '"/api/telemetry-cleanup/preview"'
  '"/api/telemetry-cleanup/clear-all"'
  'TELEMETRY_CLEANUP_CONFIRMATION = "DELETE TELEMETRY"'
  'action="TELEMETRY_CLEANUP_CLEAR_ALL"'
  'Scheduler: enabled'
)

for needle in "${required_source_strings[@]}"; do
  if ! grep -Fq "$needle" deltaaegis.py; then
    echo "[FAIL] missing required v0.36 source string: $needle" >&2
    exit 1
  fi
done

required_readme_strings=(
  '## Current Release — v0.36.0'
  '**DeltaAegis v0.36.0 — Dashboard Operations Automation**'
  'local dashboard time formatting'
  'automatic scheduled NetSniper scan worker controls'
  'ADMIN-only telemetry reset workflow'
  '/operator/reset'
)

for needle in "${required_readme_strings[@]}"; do
  if ! grep -Fq "$needle" README.md; then
    echo "[FAIL] missing required v0.36 README string: $needle" >&2
    exit 1
  fi
done

required_changelog_strings=(
  '## DeltaAegis v0.36.0 — Dashboard Operations Automation'
  'validate_v0_36_release.sh'
  'dedicated ADMIN-only `/operator/reset`'
  'ADMIN-only telemetry cleanup preview and execution APIs'
)

for needle in "${required_changelog_strings[@]}"; do
  if ! grep -Fq "$needle" CHANGELOG.md; then
    echo "[FAIL] missing required v0.36 CHANGELOG string: $needle" >&2
    exit 1
  fi
done

for stale in \
  'v0.35 TrueAegis Orchestration' \
  'v0.34 does not change risk scoring' \
  'In v0.34, ' \
  'DeltaAegis v0.34.0 — TrueAegis Validation Correlation' \
  '## Current Release — v0.34.0' \
  'description="DeltaAegis v0.34.0'
do
  if grep -Fq "$stale" deltaaegis.py README.md; then
    echo "[FAIL] stale pre-v0.36 current-release text remains: $stale" >&2
    exit 1
  fi
done

if grep -Fq 'shell=True' deltaaegis.py; then
  echo "[FAIL] v0.36 release must not use shell=True" >&2
  exit 1
fi

time tools/validate_v0_36_local_time_formatting.sh
time tools/validate_v0_36_scheduled_scan_worker.sh
time tools/validate_v0_36_telemetry_cleanup.sh
time tools/validate_v0_36_telemetry_cleanup_dashboard_api.sh
time tools/validate_v0_36_operator_reset_page.sh

echo "[PASS] DeltaAegis v0.36 release validation passed"
