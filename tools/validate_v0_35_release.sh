#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py


grep -Fq 'v0.35 TrueAegis Orchestration' deltaaegis.py || {
  echo "[FAIL] dashboard release badge must say v0.35 TrueAegis Orchestration" >&2
  exit 1
}

grep -Fq 'panel.dataset.tabPanel = "trueaegis";' deltaaegis.py || {
  echo "[FAIL] TrueAegis orchestration panel must render on the TrueAegis tab" >&2
  exit 1
}

if grep -Fq 'v0.34 TrueAegis Validation Correlation' deltaaegis.py; then
  echo "[FAIL] stale v0.34 dashboard release badge remains" >&2
  exit 1
fi


required_strings=(
  'DeltaAegis v0.35.0'
  'DEFAULT_TRUEAEGIS = Path.home() / "TrueAegis" / "trueaegis.py"'
  'DEFAULT_TRUEAEGIS_LOGS = Path.home() / "DeltaAegis" / "trueaegis-logs"'
  'CREATE TABLE IF NOT EXISTS trueaegis_jobs'
  '("GET", "/api/trueaegis-jobs", "dashboard.read")'
  '("GET", "/api/trueaegis/context", "dashboard.read")'
  '("POST", "/api/trueaegis/run", "scan.start")'
  'def create_trueaegis_job('
  'def dashboard_trueaegis_jobs_payload('
  'def dashboard_trueaegis_orchestration_context_payload('
  'def build_trueaegis_validation_command('
  'def execute_trueaegis_job('
  'def import_trueaegis_job_results('
  'def dashboard_trueaegis_validation_start_payload('
  'if route == "/api/trueaegis/run":'
  'trueaegis-orchestration-panel'
  'trueaegis-run-button'
  'deltaAegisTrueAegisOrchestrationRefresh'
  'validation_run_id=validation_run_id'
  'imported_observations=imported_observations'
  'correlation_count=correlation_count'
)

for needle in "${required_strings[@]}"; do
  grep -Fq "$needle" deltaaegis.py || {
    echo "[FAIL] missing required v0.35 string: $needle" >&2
    exit 1
  }
done


grep -Fq '"execution_enabled": bool(ready_to_start)' deltaaegis.py || {
  echo "[FAIL] TrueAegis context must expose execution_enabled based on ready_to_start" >&2
  exit 1
}

grep -Fq 'TrueAegis orchestration is ready to run.' deltaaegis.py || {
  echo "[FAIL] TrueAegis context ready message is missing" >&2
  exit 1
}

if grep -Fq 'execution will be added in a later checkpoint' deltaaegis.py; then
  echo "[FAIL] stale TrueAegis checkpoint message remains" >&2
  exit 1
fi

if grep -n 'shell=True' deltaaegis.py; then
  echo "[FAIL] v0.35 release must not use shell=True" >&2
  exit 1
fi

test -x tools/validate_v0_35_trueaegis_job_storage.sh
test -x tools/validate_v0_35_trueaegis_orchestration_context.sh
test -x tools/validate_v0_35_trueaegis_execution_worker.sh
test -x tools/validate_v0_35_trueaegis_auto_import.sh

time tools/validate_v0_35_trueaegis_job_storage.sh
time tools/validate_v0_35_trueaegis_orchestration_context.sh
time tools/validate_v0_35_trueaegis_execution_worker.sh
time tools/validate_v0_35_trueaegis_auto_import.sh

echo "[PASS] DeltaAegis v0.35 release validation passed"
