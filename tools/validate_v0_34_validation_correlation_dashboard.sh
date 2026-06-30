#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

tools/validate_v0_34_validation_correlation_storage.sh

grep -Fq '("GET", "/api/validation-correlations", "dashboard.read")' deltaaegis.py
grep -Fq 'elif route == "/api/validation-correlations":' deltaaegis.py
grep -Fq 'dashboard_validation_correlations_payload' deltaaegis.py
grep -Fq 'refresh_trueaegis_validation_correlations' deltaaegis.py
grep -Fq 'trueaegis-validation-correlation-count' deltaaegis.py
grep -Fq 'trueaegis-validation-correlated-asset-count' deltaaegis.py
grep -Fq 'trueaegis-validation-correlations-body' deltaaegis.py
grep -Fq 'renderTrueAegisValidationCorrelations' deltaaegis.py
grep -Fq '/api/validation-correlations?limit=25' deltaaegis.py

echo "[PASS] DeltaAegis v0.34 validation correlation dashboard/API validation passed"
