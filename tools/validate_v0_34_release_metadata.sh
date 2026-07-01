#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

grep -Fq 'DeltaAegis v0.34.0' deltaaegis.py
grep -Fq 'TrueAegis Validation Correlation' deltaaegis.py
grep -Fq 'v0.34 TrueAegis Validation Correlation' deltaaegis.py
grep -Fq '## Current Release — v0.34.0' README.md
grep -Fq '**DeltaAegis v0.34.0 — TrueAegis Validation Correlation**' README.md
grep -Fq './tools/validate_v0_34_release.sh' README.md
grep -Fq '## v0.34.0 — TrueAegis Validation Correlation' CHANGELOG.md
grep -Fq 'validate_v0_34_release.sh' CHANGELOG.md

if grep -Fq '## Current Release — v0.33.0' README.md; then
    echo "[FAIL] README still advertises v0.33.0 as current release" >&2
    exit 1
fi

grep -Fq 'v0.34 does not alter risk scoring' deltaaegis.py

echo "[PASS] DeltaAegis v0.34 release metadata validation passed"
