#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "DeltaAegis v0.45 Telemetry Trust Checkpoints 1-5 Gate"
echo "======================================================"

git diff --check

python3 -W error::SyntaxWarning -m py_compile \
  deltaaegis.py \
  deltaaegis_core/auth.py \
  deltaaegis_core/config.py \
  deltaaegis_core/current_state.py \
  deltaaegis_core/reports.py \
  deltaaegis_core/telemetry_quality.py \
  deltaaegis_core/web.py \
  tools/validate_v0_45_netsniper_context_consumer.py \
  tools/validate_v0_45_quality_runtime.py \
  tools/validate_v0_45_quality_storage.py \
  tools/validate_v0_45_quality_effects.py \
  tools/validate_v0_45_quality_review.py \
  tools/validate_v0_45_quality_center.py

bash -n install.sh
bash -n uninstall.sh
bash -n tools/validate_v0_45_checkpoints_1_5_all.sh

python3 tools/validate_v0_45_netsniper_context_consumer.py
python3 tools/validate_v0_45_quality_runtime.py
python3 tools/validate_v0_45_quality_storage.py
python3 tools/validate_v0_45_quality_effects.py
python3 tools/validate_v0_45_v0_44_ingest_transition.py
python3 tools/validate_v0_45_quality_review.py
python3 tools/validate_v0_45_v0_44_web_transition.py
python3 tools/validate_v0_45_quality_center.py
python3 tools/audit_v0_44_repository.py --check

echo
echo "PASS: DeltaAegis v0.45 telemetry trust checkpoints 1-5"
