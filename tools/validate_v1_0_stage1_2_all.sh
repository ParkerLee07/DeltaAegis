#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export PYTHONDONTWRITEBYTECODE=1

echo "DeltaAegis v1.0 Combined Stage 1–2 Validation"
echo "================================================"

python3 -W error::SyntaxWarning -m py_compile \
    deltaaegis.py \
    deltaaegis_core/*.py \
    tools/audit_v0_44_repository.py \
    tools/bootstrap_first_admin.py \
    tools/deltaaegis_troubleshooter.py \
    tools/reset_dashboard_admin.py \
    tools/validate_v1_stage1_migrations.py \
    tools/validate_v1_stage2_api_security.py \
    tools/validate_v1_stage1_2_architecture.py \
    tools/validate_v1_v0_45_quality_center_transition.py \
    tools/validate_v1_v0_45_web_transition.py

bash -n \
    install.sh \
    uninstall.sh \
    tools/validate_v1_0_stage1_2_all.sh \
    tools/validate_v1_0_stage1_2_gate.sh \
    tools/validate_v1_stage1_2_install_lifecycle.sh

echo
echo "[Stage 1: migrations and recovery]"
python3 tools/validate_v1_stage1_migrations.py

echo
echo "[Stage 2: stable API and web security]"
python3 tools/validate_v1_stage2_api_security.py

echo
echo "[Additive architecture and installation boundaries]"
python3 tools/validate_v1_stage1_2_architecture.py
bash tools/validate_v1_stage1_2_install_lifecycle.sh

echo
echo "[Released v0.45 telemetry-trust compatibility]"
python3 tools/validate_v0_45_deep_bug_fixes.py
python3 tools/validate_v0_45_netsniper_context_consumer.py
python3 tools/validate_v0_45_quality_runtime.py
python3 tools/validate_v0_45_quality_storage.py
python3 tools/validate_v0_45_quality_effects.py
python3 tools/validate_v0_45_v0_44_ingest_transition.py
python3 tools/validate_v0_45_quality_review.py
python3 tools/validate_v1_v0_45_quality_center_transition.py
python3 tools/validate_v1_v0_45_web_transition.py

echo
echo "[Applicable predecessor security and modular contracts]"
python3 tools/validate_v0_44_stage3_auth.py
python3 tools/validate_v0_44_stage5_7.py
python3 tools/validate_v0_42_security_hotfix.py
bash tools/validate_v0_40_dashboard_javascript_syntax.sh
bash tools/validate_v0_40_broken_pipe_response.sh

echo
echo "[Core regression tests]"
python3 -m unittest discover -s tests -p 'test*.py' -v

echo
echo "[PASS] DeltaAegis v1.0 combined Stage 1–2 validation"
echo "NOTICE: this checkpoint is not the complete v1.0 GA release gate."
