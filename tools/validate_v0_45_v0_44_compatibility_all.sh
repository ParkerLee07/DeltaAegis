#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

allow_dirty=0
case "${1:-}" in
  "") ;;
  --allow-dirty) allow_dirty=1 ;;
  *) echo "Usage: $0 [--allow-dirty]" >&2; exit 2 ;;
esac

echo "DeltaAegis v0.45 / v0.44 Applicable Compatibility Gate"
echo "========================================================="

branch="$(git branch --show-current)"
case "$branch" in
  feature/v0.45-telemetry-trust|main)
    echo "PASS: supported validation branch $branch"
    ;;
  *)
    echo "ERROR: unsupported validation branch: $branch" >&2
    exit 1
    ;;
esac

if [[ "$allow_dirty" -eq 0 ]]; then
  if [[ -n "$(git status --short)" ]]; then
    echo "ERROR: compatibility gate requires a clean working tree" >&2
    git status --short >&2
    exit 1
  fi
  echo "PASS: clean working tree"
else
  echo "NOTICE: dirty-tree check bypassed for installer validation"
fi

git diff --check
python3 -W error::SyntaxWarning -m py_compile \
  deltaaegis.py \
  deltaaegis_core/__init__.py \
  deltaaegis_core/auth.py \
  deltaaegis_core/config.py \
  deltaaegis_core/current_state.py \
  deltaaegis_core/db.py \
  deltaaegis_core/ingest.py \
  deltaaegis_core/jobs.py \
  deltaaegis_core/reports.py \
  deltaaegis_core/sites.py \
  deltaaegis_core/telemetry_quality.py \
  deltaaegis_core/web.py \
  tools/validate_v0_44_stage1_2.py \
  tools/validate_v0_44_stage3_auth.py \
  tools/validate_v0_44_stage4_ingest.py \
  tools/validate_v0_44_stage5_7.py \
  tools/validate_v0_44_stage8_web.py \
  tools/validate_v0_45_v0_44_ingest_transition.py \
  tools/validate_v0_45_v0_44_web_transition.py
bash -n install.sh uninstall.sh tools/validate_v0_45_v0_44_compatibility_all.sh
echo "PASS: syntax and whitespace"

echo "[v0.44 component contracts with approved v0.45 transitions]"
python3 tools/validate_v0_44_stage1_2.py
python3 tools/validate_v0_44_stage3_auth.py
python3 tools/validate_v0_45_v0_44_ingest_transition.py
python3 tools/validate_v0_44_stage5_7.py
python3 tools/validate_v0_45_v0_44_web_transition.py

echo "[checkpoint-specific predecessor contracts]"
tools/validate_v0_42_logical_site_foundation.sh
tools/validate_v0_42_sites_management.sh
tools/validate_v0_39_scan_lifecycle_storage.sh
tools/validate_v0_39_cancellation_backend.sh
tools/validate_v0_39_schedule_deletion_semantics.sh
tools/validate_v0_42_scan_watchdog.sh
python3 tools/validate_v0_44_1_report_contracts.py
tools/validate_v0_40_broken_pipe_response.sh
tools/validate_v0_40_dashboard_javascript_syntax.sh
tools/validate_v0_42_dashboard_lan_flag.sh
python3 tools/validate_v0_42_security_hotfix.py
tools/validate_v0_42_install_uninstall_lifecycle.sh

python3 tools/audit_v0_44_repository.py --check
echo "PASS: deterministic repository audit"

echo "[complete predecessor behavior compatibility]"
python3 tools/validate_v0_43_v0_42_compatibility.py

echo
echo "PASS: v0.45 preserves every applicable v0.44 contract"
echo "PASS: frozen Stage 4 and Stage 8 assertions are superseded only by"
echo "      the approved degraded-evidence and Quality Center transitions"
