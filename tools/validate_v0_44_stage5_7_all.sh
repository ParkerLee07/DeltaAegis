#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

allow_dirty=0
case "${1:-}" in
  "") ;;
  --allow-dirty) allow_dirty=1 ;;
  *) echo "Usage: $0 [--allow-dirty]" >&2; exit 2 ;;
esac

echo "DeltaAegis v0.44 Stages 5-7 Gate"
echo "=================================="

branch="$(git branch --show-current)"
case "$branch" in
  feature/v0.44-module-boundary-extraction|main)
    echo "PASS: supported checkpoint branch $branch"
    ;;
  *)
    echo "ERROR: unsupported v0.44 checkpoint branch: $branch" >&2
    exit 1
    ;;
esac

if [[ "$allow_dirty" -eq 0 ]]; then
  if [[ -n "$(git status --short)" ]]; then
    echo "ERROR: v0.44 Stages 5-7 gate requires a clean working tree" >&2
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
  deltaaegis_core/db.py \
  deltaaegis_core/ingest.py \
  deltaaegis_core/jobs.py \
  deltaaegis_core/reports.py \
  deltaaegis_core/sites.py \
  tools/validate_v0_44_stage1_2.py \
  tools/validate_v0_44_stage3_auth.py \
  tools/validate_v0_44_stage4_ingest.py \
  tools/validate_v0_44_stage5_7.py
bash -n install.sh tools/validate_v0_44_stage5_7_all.sh
echo "PASS: syntax and whitespace"

python3 tools/validate_v0_44_stage1_2.py
python3 tools/validate_v0_44_stage3_auth.py
python3 tools/validate_v0_44_stage4_ingest.py
python3 tools/validate_v0_44_stage5_7.py

compat_root="$(mktemp -d)"
trap 'rm -rf "$compat_root"' EXIT
git clone -q --no-hardlinks . "$compat_root/repository"
git -C "$compat_root/repository" switch -q -C main
(
  cd "$compat_root/repository"
  export HOME="$compat_root/home"

  echo "[v0.44 checkpoint 5] Sites compatibility"
  tools/validate_v0_42_logical_site_foundation.sh
  tools/validate_v0_42_sites_management.sh

  echo "[v0.44 checkpoint 6] Jobs compatibility"
  tools/validate_v0_39_scan_lifecycle_storage.sh
  tools/validate_v0_39_cancellation_backend.sh
  tools/validate_v0_39_schedule_deletion_semantics.sh
  tools/validate_v0_42_scan_watchdog.sh

  echo "[v0.44 checkpoint 7] Reports compatibility"
  tools/validate_v0_15_port_behavior_report.sh
  tools/validate_v0_16_investigation_center_report.sh
  tools/validate_v0_20_report_ticket_evidence.sh
  tools/validate_v0_22_report_triage_summary.sh
  tools/validate_v0_34_report_correlation.sh
)
rm -rf "$compat_root"
trap - EXIT

python3 tools/audit_v0_43_repository.py --check
echo "PASS: deterministic repository audit"

echo "[v0.44 stages 5-7] complete predecessor behavior compatibility"
python3 tools/validate_v0_43_v0_42_compatibility.py

echo
echo "PASS: DeltaAegis v0.44 Stages 5-7 gate"
