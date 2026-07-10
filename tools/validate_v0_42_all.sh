#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "DeltaAegis v0.42 Component Validator Suite"
echo "============================================"

validators=(
  tools/validate_v0_42_logical_site_foundation.sh
  tools/validate_v0_42_dashboard_lan_flag.sh
  tools/validate_v0_42_scan_watchdog.sh
  tools/validate_v0_42_sites_management.sh
  tools/validate_v0_42_dashboard_freshness_foundation.sh
  tools/validate_v0_42_dashboard_asset_selector_completeness.sh
  tools/validate_v0_42_trueaegis_tab_containment.sh
  tools/validate_v0_42_schedule_finalization_recovery.sh
  tools/validate_v0_42_logical_site_cli.sh
  tools/validate_v0_42_logical_site_dashboard_foundation.sh
  tools/validate_v0_42_logical_site_aggregation.sh
  tools/validate_v0_42_install_uninstall_lifecycle.sh
  tools/validate_v0_42_license_policy.sh
)

for validator in "${validators[@]}"; do
  echo "[v0.42 components] $(basename "$validator")"
  "$validator"
done

echo "PASS: all thirteen DeltaAegis v0.42 component validators"
