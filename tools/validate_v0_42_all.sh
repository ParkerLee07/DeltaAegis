#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "DeltaAegis v0.42 Component Validator Suite"
echo "============================================"

validators=(
  tools/validate_v0_42_logical_site_foundation.sh
  tools/validate_v0_42_dashboard_lan_flag.sh
  tools/validate_v0_42_logical_site_cli.sh
  tools/validate_v0_42_logical_site_dashboard_foundation.sh
  tools/validate_v0_42_logical_site_aggregation.sh
)

for validator in "${validators[@]}"; do
  echo "[v0.42 components] $(basename "$validator")"
  "$validator"
done

echo "PASS: all five DeltaAegis v0.42 component validators"
