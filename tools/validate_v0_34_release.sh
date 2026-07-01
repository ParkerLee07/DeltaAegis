#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[INFO] Running DeltaAegis v0.34 release validation..."

tools/validate_v0_34_validation_correlation_storage.sh
tools/validate_v0_34_validation_correlation_dashboard.sh
tools/validate_v0_34_asset_detail_validation_correlation.sh
tools/validate_v0_34_report_correlation.sh
tools/validate_v0_34_release_metadata.sh

echo "[INFO] Running inherited functional regression validators..."

shopt -s nullglob

for validator in tools/validate_v0_33*.sh tools/validate_v0_32*.sh tools/validate_v0_31*.sh; do
    case "$(basename "$validator")" in
        validate_v0_33_release.sh|validate_v0_33_release_metadata.sh|validate_v0_33_report_validation.sh|\
validate_v0_32_release.sh|validate_v0_32_release_metadata.sh|\
validate_v0_31_release.sh|validate_v0_31_release_metadata.sh)
            echo "[INFO] Skipping superseded current-release validator: $validator"
            continue
            ;;
    esac

    if [[ -x "$validator" ]]; then
        "$validator"
    else
        bash "$validator"
    fi
done

python3 -m pytest

echo "[PASS] DeltaAegis v0.34 release validation passed"
