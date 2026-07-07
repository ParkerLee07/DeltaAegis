#!/usr/bin/env bash
set -euo pipefail

REPO="${HOME}/DeltaAegis"

cd "$REPO"

echo "DeltaAegis v0.40 Flat Validation Suite"
echo "======================================"

validators=(
  "tools/validate_v0_40_action_receipt_contract.sh"
  "tools/validate_v0_40_netsniper_action_receipts.sh"
  "tools/validate_v0_40_schedule_action_receipts.sh"
  "tools/validate_v0_40_trueaegis_action_receipts.sh"
  "tools/validate_v0_40_admin_workflow_action_receipts.sh"
  "tools/validate_v0_40_progressive_technical_disclosure.sh"
)

for validator in "${validators[@]}"; do
  if [[ ! -x "$validator" ]]; then
    echo "FAIL: validator is missing or not executable: $validator"
    exit 1
  fi
done

suite_start="${SECONDS}"

for validator in "${validators[@]}"; do
  echo
  echo ">>> Running $validator"
  validator_start="${SECONDS}"

  DELTAAEGIS_V040_SKIP_COMPAT=1 "$validator"

  validator_elapsed="$((SECONDS - validator_start))"
  echo "<<< PASS: $validator (${validator_elapsed}s)"
done

suite_elapsed="$((SECONDS - suite_start))"

echo
echo "PASS: all DeltaAegis v0.40 validators ran once"
echo "Elapsed: ${suite_elapsed}s"
