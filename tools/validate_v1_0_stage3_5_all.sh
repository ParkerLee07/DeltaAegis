#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
export PYTHONDONTWRITEBYTECODE=1

echo "DeltaAegis v1.0 Combined Stage 3–5 Validation"
echo "================================================"

python3 -W error::SyntaxWarning -m py_compile \
    deltaaegis.py \
    deltaaegis_core/*.py \
    tools/measure_v1_stage5_performance.py \
    tools/run_v1_stage5_soak.py \
    tools/validate_v1_stage3_5.py

bash -n \
    install.sh \
    uninstall.sh \
    tools/validate_v1_0_stage3_5_all.sh \
    tools/validate_v1_0_stage3_5_gate.sh \
    tools/validate_v1_stage1_2_install_lifecycle.sh

echo
echo "[Preserved Stage 1–2 migration, API, security, and compatibility baseline]"
./tools/validate_v1_0_stage1_2_all.sh

echo
echo "[Stages 3–5 identity, detection, operations, and stable API boundary]"
python3 tools/validate_v1_stage3_5.py

echo
echo "[Stage 5 reproducible performance thresholds]"
performance_receipt="$(mktemp)"
python3 tools/measure_v1_stage5_performance.py --output "$performance_receipt" >/dev/null
python3 - "$performance_receipt" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload["assessment"]["status"] == "PASS"
for name, value in sorted(payload["measurements"].items()):
    print(f"  {name}: {value}")
print("[PASS] v1 Stage 5 performance thresholds")
PY
rm -f -- "$performance_receipt"

echo
echo "[Stage 5 bounded soak-harness rehearsal]"
soak_root="$(mktemp -d)"
python3 deltaaegis.py --db "$soak_root/soak.db" readiness >/dev/null
python3 tools/run_v1_stage5_soak.py \
    --db "$soak_root/soak.db" \
    --output "$soak_root/receipt.json" \
    --duration-hours 0.00002 \
    --interval-seconds 0.02 \
    >/dev/null
python3 - "$soak_root/receipt.json" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload["completed_requested_duration"] is True
assert payload["summary"] == {
    "integrity_failures": 0,
    "readiness_failures": 0,
    "unplanned_worker_failures": 0,
}
print("[PASS] v1 Stage 5 soak harness rehearsal")
PY
rm -rf -- "$soak_root"

echo
echo "[PASS] DeltaAegis v1.0 combined Stage 3–5 implementation validation"
echo "NOTICE: v1.0.0 GA still requires a completed 24-hour release-evidence soak."
