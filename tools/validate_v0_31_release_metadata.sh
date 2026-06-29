#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

grep -Fq 'DeltaAegis v0.31.0: Scheduled Profile-Aware Scans' deltaaegis.py \
    || fail "deltaaegis.py top metadata does not advertise v0.31.0"

grep -Fq 'DeltaAegis v0.31.0 — Scheduled Profile-Aware Scans' deltaaegis.py \
    || fail "CLI parser metadata does not advertise v0.31.0"

grep -Fq 'v0.31 Scheduled Scans' deltaaegis.py \
    || fail "dashboard release pill does not advertise v0.31 scheduled scans"

grep -Fq '## Current Release — v0.31.0' README.md \
    || fail "README does not advertise v0.31.0 as current release"

grep -Fq 'DeltaAegis v0.31.0 — Scheduled Profile-Aware Scans' README.md \
    || fail "README missing v0.31.0 release title"

grep -Fq 'Hourly Balanced Monitoring' README.md \
    || fail "README missing hourly monitoring release detail"

grep -Fq './tools/validate_v0_31_release.sh' README.md \
    || fail "README missing v0.31 release gate command"

python3 - <<'DELTA_31_METADATA_PY'
from pathlib import Path

readme = Path("README.md").read_text(encoding="utf-8")
source = Path("deltaaegis.py").read_text(encoding="utf-8")
release_gate = Path("tools/validate_v0_31_release.sh").read_text(encoding="utf-8")

start = readme.find("## Current Release")
assert start != -1, "README missing Current Release section"
next_section = readme.find("\n## ", start + 1)
current = readme[start:] if next_section == -1 else readme[start:next_section]

assert "Current Release — v0.31.0" in current
assert "DeltaAegis v0.31.0 — Scheduled Profile-Aware Scans" in current
assert "Current Release — v0.30.0" not in current
assert "DeltaAegis v0.30.0 — NetSniper Profile-Aware Scan Jobs" not in current

required_source = [
    "DASHBOARD_SCHEDULE_WORKER_INTERVAL_SECONDS = 60",
    "HOURLY_BALANCED_MONITORING_NAME = \"Hourly Balanced Monitoring\"",
    "def dashboard_netsniper_hourly_monitoring_payload(",
    "def dashboard_schedule_worker_loop(",
    "def dashboard_run_due_schedule_tick(",
    "failure_message = str(exc)",
]

missing_source = [item for item in required_source if item not in source]
assert not missing_source, f"missing v0.31 source fragments: {missing_source}"

required_validators = [
    "validate_v0_31_scan_schedule_backend.sh",
    "validate_v0_31_schedule_runner.sh",
    "validate_v0_31_dashboard_schedule_api.sh",
    "validate_v0_31_dashboard_schedule_ui.sh",
    "validate_v0_31_hourly_monitoring.sh",
    "validate_v0_31_dashboard_schedule_worker.sh",
    "validate_v0_31_schedule_failure_persistence.sh",
    "validate_v0_31_scan_result_capture.sh",
    "validate_v0_31_release_metadata.sh",
    "validate_v0_30_scan_profile_backend.sh",
    "validate_v0_30_dashboard_scan_profile_ui.sh",
    "validate_v0_29_scan_start_foundation.sh",
    "validate_v0_29_dashboard_scan_start_background.sh",
    "validate_v0_29_netsniper_scan_ui.sh",
]

missing_validators = [item for item in required_validators if item not in release_gate]
assert not missing_validators, f"release gate missing validators: {missing_validators}"

assert "./tools/validate_v0_30_release.sh" not in release_gate, (
    "v0.31 release gate must not execute the v0.30 metadata release gate"
)

print("[PASS] v0.31 release metadata python checks passed")
DELTA_31_METADATA_PY

pass "DeltaAegis v0.31 release metadata validation passed"
