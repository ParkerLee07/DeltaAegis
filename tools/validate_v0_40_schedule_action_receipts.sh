#!/usr/bin/env bash
set -euo pipefail

REPO="${HOME}/DeltaAegis"
EXPECTED_BRANCH="feature/v0.40-human-readable-operator-actions"
EXPECTED_BASE="ea5d0da"

cd "$REPO"

echo "DeltaAegis v0.40 Schedule Action Receipt Validator"
echo "==================================================="

branch="$(git branch --show-current)"
if [[ "$branch" != "$EXPECTED_BRANCH" ]]; then
  echo "FAIL: expected branch $EXPECTED_BRANCH, found $branch"
  exit 1
fi

if ! git merge-base --is-ancestor "$EXPECTED_BASE" HEAD; then
  echo "FAIL: branch does not descend from Checkpoint 2 commit $EXPECTED_BASE"
  exit 1
fi

echo "[v0.40 checkpoint 3] syntax"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py
echo "PASS: syntax without warnings"

echo "[v0.40 checkpoint 3] static backend receipt coverage"
python3 -W error::SyntaxWarning - <<'PY'
from pathlib import Path
import ast

source = Path("deltaaegis.py").read_text(encoding="utf-8")
tree = ast.parse(source)
lines = source.splitlines()

required_functions = {
    "dashboard_netsniper_schedule_create_payload",
    "dashboard_netsniper_schedule_enabled_payload",
    "dashboard_netsniper_schedule_delete_payload",
    "dashboard_netsniper_schedule_run_due_payload",
    "dashboard_netsniper_hourly_monitoring_payload",
    "dashboard_netsniper_stale_scan_recovery_payload",
    "dashboard_netsniper_schedule_run_due_receipt",
}

function_sources = {}

for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name in required_functions:
        end = getattr(node, "end_lineno", node.lineno)
        function_sources[node.name] = "\n".join(
            lines[node.lineno - 1:end]
        )

missing = sorted(required_functions - set(function_sources))
if missing:
    raise SystemExit(
        "missing function(s): " + ", ".join(missing)
    )

for name in required_functions - {"dashboard_netsniper_schedule_run_due_receipt"}:
    if '"receipt": receipt' not in function_sources[name]:
        raise SystemExit(
            f"{name} does not include receipt in its response"
        )

actions = (
    '"schedule.create"',
    '"schedule.enable"',
    '"schedule.disable"',
    '"schedule.delete"',
    '"schedule.run_due"',
    '"hourly_monitoring.enable"',
    '"hourly_monitoring.disable"',
    '"netsniper.stale_scan_fail"',
)

for action in actions:
    if action not in source:
        raise SystemExit(f"missing receipt action: {action}")

print("static backend receipt coverage passed")
PY
echo "PASS: static backend receipt coverage"

echo "[v0.40 checkpoint 3] raw dump removal and refresh boundaries"
python3 - <<'PY'
from pathlib import Path

source = Path("deltaaegis.py").read_text(encoding="utf-8")
raw_dump = "output.textContent = JSON.stringify(payload, null, 2);"

if raw_dump in source:
    raise SystemExit(
        "legacy full-payload operator action dump remains"
    )

if source.count(
    "renderDashboardActionReceipt(output, payload.receipt, payload);"
) != 7:
    raise SystemExit(
        "expected seven backend-receipt operator render calls"
    )

handler_boundaries = (
    (
        "setHourlyNetSniperMonitoring",
        "    async function setHourlyNetSniperMonitoring(enabled) {",
        "    async function createNetSniperSchedule(event) {",
    ),
    (
        "createNetSniperSchedule",
        "    async function createNetSniperSchedule(event) {",
        "    async function runDueNetSniperSchedules() {",
    ),
    (
        "runDueNetSniperSchedules",
        "    async function runDueNetSniperSchedules() {",
        "    async function recoverStaleNetSniperScans() {",
    ),
    (
        "recoverStaleNetSniperScans",
        "    async function recoverStaleNetSniperScans() {",
        "    async function handleNetSniperScheduleAction(event) {",
    ),
    (
        "handleNetSniperScheduleAction",
        "    async function handleNetSniperScheduleAction(event) {",
        "    async function startNetSniperScan(event) {",
    ),
)

handler_sources = {}

for name, start_marker, end_marker in handler_boundaries:
    start = source.find(start_marker)

    if start < 0:
        raise SystemExit(
            f"could not locate mutation handler start: {name}"
        )

    end = source.find(end_marker, start + len(start_marker))

    if end < 0:
        raise SystemExit(
            f"could not locate mutation handler end: {name}"
        )

    handler_sources[name] = source[start:end]

forbidden_embedded_renderers = (
    "renderNetSniperSchedules(payload);",
    "renderNetSniperScanJobs(payload.scan_jobs);",
    "renderNetSniperScheduleHistory({history: payload.schedule_history});",
)

for name, handler_source in handler_sources.items():
    for forbidden in forbidden_embedded_renderers:
        if forbidden in handler_source:
            raise SystemExit(
                "write-action response still renders an embedded collection "
                f"inside {name}: {forbidden}"
            )

required_handler_refreshes = {
    "setHourlyNetSniperMonitoring": (
        "await loadNetSniperSchedules();",
    ),
    "createNetSniperSchedule": (
        "await loadNetSniperSchedules();",
    ),
    "runDueNetSniperSchedules": (
        "await loadNetSniperSchedules();",
        "await loadNetSniperScanJobs();",
        "await loadNetSniperScheduleHistory();",
    ),
    "recoverStaleNetSniperScans": (
        "await loadNetSniperSchedules();",
        "await loadNetSniperScanJobs();",
        "await loadNetSniperScheduleHistory();",
    ),
    "handleNetSniperScheduleAction": (
        "await loadNetSniperSchedules();",
        "await loadNetSniperScanJobs();",
        "await loadNetSniperScheduleHistory();",
    ),
}

for name, required_refreshes in required_handler_refreshes.items():
    handler_source = handler_sources[name]

    for refresh in required_refreshes:
        if refresh not in handler_source:
            raise SystemExit(
                f"missing read-only refresh boundary in {name}: {refresh}"
            )

print("raw dump removal and refresh boundary checks passed")
PY
echo "PASS: raw dump removal and refresh boundaries"

echo "[v0.40 checkpoint 3] functional run-due receipt outcomes"
python3 - <<'PY'
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v040_checkpoint3"
spec = importlib.util.spec_from_file_location(
    module_name,
    module_path,
)

if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module

try:
    spec.loader.exec_module(module)
finally:
    sys.modules.pop(module_name, None)

none_due = module.dashboard_netsniper_schedule_run_due_receipt(
    [],
    1,
)

if none_due["message"] != "No scheduled scans were due.":
    raise SystemExit("no-due message mismatch")

if none_due["severity"] != "info":
    raise SystemExit("no-due severity mismatch")

blocked = module.dashboard_netsniper_schedule_run_due_receipt(
    [
        {
            "action": "blocked",
            "schedule_id": "sched-1",
            "reason": "active scan job exists",
        }
    ],
    1,
)

if blocked["severity"] != "warning":
    raise SystemExit("blocked severity mismatch")

if blocked["summary"]["blocked"] != 1:
    raise SystemExit("blocked count mismatch")

completed = module.dashboard_netsniper_schedule_run_due_receipt(
    [
        {
            "action": "executed",
            "job": {
                "job_id": "scan-1",
                "status": "COMPLETED",
            },
        }
    ],
    1,
)

if completed["severity"] != "success":
    raise SystemExit("completed severity mismatch")

if completed["summary"]["started"] != 1:
    raise SystemExit("started count mismatch")

if completed["summary"]["completed"] != 1:
    raise SystemExit("completed count mismatch")

failed = module.dashboard_netsniper_schedule_run_due_receipt(
    [
        {
            "action": "executed",
            "job": {
                "job_id": "scan-2",
                "status": "FAILED",
            },
        }
    ],
    1,
)

if failed["severity"] != "warning":
    raise SystemExit("failed severity mismatch")

if failed["summary"]["failed"] != 1:
    raise SystemExit("failed count mismatch")

print("functional run-due receipt checks passed")
PY
echo "PASS: functional run-due receipt outcomes"

echo "[v0.40 checkpoint 3] staged compatibility"
tools/validate_v0_40_action_receipt_contract.sh
tools/validate_v0_40_netsniper_action_receipts.sh
echo "PASS: staged compatibility"

echo "[v0.40 checkpoint 3] repository hygiene"
git diff --check

unexpected_paths="$(
  {
    git diff --name-only
    git ls-files --others --exclude-standard
  } | sort -u | grep -Ev '^$|^deltaaegis\.py$|^tools/validate_v0_40_action_receipt_contract\.sh$|^tools/validate_v0_40_netsniper_action_receipts\.sh$|^tools/validate_v0_40_schedule_action_receipts\.sh$|^tools/validate_v0_40_trueaegis_action_receipts\.sh$|^tools/validate_v0_40_admin_workflow_action_receipts\.sh$|^tools/validate_v0_40_progressive_technical_disclosure\.sh$' || true
)"

if [[ -n "$unexpected_paths" ]]; then
  echo "FAIL: unexpected changed paths"
  printf '%s\n' "$unexpected_paths"
  exit 1
fi

echo "PASS: repository hygiene"
echo "PASS: DeltaAegis v0.40 schedule action receipt validator"
