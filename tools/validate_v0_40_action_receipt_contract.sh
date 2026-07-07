#!/usr/bin/env bash
set -euo pipefail

REPO="${HOME}/DeltaAegis"
EXPECTED_BRANCH="feature/v0.40-human-readable-operator-actions"
EXPECTED_BASE="508cccc"

cd "$REPO"

echo "DeltaAegis v0.40 Action Receipt Contract Validator"
echo "==================================================="

branch="$(git branch --show-current)"
if [[ "$branch" != "$EXPECTED_BRANCH" ]]; then
  echo "FAIL: expected branch $EXPECTED_BRANCH, found $branch"
  exit 1
fi

if ! git merge-base --is-ancestor "$EXPECTED_BASE" HEAD; then
  echo "FAIL: branch does not descend from validated v0.39 release commit $EXPECTED_BASE"
  exit 1
fi

echo "[v0.40 checkpoint 1] source syntax"
python3 -m py_compile deltaaegis.py
echo "PASS: source syntax"

echo "[v0.40 checkpoint 1] static action-receipt contract"
python3 - <<'PY'
from pathlib import Path
import ast

source_path = Path("deltaaegis.py")
source = source_path.read_text(encoding="utf-8")
tree = ast.parse(source)

required_names = {
    "DASHBOARD_ACTION_RECEIPT_SCHEMA_VERSION",
    "DASHBOARD_ACTION_RECEIPT_SEVERITIES",
    "DASHBOARD_ACTION_RECEIPT_ACTION_PATTERN",
    "DASHBOARD_ACTION_RECEIPT_MESSAGE_MAX_LENGTH",
    "dashboard_action_receipt_json_object",
    "dashboard_action_receipt",
}

found = set()

for node in tree.body:
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = []
        if isinstance(node, ast.Assign):
            targets.extend(node.targets)
        else:
            targets.append(node.target)

        for target in targets:
            if isinstance(target, ast.Name):
                found.add(target.id)

    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        found.add(node.name)

missing = sorted(required_names - found)
if missing:
    raise SystemExit(
        "missing action-receipt foundation symbols: "
        + ", ".join(missing)
    )

raw_dump_count = source.count(
    "output.textContent = JSON.stringify(payload, null, 2);"
)
if raw_dump_count > 7:
    raise SystemExit(
        "action receipt migrations must not increase legacy raw payload render sites; "
        f"expected at most 7, found {raw_dump_count}"
    )

legacy_functions = (
    "dashboard_netsniper_import_latest_payload",
    "dashboard_netsniper_scan_start_payload",
    "dashboard_netsniper_schedule_create_payload",
    "dashboard_netsniper_schedule_enabled_payload",
    "dashboard_netsniper_schedule_delete_payload",
    "dashboard_netsniper_schedule_run_due_payload",
    "dashboard_netsniper_hourly_monitoring_payload",
    "dashboard_netsniper_stale_scan_recovery_payload",
    "dashboard_trueaegis_validation_start_payload",
    "dashboard_trueaegis_validation_ingest_payload",
)

for function_name in legacy_functions:
    if f"def {function_name}(" not in source:
        raise SystemExit(
            f"legacy payload builder missing after checkpoint 1: {function_name}"
        )

print("static contract checks passed")
PY
echo "PASS: static action-receipt contract"

echo "[v0.40 checkpoint 1] functional action-receipt contract"
python3 - <<'PY'
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v040_checkpoint1"

spec = importlib.util.spec_from_file_location(
    module_name,
    module_path,
)

if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)

# Python 3.14 dataclasses resolve annotations through sys.modules during
# module execution. Register the dynamic module before exec_module().
sys.modules[module_name] = module

try:
    spec.loader.exec_module(module)
finally:
    # Keep the test process isolated after import.
    sys.modules.pop(module_name, None)

receipt = module.dashboard_action_receipt(
    "schedule.run_due",
    "No scheduled scans were due.",
    summary={
        "schedules_checked": 2,
        "started": 0,
        "skipped": 0,
        "failed": 0,
    },
    identifiers={
        "scope": "192.168.4.0/24",
    },
)

expected_keys = {
    "schema_version",
    "ok",
    "action",
    "severity",
    "message",
    "summary",
    "identifiers",
    "diagnostic_detail",
}

if set(receipt) != expected_keys:
    raise SystemExit(
        f"unexpected receipt keys: {sorted(receipt)}"
    )

if receipt["schema_version"] != "deltaaegis-dashboard-action-receipt-v1":
    raise SystemExit("unexpected receipt schema version")

if receipt["ok"] is not True:
    raise SystemExit("success receipt did not preserve ok=true")

if receipt["severity"] != "success":
    raise SystemExit("success receipt did not default to success severity")

if receipt["diagnostic_detail"] != {"available": False}:
    raise SystemExit(
        "empty diagnostic detail did not normalize to available=false"
    )

failure = module.dashboard_action_receipt(
    "scan.start",
    "Unable to start the scan.",
    ok=False,
)

if failure["severity"] != "error":
    raise SystemExit("failed receipt did not default to error severity")

warning = module.dashboard_action_receipt(
    "schedule.delete",
    "Schedule deleted; one active job continues running.",
    severity="warning",
    identifiers={
        "schedule_id": "sched-example",
    },
    diagnostic_detail={
        "available": True,
        "detail_route": "/api/netsniper/schedule-history",
    },
)

if warning["severity"] != "warning":
    raise SystemExit("explicit warning severity was not preserved")

if warning["diagnostic_detail"].get("available") is not True:
    raise SystemExit("diagnostic availability was not preserved")

if json.loads(json.dumps(warning)) != warning:
    raise SystemExit("receipt is not JSON round-trip safe")

summary = {"count": 1}
copied = module.dashboard_action_receipt(
    "test.copy",
    "Copy test.",
    summary=summary,
)
summary["count"] = 99

if copied["summary"]["count"] != 1:
    raise SystemExit("receipt did not isolate caller-owned summary data")

invalid_cases = (
    lambda: module.dashboard_action_receipt("", "Missing action."),
    lambda: module.dashboard_action_receipt("UPPER CASE", "Invalid action."),
    lambda: module.dashboard_action_receipt("test.invalid", ""),
    lambda: module.dashboard_action_receipt(
        "test.invalid",
        "Invalid severity.",
        severity="critical",
    ),
    lambda: module.dashboard_action_receipt(
        "test.invalid",
        "Invalid summary.",
        summary=[],
    ),
    lambda: module.dashboard_action_receipt(
        "test.invalid",
        "Non-JSON summary.",
        summary={"bad": {1, 2}},
    ),
)

for index, operation in enumerate(invalid_cases, 1):
    try:
        operation()
    except module.DeltaAegisError:
        continue

    raise SystemExit(
        f"invalid receipt case {index} was accepted"
    )

print("functional contract checks passed")
PY
echo "PASS: functional action-receipt contract"

echo "[v0.40 checkpoint 1] repository hygiene"
git diff --check

unexpected_paths="$(
  {
    git diff --name-only
    git ls-files --others --exclude-standard
  } | sort -u | grep -Ev '^$|^deltaaegis\.py$|^tools/validate_v0_40_action_receipt_contract\.sh$|^tools/validate_v0_40_netsniper_action_receipts\.sh$|^tools/validate_v0_40_schedule_action_receipts\.sh$|^tools/validate_v0_40_trueaegis_action_receipts\.sh$|^tools/validate_v0_40_admin_workflow_action_receipts\.sh$|^tools/validate_v0_40_progressive_technical_disclosure\.sh$|^tools/validate_v0_40_payload_separation\.sh$|^tools/validate_v0_40_all\.sh$' || true
)"

if [[ -n "$unexpected_paths" ]]; then
  echo "FAIL: unexpected changed paths"
  printf '%s\n' "$unexpected_paths"
  exit 1
fi

echo "PASS: repository hygiene"
echo "PASS: DeltaAegis v0.40 action receipt contract validator"
