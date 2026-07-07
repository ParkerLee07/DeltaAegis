#!/usr/bin/env bash
set -euo pipefail

REPO="${HOME}/DeltaAegis"
EXPECTED_BRANCH="feature/v0.40-human-readable-operator-actions"
EXPECTED_BASE="7b76f86"

cd "$REPO"

echo "DeltaAegis v0.40 Payload/List-Detail Separation Validator"
echo "=========================================================="

branch="$(git branch --show-current)"
if [[ "$branch" != "$EXPECTED_BRANCH" && "$branch" != "main" ]]; then
  echo "FAIL: expected branch $EXPECTED_BRANCH or main, found $branch"
  exit 1
fi

if ! git merge-base --is-ancestor "$EXPECTED_BASE" HEAD; then
  echo "FAIL: branch does not descend from $EXPECTED_BASE"
  exit 1
fi

echo "[v0.40 checkpoint 7] syntax"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py
echo "PASS: syntax without warnings"

echo "[v0.40 checkpoint 7] compact mutation payload contract"
python3 - <<'PY'
from pathlib import Path
import ast

source = Path("deltaaegis.py").read_text(encoding="utf-8")
tree = ast.parse(source)

functions = {
    node.name: node
    for node in ast.walk(tree)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
}

forbidden = {
    "dashboard_netsniper_schedule_create_payload": {"schedules"},
    "dashboard_netsniper_schedule_enabled_payload": {"schedules"},
    "dashboard_netsniper_schedule_delete_payload": {
        "schedules",
        "schedule_history",
    },
    "dashboard_netsniper_schedule_run_due_payload": {
        "schedules",
        "scan_jobs",
        "schedule_history",
    },
    "dashboard_netsniper_hourly_monitoring_payload": {"schedules"},
    "dashboard_netsniper_stale_scan_recovery_payload": {
        "recovered_jobs",
        "remaining_stale_jobs",
        "scan_jobs",
    },
    "dashboard_trueaegis_validation_ingest_payload": {
        "summary",
        "observations",
    },
    "dashboard_admin_user_action_response": {"access"},
}

required = {
    "dashboard_netsniper_schedule_create_payload": {
        "ok", "action", "schedule", "receipt",
    },
    "dashboard_netsniper_schedule_enabled_payload": {
        "ok", "action", "schedule", "receipt",
    },
    "dashboard_netsniper_schedule_delete_payload": {
        "ok", "action", "schedule_id", "deletion", "receipt",
    },
    "dashboard_netsniper_schedule_run_due_payload": {
        "ok", "action", "results", "receipt",
    },
    "dashboard_netsniper_hourly_monitoring_payload": {
        "ok", "action", "schedule", "receipt",
    },
    "dashboard_netsniper_stale_scan_recovery_payload": {
        "ok", "action", "recovered_count", "stale_after_count", "receipt",
    },
    "dashboard_trueaegis_validation_ingest_payload": {
        "ok", "schema_version", "validation_run_id", "import_result", "receipt",
    },
    "dashboard_admin_user_action_response": {
        "ok", "action", "target_username", "receipt",
    },
}

def return_key_sets(node):
    result = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Return):
            continue
        if not isinstance(child.value, ast.Dict):
            continue
        result.append({
            key.value
            for key in child.value.keys
            if isinstance(key, ast.Constant)
            and isinstance(key.value, str)
        })
    return result

for name, forbidden_keys in forbidden.items():
    node = functions.get(name)
    if node is None:
        raise SystemExit(f"missing mutation function: {name}")

    key_sets = return_key_sets(node)
    if not key_sets:
        raise SystemExit(f"no direct return dictionaries found: {name}")

    combined = set().union(*key_sets)
    present = sorted(combined & forbidden_keys)
    if present:
        raise SystemExit(
            f"{name} still returns refreshed collection/detail fields: "
            f"{present}"
        )

    missing = sorted(required[name] - combined)
    if missing:
        raise SystemExit(f"{name} lost required action fields: {missing}")

if "observations = dashboard_validations_payload(connection, limit=25)" in source:
    raise SystemExit(
        "TrueAegis ingest still constructs refreshed observations"
    )

print("compact mutation payload contract passed")
PY
echo "PASS: compact mutation payload contract"

echo "[v0.40 checkpoint 7] GET refresh boundaries and exceptions"
python3 -W error::SyntaxWarning - <<'PY'
import importlib.util
from pathlib import Path
import sys

module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v040_checkpoint7"
spec = importlib.util.spec_from_file_location(module_name, module_path)
if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module
try:
    spec.loader.exec_module(module)
finally:
    sys.modules.pop(module_name, None)

source = module_path.read_text(encoding="utf-8")
netsniper_html = module.render_netsniper_page()
users_html = module.dashboard_operator_users_shell_html()
reset_html = module.dashboard_operator_reset_shell_html()

for fragment in (
    "await loadNetSniperSchedules();",
    "await loadNetSniperScanJobs();",
    "await loadNetSniperScheduleHistory();",
):
    if fragment not in netsniper_html:
        raise SystemExit(
            f"NetSniper GET-refresh boundary lost: {fragment}"
        )

if "await loadOperatorUsers();" not in users_html:
    raise SystemExit("admin-user GET-refresh boundary was lost")

for fragment in (
    '"/api/validation-summary"',
    '"/api/validations"',
):
    if fragment not in source:
        raise SystemExit(f"TrueAegis read-model endpoint lost: {fragment}")

if "renderAssetDetail(payload.asset_detail);" not in source:
    raise SystemExit(
        "asset-detail immediate-consumer exception was lost"
    )

if "renderTelemetryCleanup(payload);" not in reset_html:
    raise SystemExit(
        "telemetry cleanup direct-render exception was lost"
    )

print("GET refresh boundaries and intentional exceptions passed")
PY
echo "PASS: GET refresh boundaries and exceptions"

echo "[v0.40 checkpoint 7] predecessor compatibility"
if [[ "${DELTAAEGIS_V040_SKIP_COMPAT:-0}" == "1" ]]; then
  echo "SKIP: compatibility checks delegated to flat validation"
else
  DELTAAEGIS_V040_SKIP_COMPAT=1 tools/validate_v0_40_action_receipt_contract.sh
  DELTAAEGIS_V040_SKIP_COMPAT=1 tools/validate_v0_40_netsniper_action_receipts.sh
  DELTAAEGIS_V040_SKIP_COMPAT=1 tools/validate_v0_40_schedule_action_receipts.sh
  DELTAAEGIS_V040_SKIP_COMPAT=1 tools/validate_v0_40_trueaegis_action_receipts.sh
  DELTAAEGIS_V040_SKIP_COMPAT=1 tools/validate_v0_40_admin_workflow_action_receipts.sh
  DELTAAEGIS_V040_SKIP_COMPAT=1 tools/validate_v0_40_progressive_technical_disclosure.sh
fi
echo "PASS: predecessor compatibility"

echo "[v0.40 checkpoint 7] repository hygiene"
git diff --check

unexpected_paths="$(
  {
    git diff --name-only
    git ls-files --others --exclude-standard
  } | sort -u | grep -Ev '^$|^deltaaegis\.py$|^tools/validate_v0_40_action_receipt_contract\.sh$|^tools/validate_v0_40_netsniper_action_receipts\.sh$|^tools/validate_v0_40_schedule_action_receipts\.sh$|^tools/validate_v0_40_trueaegis_action_receipts\.sh$|^tools/validate_v0_40_admin_workflow_action_receipts\.sh$|^tools/validate_v0_40_progressive_technical_disclosure\.sh$|^tools/validate_v0_40_payload_separation\.sh$|^README\.md$|^CHANGELOG\.md$|^RELEASE_NOTES_v0\.40\.0\.md$|^MANUAL_VERIFICATION_v0\.40\.0\.md$|^tools/validate_v0_40_release_metadata\.sh$|^tools/validate_v0_40_v0_39_compatibility\.sh$|^tools/validate_v0_40_dashboard_javascript_syntax\.sh$|^tools/validate_v0_40_broken_pipe_response\.sh$|^tools/validate_v0_40_release_gate\.sh$|^tools/validate_v0_40_all\.sh$' || true
)"

if [[ -n "$unexpected_paths" ]]; then
  echo "FAIL: unexpected changed paths"
  printf '%s\n' "$unexpected_paths"
  exit 1
fi

echo "PASS: repository hygiene"
echo "PASS: DeltaAegis v0.40 payload/list-detail separation validator"
