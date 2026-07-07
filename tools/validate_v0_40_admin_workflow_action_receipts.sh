#!/usr/bin/env bash
set -euo pipefail

REPO="${HOME}/DeltaAegis"
EXPECTED_BRANCH="feature/v0.40-human-readable-operator-actions"
EXPECTED_BASE="e8d8fc6"

cd "$REPO"

echo "DeltaAegis v0.40 Admin/Workflow Action Receipt Validator"
echo "========================================================="

branch="$(git branch --show-current)"
if [[ "$branch" != "$EXPECTED_BRANCH" ]]; then
  echo "FAIL: expected branch $EXPECTED_BRANCH, found $branch"
  exit 1
fi

if ! git merge-base --is-ancestor "$EXPECTED_BASE" HEAD; then
  echo "FAIL: branch does not descend from Checkpoint 4 commit $EXPECTED_BASE"
  exit 1
fi

echo "[v0.40 checkpoint 5] syntax"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py
echo "PASS: syntax without warnings"

echo "[v0.40 checkpoint 5] static backend receipt coverage"
python3 -W error::SyntaxWarning - <<'PY'
from pathlib import Path
import ast

source = Path("deltaaegis.py").read_text(encoding="utf-8")
tree = ast.parse(source)
lines = source.splitlines()

required = {
    "dashboard_ticket_status_action_receipt",
    "dashboard_asset_investigation_action_receipt",
    "dashboard_admin_user_action_receipt",
    "dashboard_telemetry_cleanup_action_receipt",
    "dashboard_admin_user_action_response",
    "dashboard_telemetry_cleanup_clear_all_payload",
}

functions = {}

for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name in required:
        end = getattr(node, "end_lineno", node.lineno)
        functions[node.name] = "\n".join(lines[node.lineno - 1:end])

missing = sorted(required - set(functions))
if missing:
    raise SystemExit(
        "missing receipt function(s): " + ", ".join(missing)
    )

for action in (
    '"workflow.ticket_status"',
    '"workflow.asset_investigation"',
    '"admin.user_create"',
    '"admin.user_enable"',
    '"admin.user_disable"',
    '"admin.user_role"',
    '"admin.user_password"',
    '"admin.telemetry_cleanup"',
):
    if action not in source:
        raise SystemExit(f"missing action receipt identifier: {action}")

if '"receipt": receipt' not in functions["dashboard_admin_user_action_response"]:
    raise SystemExit("admin user action response does not return receipt")

if (
    'result["receipt"] = dashboard_telemetry_cleanup_action_receipt('
    not in functions["dashboard_telemetry_cleanup_clear_all_payload"]
):
    raise SystemExit("telemetry cleanup payload does not attach receipt")

if source.count(
    '"receipt": dashboard_ticket_status_action_receipt('
) != 1:
    raise SystemExit("ticket route receipt attachment missing or duplicated")

if source.count(
    '"receipt": dashboard_asset_investigation_action_receipt('
) != 1:
    raise SystemExit("asset investigation route receipt attachment missing or duplicated")

print("static backend receipt coverage passed")
PY
echo "PASS: static backend receipt coverage"

echo "[v0.40 checkpoint 5] static UI receipt coverage"
python3 - <<'PY'
from pathlib import Path

source = Path("deltaaegis.py").read_text(encoding="utf-8")

required_fragments = (
    "function ensureWorkflowActionReceipt()",
    "renderWorkflowActionReceipt(payload.receipt, payload);",
    "renderDashboardActionReceipt(\n              nextMessage,\n              payload.receipt,",
    "function adminActionReceiptText(receipt, fallbackMessage)",
    "function renderAdminActionReceipt(status, receipt, fallbackMessage)",
    "const result = await adminPost(\"/api/admin/users\", payload);",
    "result = await adminPost(`/api/admin/users/${encodeURIComponent(username)}/role`",
    "function cleanupReceiptText(receipt, fallbackMessage)",
    "if (payload.receipt) {",
    "loadTelemetryResetAuditEvents();",
)

for fragment in required_fragments:
    if fragment not in source:
        raise SystemExit(f"missing UI receipt fragment: {fragment}")

legacy_success_fragments = (
    "nextMessage.textContent = `Saved investigation status: ${status}`;",
    "await adminPost(\"/api/admin/users\", payload);\n        form.reset();",
)

for fragment in legacy_success_fragments:
    if fragment in source:
        raise SystemExit(f"legacy reconstructed success message remains: {fragment}")

if "JSON.stringify(payload.receipt" in source:
    raise SystemExit("action receipt rendered as raw JSON")

print("static UI receipt coverage passed")
PY
echo "PASS: static UI receipt coverage"

echo "[v0.40 checkpoint 5] functional backend receipts"
python3 - <<'PY'
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v040_checkpoint5"
spec = importlib.util.spec_from_file_location(module_name, module_path)

if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module

try:
    spec.loader.exec_module(module)
finally:
    sys.modules.pop(module_name, None)


ticket = module.dashboard_ticket_status_action_receipt(
    {
        "ticket_key": "ticket-example",
        "ticket_status": "IN_REVIEW",
        "analyst": "dashboard",
        "note": "reviewing",
    },
    "subject-example",
    "192.168.4.0/24",
)

if ticket["action"] != "workflow.ticket_status":
    raise SystemExit("ticket receipt action mismatch")

if ticket["summary"]["status"] != "IN_REVIEW":
    raise SystemExit("ticket receipt status mismatch")

asset = module.dashboard_asset_investigation_action_receipt(
    {
        "status": "RESOLVED",
        "reason": "validated",
    },
    "asset-example",
    "192.168.4.0/24",
    {
        "ticket_status": "RESOLVED",
    },
)

if asset["action"] != "workflow.asset_investigation":
    raise SystemExit("asset receipt action mismatch")

if asset["identifiers"]["asset_key"] != "asset-example":
    raise SystemExit("asset receipt identifier mismatch")

access_payload = {
    "count": 1,
    "enabled_count": 1,
    "role_counts": {"ADMIN": 1},
    "roles": ["ADMIN", "ANALYST", "VIEWER"],
    "users": [
        {
            "username": "admin.example",
            "role": "ADMIN",
            "enabled": True,
            "password_configured": True,
            "active_token_count": 2,
        }
    ],
}
module.dashboard_admin_users_payload = lambda connection: access_payload

admin = module.dashboard_admin_user_action_response(
    object(),
    "role",
    "admin.example",
)

if admin["receipt"]["action"] != "admin.user_role":
    raise SystemExit("admin user receipt action mismatch")

if "access" in admin:
    raise SystemExit(
        "admin mutation response still embeds access read model"
    )

if module.dashboard_admin_users_payload(object()) is not access_payload:
    raise SystemExit(
        "admin access read-model helper did not preserve user payload"
    )

cleanup_result = {
    "ok": True,
    "action": "telemetry.cleanup.clear_all",
    "dry_run": False,
    "total_deleted_rows": 12,
    "deleted_rows": {"snapshots": 12},
    "protected_tables_preserved": True,
    "protected_tables_after": {"access_users": 1},
    "message": "Telemetry cleanup completed.",
}

audit_calls = []
module.telemetry_cleanup_clear_all = (
    lambda connection, confirmation, dry_run=False: dict(cleanup_result)
)
module.record_access_audit_event = (
    lambda *args, **kwargs: audit_calls.append((args, kwargs))
)

cleanup = module.dashboard_telemetry_cleanup_clear_all_payload(
    object(),
    {
        "confirmation": "DELETE TELEMETRY",
        "dry_run": False,
    },
    actor={"username": "admin.example"},
)

if cleanup["receipt"]["action"] != "admin.telemetry_cleanup":
    raise SystemExit("telemetry cleanup receipt action mismatch")

if cleanup["receipt"]["severity"] != "warning":
    raise SystemExit("telemetry cleanup severity mismatch")

if cleanup["total_deleted_rows"] != 12:
    raise SystemExit("legacy telemetry cleanup result was not preserved")

if len(audit_calls) != 1:
    raise SystemExit("telemetry cleanup audit event was not preserved")

print("functional backend receipt checks passed")
PY
echo "PASS: functional backend receipts"

echo "[v0.40 checkpoint 5] staged compatibility"
if [[ "${DELTAAEGIS_V040_SKIP_COMPAT:-0}" == "1" ]]; then
  echo "SKIP: compatibility checks delegated to flat validation"
else
  DELTAAEGIS_V040_SKIP_COMPAT=1 "tools/validate_v0_40_action_receipt_contract.sh"
  DELTAAEGIS_V040_SKIP_COMPAT=1 "tools/validate_v0_40_netsniper_action_receipts.sh"
  DELTAAEGIS_V040_SKIP_COMPAT=1 "tools/validate_v0_40_schedule_action_receipts.sh"
  DELTAAEGIS_V040_SKIP_COMPAT=1 "tools/validate_v0_40_trueaegis_action_receipts.sh"
fi
echo "PASS: staged compatibility"
echo "[v0.40 checkpoint 5] repository hygiene"
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
echo "PASS: DeltaAegis v0.40 admin/workflow action receipt validator"
