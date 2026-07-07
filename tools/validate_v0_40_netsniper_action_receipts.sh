#!/usr/bin/env bash
set -euo pipefail

REPO="${HOME}/DeltaAegis"
EXPECTED_BRANCH="feature/v0.40-human-readable-operator-actions"
EXPECTED_BASE="084b7a4"

cd "$REPO"

echo "DeltaAegis v0.40 NetSniper Action Receipt Validator"
echo "===================================================="

branch="$(git branch --show-current)"
if [[ "$branch" != "$EXPECTED_BRANCH" ]]; then
  echo "FAIL: expected branch $EXPECTED_BRANCH, found $branch"
  exit 1
fi

if ! git merge-base --is-ancestor "$EXPECTED_BASE" HEAD; then
  echo "FAIL: branch does not descend from Checkpoint 1 commit $EXPECTED_BASE"
  exit 1
fi

echo "[v0.40 checkpoint 2] source syntax"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py
echo "PASS: source syntax without SyntaxWarning"

echo "[v0.40 checkpoint 2] static backend and UI contract"
python3 -W error::SyntaxWarning - <<'PY'
from pathlib import Path
import ast

source = Path("deltaaegis.py").read_text(encoding="utf-8")
tree = ast.parse(source)

required_functions = {
    "dashboard_netsniper_import_latest_payload",
    "dashboard_netsniper_scan_start_payload",
}

function_sources = {}
lines = source.splitlines()

for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name in required_functions:
        end = getattr(node, "end_lineno", node.lineno)
        function_sources[node.name] = "\n".join(lines[node.lineno - 1:end])

missing = sorted(required_functions - set(function_sources))
if missing:
    raise SystemExit(
        "missing backend function(s): " + ", ".join(missing)
    )

for name, function_source in function_sources.items():
    if '"receipt": receipt' not in function_source:
        raise SystemExit(
            f"{name} does not preserve a receipt in its response"
        )

if 'dashboard_action_receipt(\n        "netsniper.import_latest"' not in function_sources[
    "dashboard_netsniper_import_latest_payload"
]:
    raise SystemExit("import latest receipt builder missing")

if 'dashboard_action_receipt(\n        "netsniper.scan_start"' not in function_sources[
    "dashboard_netsniper_scan_start_payload"
]:
    raise SystemExit("scan start receipt builder missing")

required_ui_fragments = (
    "function dashboardActionReceiptLabel(value)",
    "function dashboardActionReceiptValue(value)",
    "function renderDashboardActionReceipt(target, receipt, fallbackPayload)",
    "renderDashboardActionReceipt(output, payload.receipt, payload);",
    'action: "netsniper.scan_cancel"',
    ".replace(/\\\\b\\\\w/g, function (character) {",
)

for fragment in required_ui_fragments:
    if fragment not in source:
        raise SystemExit(f"missing UI receipt fragment: {fragment}")

raw_dump = "output.textContent = JSON.stringify(payload, null, 2);"
raw_dump_count = source.count(raw_dump)

if raw_dump_count != 0:
    raise SystemExit(
        f"expected no remaining legacy raw action dumps, found {raw_dump_count}"
    )

legacy_cancel = (
    'result.textContent = `${payload.cancellation_action || "requested"}: '
    '${payload.message || "cancellation request accepted"}`;'
)
if legacy_cancel in source:
    raise SystemExit("legacy cancellation result assignment remains")

if source.count("renderDashboardActionReceipt(output, payload.receipt, payload);") < 2:
    raise SystemExit(
        "NetSniper import and scan-start receipt migrations are missing"
    )

print("static backend and UI checks passed")
PY
echo "PASS: static backend and UI contract"

echo "[v0.40 checkpoint 2] functional backend receipts"
python3 - <<'PY'
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile


module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v040_checkpoint2"
spec = importlib.util.spec_from_file_location(module_name, module_path)

if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module

try:
    spec.loader.exec_module(module)
finally:
    sys.modules.pop(module_name, None)


class DummyConnection:
    def __init__(self) -> None:
        self.commits = 0

    def commit(self) -> None:
        self.commits += 1


with tempfile.TemporaryDirectory() as temp_directory:
    temp_root = Path(temp_directory)
    run_dir = temp_root / "runs" / "20260706-123456"
    run_dir.mkdir(parents=True)
    manifest = run_dir / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")

    module.dashboard_netsniper_runs_dir = lambda: temp_root / "runs"
    module.dashboard_netsniper_latest_completed_manifest = lambda _: manifest
    module.ingest_manifest = (
        lambda connection, manifest_path, export_path:
        "IMPORT 20260706-123456: quality=ACCEPTED, assets=12, events=3"
    )
    module.dashboard_netsniper_status_payload = lambda: {
        "import_ready": True,
    }

    import_payload = module.dashboard_netsniper_import_latest_payload(
        DummyConnection(),
        temp_root / "events.json",
    )

    receipt = import_payload.get("receipt") or {}

    if receipt.get("action") != "netsniper.import_latest":
        raise SystemExit("import receipt action mismatch")

    if receipt.get("message") != "Imported NetSniper run 20260706-123456.":
        raise SystemExit("import receipt message mismatch")

    if (receipt.get("identifiers") or {}).get("run_id") != "20260706-123456":
        raise SystemExit("import receipt run identifier missing")

    root = temp_root / "NetSniper"
    root.mkdir()
    script = root / "netsniper.sh"
    script.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    runs = root / "runs"
    runs.mkdir()
    logs = temp_root / "logs"

    module.validate_private_cidr = lambda value: str(value)
    module.validate_netsniper_scan_profile = lambda value: str(value)
    module.dashboard_active_scan_job = lambda connection: None
    module.dashboard_netsniper_root_path = lambda: root
    module.dashboard_netsniper_runs_dir = lambda: runs
    module.DEFAULT_SCAN_LOGS = logs
    module.create_scan_job = lambda *args, **kwargs: {
        "job_id": "scan-example",
        "status": "QUEUED",
    }
    started = []
    module.dashboard_start_scan_job_thread = lambda **kwargs: started.append(kwargs)

    connection = DummyConnection()
    scan_payload = module.dashboard_netsniper_scan_start_payload(
        connection,
        {
            "target": "192.168.4.0/24",
            "scan_profile": "balanced",
        },
        temp_root / "deltaaegis.db",
        temp_root / "events.json",
    )

    scan_receipt = scan_payload.get("receipt") or {}

    if scan_receipt.get("action") != "netsniper.scan_start":
        raise SystemExit("scan receipt action mismatch")

    if scan_receipt.get("message") != "NetSniper scan queued successfully.":
        raise SystemExit("scan receipt message mismatch")

    if (scan_receipt.get("identifiers") or {}).get("job_id") != "scan-example":
        raise SystemExit("scan receipt job identifier missing")

    summary = scan_receipt.get("summary") or {}

    if summary.get("target") != "192.168.4.0/24":
        raise SystemExit("scan receipt target missing")

    if summary.get("scan_profile") != "balanced":
        raise SystemExit("scan receipt profile missing")

    if summary.get("status") != "QUEUED":
        raise SystemExit("scan receipt status missing")

    if connection.commits != 1:
        raise SystemExit("scan start did not preserve transaction commit")

    if len(started) != 1:
        raise SystemExit("scan start did not preserve worker launch")

print("functional backend receipt checks passed")
PY
echo "PASS: functional backend receipts"

echo "[v0.40 checkpoint 2] foundation compatibility"
tools/validate_v0_40_action_receipt_contract.sh
echo "PASS: foundation compatibility"

echo "[v0.40 checkpoint 2] repository hygiene"
git diff --check

unexpected_paths="$(
  {
    git diff --name-only
    git ls-files --others --exclude-standard
  } | sort -u | grep -Ev '^$|^deltaaegis\.py$|^tools/validate_v0_40_action_receipt_contract\.sh$|^tools/validate_v0_40_netsniper_action_receipts\.sh$|^tools/validate_v0_40_schedule_action_receipts\.sh$|^tools/validate_v0_40_trueaegis_action_receipts\.sh$|^tools/validate_v0_40_admin_workflow_action_receipts\.sh$' || true
)"

if [[ -n "$unexpected_paths" ]]; then
  echo "FAIL: unexpected changed paths"
  printf '%s\n' "$unexpected_paths"
  exit 1
fi

echo "PASS: repository hygiene"
echo "PASS: DeltaAegis v0.40 NetSniper action receipt validator"
