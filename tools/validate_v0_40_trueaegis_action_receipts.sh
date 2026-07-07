#!/usr/bin/env bash
set -euo pipefail

REPO="${HOME}/DeltaAegis"
EXPECTED_BRANCH="feature/v0.40-human-readable-operator-actions"
EXPECTED_BASE="0053b53"

cd "$REPO"

echo "DeltaAegis v0.40 TrueAegis Action Receipt Validator"
echo "====================================================="

branch="$(git branch --show-current)"
if [[ "$branch" != "$EXPECTED_BRANCH" ]]; then
  echo "FAIL: expected branch $EXPECTED_BRANCH, found $branch"
  exit 1
fi

if ! git merge-base --is-ancestor "$EXPECTED_BASE" HEAD; then
  echo "FAIL: branch does not descend from Checkpoint 3 commit $EXPECTED_BASE"
  exit 1
fi

echo "[v0.40 checkpoint 4] syntax"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py
echo "PASS: syntax without warnings"

echo "[v0.40 checkpoint 4] static backend receipt contract"
python3 -W error::SyntaxWarning - <<'PY'
from pathlib import Path
import ast

source = Path("deltaaegis.py").read_text(encoding="utf-8")
tree = ast.parse(source)
lines = source.splitlines()

required = {
    "dashboard_trueaegis_validation_start_payload",
    "dashboard_trueaegis_validation_ingest_payload",
}

functions = {}

for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name in required:
        end = getattr(node, "end_lineno", node.lineno)
        functions[node.name] = "\n".join(lines[node.lineno - 1:end])

missing = sorted(required - set(functions))
if missing:
    raise SystemExit(
        "missing TrueAegis payload function(s): " + ", ".join(missing)
    )

for name, body in functions.items():
    if '"receipt": receipt' not in body:
        raise SystemExit(f"{name} does not return a receipt")

if (
    'dashboard_action_receipt(\n        "trueaegis.validation_start"'
    not in functions["dashboard_trueaegis_validation_start_payload"]
):
    raise SystemExit("TrueAegis validation-start receipt builder missing")

if (
    'dashboard_action_receipt(\n        "trueaegis.validation_ingest"'
    not in functions["dashboard_trueaegis_validation_ingest_payload"]
):
    raise SystemExit("TrueAegis validation-ingest receipt builder missing")

print("static backend receipt contract passed")
PY
echo "PASS: static backend receipt contract"

echo "[v0.40 checkpoint 4] static UI receipt contract"
python3 - <<'PY'
from pathlib import Path

source = Path("deltaaegis.py").read_text(encoding="utf-8")

required_fragments = (
    "function trueAegisActionReceiptText(receipt, fallbackMessage)",
    "function trueAegisRenderActionReceipt(element, receipt, fallbackMessage)",
    "let deltaAegisTrueAegisLastRunReceipt = null;",
    'id="trueaegis-run-receipt"',
    "const result = await deltaAegisTrueAegisOrchestrationFetchJson",
    "deltaAegisTrueAegisLastRunReceipt = result.receipt || {",
    "trueAegisActionReceiptText(result.receipt, fallbackMessage)",
    "status.dataset.receiptSeverity",
    "element.textContent = trueAegisActionReceiptText",
)

for fragment in required_fragments:
    if fragment not in source:
        raise SystemExit(f"missing TrueAegis UI fragment: {fragment}")

run_start = source.find(
    "    async function deltaAegisTrueAegisOrchestrationRun() {"
)
run_end = source.find(
    "    if (!window.__deltaAegisTrueAegisOrchestrationPanelInitialized)",
    run_start,
)

if run_start < 0 or run_end < 0:
    raise SystemExit(
        "could not isolate the TrueAegis orchestration run handler"
    )

run_handler = source[run_start:run_end]

if (
    'const result = await deltaAegisTrueAegisOrchestrationFetchJson('
    '"/api/trueaegis/run"'
    not in run_handler
):
    raise SystemExit(
        "TrueAegis run handler does not retain the POST response"
    )

discarded_response_statement = (
    '        await deltaAegisTrueAegisOrchestrationFetchJson('
    '"/api/trueaegis/run", {'
)

if discarded_response_statement in run_handler:
    raise SystemExit(
        "TrueAegis run handler still contains the legacy discarded-response statement"
    )

if "JSON.stringify(result.receipt" in source:
    raise SystemExit("TrueAegis receipt is rendered as raw JSON")

print("static UI receipt contract passed")
PY
echo "PASS: static UI receipt contract"

echo "[v0.40 checkpoint 4] functional backend receipts"
python3 - <<'PY'
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile


module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v040_checkpoint4"
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
    root = Path(temp_directory)
    manifest = root / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    trueaegis = root / "trueaegis.py"
    trueaegis.write_text("# test\n", encoding="utf-8")

    module.active_trueaegis_job_exists = lambda connection: False
    module.dashboard_trueaegis_orchestration_context_payload = (
        lambda connection, scope=None: {
            "ready_to_start": True,
            "latest_scan": {
                "scan_id": "scan-example",
                "network_scope": "192.168.4.0/24",
            },
            "manifest_path": str(manifest),
            "trueaegis_path": str(trueaegis),
        }
    )
    module.create_trueaegis_job = lambda *args, **kwargs: {
        "job_id": "trueaegis-job-example",
        "status": "QUEUED",
    }
    started = []
    module.dashboard_start_trueaegis_job_thread = (
        lambda **kwargs: started.append(kwargs)
    )
    module.DEFAULT_TRUEAEGIS_LOGS = root / "logs"

    connection = DummyConnection()
    start_payload = module.dashboard_trueaegis_validation_start_payload(
        connection,
        {},
        root / "deltaaegis.db",
    )
    start_receipt = start_payload.get("receipt") or {}

    if start_receipt.get("action") != "trueaegis.validation_start":
        raise SystemExit("validation-start action mismatch")

    if start_receipt.get("message") != "TrueAegis validation queued successfully.":
        raise SystemExit("validation-start message mismatch")

    if (
        (start_receipt.get("identifiers") or {}).get("job_id")
        != "trueaegis-job-example"
    ):
        raise SystemExit("validation-start job identifier missing")

    if connection.commits != 1:
        raise SystemExit("validation-start commit was not preserved")

    if len(started) != 1:
        raise SystemExit("validation-start worker launch was not preserved")

    validation_path = root / "validation_results.json"
    validation_path.write_text("{}", encoding="utf-8")

    module.import_trueaegis_validation_results = (
        lambda connection, path: {
            "validation_run_id": "validation-example",
            "observation_count": 7,
        }
    )
    module.dashboard_validation_summary_payload = lambda connection: {
        "validation_run_count": 3,
        "observation_count": 21,
    }
    module.dashboard_validations_payload = lambda connection, limit=25: {
        "observations": [],
    }

    ingest_connection = DummyConnection()
    ingest_payload = module.dashboard_trueaegis_validation_ingest_payload(
        ingest_connection,
        {
            "mode": "path",
            "path": str(validation_path),
        },
    )
    ingest_receipt = ingest_payload.get("receipt") or {}

    if ingest_receipt.get("action") != "trueaegis.validation_ingest":
        raise SystemExit("validation-ingest action mismatch")

    if (
        ingest_receipt.get("message")
        != "Imported 7 TrueAegis validation observation(s)."
    ):
        raise SystemExit("validation-ingest message mismatch")

    if (
        (ingest_receipt.get("identifiers") or {}).get("validation_run_id")
        != "validation-example"
    ):
        raise SystemExit("validation-ingest identifier missing")

    if ingest_receipt["summary"].get("observations_imported") != 7:
        raise SystemExit("validation-ingest observation count missing")

    if ingest_connection.commits != 1:
        raise SystemExit("validation-ingest commit was not preserved")

print("functional backend receipt checks passed")
PY
echo "PASS: functional backend receipts"

echo "[v0.40 checkpoint 4] staged compatibility"
if [[ "${DELTAAEGIS_V040_SKIP_COMPAT:-0}" == "1" ]]; then
  echo "SKIP: compatibility checks delegated to flat validation"
else
  DELTAAEGIS_V040_SKIP_COMPAT=1 "tools/validate_v0_40_action_receipt_contract.sh"
  DELTAAEGIS_V040_SKIP_COMPAT=1 "tools/validate_v0_40_netsniper_action_receipts.sh"
  DELTAAEGIS_V040_SKIP_COMPAT=1 "tools/validate_v0_40_schedule_action_receipts.sh"
fi
echo "PASS: staged compatibility"
echo "[v0.40 checkpoint 4] repository hygiene"
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
echo "PASS: DeltaAegis v0.40 TrueAegis action receipt validator"
