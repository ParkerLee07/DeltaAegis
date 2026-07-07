#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "DeltaAegis v0.40 Release Metadata Validator"
echo "============================================="

python3 -W error::SyntaxWarning - <<'PY'
from pathlib import Path
import ast
import subprocess


def fail(message: str) -> None:
    raise SystemExit(message)


def git_lines(*args: str) -> set[str]:
    completed = subprocess.run(
        ["git", *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return {
        line.strip()
        for line in completed.stdout.splitlines()
        if line.strip()
    }


readme = Path("README.md").read_text(encoding="utf-8")
changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
source = Path("deltaaegis.py").read_text(encoding="utf-8")
notes_path = Path("RELEASE_NOTES_v0.40.0.md")
checklist_path = Path("MANUAL_VERIFICATION_v0.40.0.md")

if not notes_path.is_file():
    fail("missing RELEASE_NOTES_v0.40.0.md")

if not checklist_path.is_file():
    fail("missing MANUAL_VERIFICATION_v0.40.0.md")

notes = notes_path.read_text(encoding="utf-8")
checklist = checklist_path.read_text(encoding="utf-8")

required_readme = [
    "## Current Release — v0.40.0",
    "**DeltaAegis v0.40.0 — Human-Readable Operator Actions**",
    "deltaaegis-dashboard-action-receipt-v1",
    "Progressive technical disclosure",
    "Mutation and read-model separation",
    "./tools/validate_v0_40_release_gate.sh",
    "MANUAL_VERIFICATION_v0.40.0.md",
]

for needle in required_readme:
    if needle not in readme:
        fail(f"README missing v0.40 release marker: {needle}")

new_current = readme.find("## Current Release — v0.40.0")
old_current = readme.find("## Current Release — v0.39.0")

if new_current < 0:
    fail("README does not contain the v0.40 current-release heading")

if old_current >= 0 and old_current < new_current:
    fail("README still presents v0.39 before the v0.40 current release")

required_changelog = [
    "## DeltaAegis v0.40.0 — Human-Readable Operator Actions",
    "shared action-receipt contract",
    "progressive technical disclosure",
    "mutation responses",
    "validate_v0_40_release_gate.sh",
]

for needle in required_changelog:
    if needle not in changelog:
        fail(f"CHANGELOG missing v0.40 release marker: {needle}")

if not changelog.startswith(
    "## DeltaAegis v0.40.0 — Human-Readable Operator Actions"
):
    fail("CHANGELOG does not start with the v0.40 release entry")

required_source = [
    '"""DeltaAegis v0.40.0: Human-Readable Operator Actions.',
    "v0.40 Human-Readable Operator Actions",
    'server_version = "DeltaAegisDashboard/0.40.0"',
    "DeltaAegis v0.40.0 — Human-Readable Operator Actions",
    '"schema_version": DASHBOARD_ACTION_RECEIPT_SCHEMA_VERSION',
    '"receipt": receipt',
]

for needle in required_source:
    if needle not in source:
        fail(f"deltaaegis.py missing v0.40 release marker: {needle}")

for forbidden in [
    '"""DeltaAegis v0.39.0:',
    "v0.39 Scan Job Lifecycle Observability",
    'server_version = "DeltaAegisDashboard/0.39.0"',
    'description="DeltaAegis v0.39.0',
    "v0.40.0-dev",
]:
    if forbidden in source:
        fail(f"stale or prerelease source copy remains: {forbidden}")

required_notes = [
    "# DeltaAegis v0.40.0 — Human-Readable Operator Actions",
    "Stable action receipts",
    "Progressive technical disclosure",
    "Mutation and read-model separation",
    "Security boundaries preserved",
    "validate_v0_40_release_gate.sh",
]

for needle in required_notes:
    if needle not in notes:
        fail(f"release notes missing v0.40 detail: {needle}")

required_checklist = [
    "# DeltaAegis v0.40.0 Manual Verification",
    "HOLD — do not merge, tag, or publish",
    "NetSniper actions",
    "TrueAegis",
    "Telemetry cleanup",
    "Parker approves the dashboard behavior",
]

for needle in required_checklist:
    if needle not in checklist:
        fail(f"manual checklist missing required item: {needle}")

tree = ast.parse(source)
functions = {
    node.name: node
    for node in ast.walk(tree)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
}
cancel = functions.get("dashboard_netsniper_scan_cancel_payload")

if cancel is None:
    fail("scan-cancellation payload function is missing")

return_keys: set[str] = set()

for node in ast.walk(cancel):
    if not isinstance(node, ast.Return):
        continue
    if not isinstance(node.value, ast.Dict):
        continue

    for key in node.value.keys:
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return_keys.add(key.value)

required_cancel_keys = {
    "ok",
    "action",
    "job_id",
    "cancellation_action",
    "job",
    "message",
    "receipt",
}

missing_cancel_keys = sorted(required_cancel_keys - return_keys)

if missing_cancel_keys:
    fail(
        "scan-cancellation response lost required fields: "
        + ", ".join(missing_cancel_keys)
    )

expected_executable_validators = [
    "tools/validate_v0_40_action_receipt_contract.sh",
    "tools/validate_v0_40_netsniper_action_receipts.sh",
    "tools/validate_v0_40_schedule_action_receipts.sh",
    "tools/validate_v0_40_trueaegis_action_receipts.sh",
    "tools/validate_v0_40_admin_workflow_action_receipts.sh",
    "tools/validate_v0_40_progressive_technical_disclosure.sh",
    "tools/validate_v0_40_payload_separation.sh",
    "tools/validate_v0_40_all.sh",
    "tools/validate_v0_40_release_metadata.sh",
    "tools/validate_v0_40_v0_39_compatibility.sh",
    "tools/validate_v0_40_dashboard_javascript_syntax.sh",
    "tools/validate_v0_40_broken_pipe_response.sh",
    "tools/validate_v0_40_release_gate.sh",
]

for name in expected_executable_validators:
    path = Path(name)
    if not path.is_file() or not path.stat().st_mode & 0o111:
        fail(f"missing or non-executable v0.40 validator: {name}")

expected_branch_paths = {
    "deltaaegis.py",
    "README.md",
    "CHANGELOG.md",
    "RELEASE_NOTES_v0.40.0.md",
    "MANUAL_VERIFICATION_v0.40.0.md",
    "tools/validate_v0_40_action_receipt_contract.sh",
    "tools/validate_v0_40_netsniper_action_receipts.sh",
    "tools/validate_v0_40_schedule_action_receipts.sh",
    "tools/validate_v0_40_trueaegis_action_receipts.sh",
    "tools/validate_v0_40_admin_workflow_action_receipts.sh",
    "tools/validate_v0_40_progressive_technical_disclosure.sh",
    "tools/validate_v0_40_payload_separation.sh",
    "tools/validate_v0_40_all.sh",
    "tools/validate_v0_40_release_metadata.sh",
    "tools/validate_v0_40_v0_39_compatibility.sh",
    "tools/validate_v0_40_dashboard_javascript_syntax.sh",
    "tools/validate_v0_40_broken_pipe_response.sh",
    "tools/validate_v0_40_release_gate.sh",
}

changed_paths = set()

try:
    changed_paths |= git_lines("diff", "--name-only", "v0.39.0..HEAD")
except subprocess.CalledProcessError:
    fail("could not compare the release branch against tag v0.39.0")

changed_paths |= git_lines("diff", "--name-only")
changed_paths |= git_lines("ls-files", "--others", "--exclude-standard")

unexpected_paths = sorted(changed_paths - expected_branch_paths)
missing_paths = sorted(expected_branch_paths - changed_paths)

if unexpected_paths:
    fail(
        "unexpected paths are present in the v0.40 release diff: "
        + ", ".join(unexpected_paths)
    )

if missing_paths:
    fail(
        "expected v0.40 release paths are missing: "
        + ", ".join(missing_paths)
    )

print("PASS: README v0.40 release metadata")
print("PASS: CHANGELOG v0.40 release history")
print("PASS: source and dashboard v0.40 metadata")
print("PASS: scan-cancellation receipt contract")
print("PASS: release-note accuracy")
print("PASS: manual-verification hold")
print("PASS: validator inventory")
print("PASS: v0.39.0-to-v0.40.0 branch-path audit")
PY

echo "[v0.40 metadata] functional scan-cancellation receipt"

python3 -W error::SyntaxWarning - <<'PY'
import importlib.util
from pathlib import Path
import sys


module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v040_release_metadata"
spec = importlib.util.spec_from_file_location(module_name, module_path)

if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module

try:
    spec.loader.exec_module(module)
finally:
    sys.modules.pop(module_name, None)

module.scan_job_row = lambda connection, job_id: {"job_id": job_id}
module.request_scan_job_cancellation = lambda *args, **kwargs: {
    "job_id": args[1],
    "status": "RUNNING",
    "cancellation_action": "requested",
    "cancel_requested_by": kwargs["requested_by"],
    "cancel_reason": kwargs["reason"],
    "cancel_requested_at": "2026-07-07T12:00:00+00:00",
    "cancelled_at": None,
}
audit_calls = []
module.record_access_audit_event = (
    lambda *args, **kwargs: audit_calls.append((args, kwargs))
)

payload = module.dashboard_netsniper_scan_cancel_payload(
    object(),
    {
        "job_id": "scan-job-example",
        "reason": "manual release verification",
    },
    actor={
        "username": "admin.example",
        "role": "ADMIN",
        "auth_type": "session",
    },
)

receipt = payload.get("receipt") or {}

assert receipt.get("schema_version") == (
    "deltaaegis-dashboard-action-receipt-v1"
)
assert receipt.get("action") == "netsniper.scan_cancel"
assert receipt.get("severity") == "warning"
assert receipt.get("identifiers", {}).get("job_id") == "scan-job-example"
assert receipt.get("summary", {}).get("cancellation_action") == "requested"
assert receipt.get("summary", {}).get("requested_by") == "admin.example"
assert receipt.get("diagnostic_detail", {}).get("available") is True
assert len(audit_calls) == 1

print("PASS: functional scan-cancellation receipt")
PY

echo "[v0.40 metadata] CLI help smoke test"

python3 - <<'PY'
import subprocess


completed = subprocess.run(
    ["python3", "deltaaegis.py", "--help"],
    check=True,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
)

normalized = " ".join(completed.stdout.split())
expected = "DeltaAegis v0.40.0 — Human-Readable Operator Actions"

if expected not in normalized:
    raise SystemExit(
        f"CLI help missing v0.40 release title: {expected}\n"
        f"Normalized output:\n{normalized}"
    )

print("PASS: CLI help v0.40 release title")
PY

echo "PASS: DeltaAegis v0.40 release metadata validator"
