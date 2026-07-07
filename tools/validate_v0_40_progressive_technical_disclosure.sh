#!/usr/bin/env bash
set -euo pipefail

REPO="${HOME}/DeltaAegis"
EXPECTED_BRANCH="feature/v0.40-human-readable-operator-actions"
EXPECTED_BASE="e6124b0"

cd "$REPO"

echo "DeltaAegis v0.40 Progressive Technical Disclosure Validator"
echo "============================================================"

branch="$(git branch --show-current)"
if [[ "$branch" != "$EXPECTED_BRANCH" ]]; then
  echo "FAIL: expected branch $EXPECTED_BRANCH, found $branch"
  exit 1
fi

if ! git merge-base --is-ancestor "$EXPECTED_BASE" HEAD; then
  echo "FAIL: branch does not descend from Checkpoint 5 commit $EXPECTED_BASE"
  exit 1
fi

echo "[v0.40 checkpoint 6] syntax"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py
echo "PASS: syntax without warnings"

echo "[v0.40 checkpoint 6] static progressive-disclosure contract"
python3 - <<'PY'
from pathlib import Path

source = Path("deltaaegis.py").read_text(encoding="utf-8")

required = (
    '<summary>Technical paths</summary>',
    '<summary>Technical command preview</summary>',
    '<summary>Detected NetSniper paths</summary>',
    '<summary>Latest run metadata</summary>',
    '<summary>Cancellation evidence</summary>',
    '<summary>Stdout tail</summary>',
    '<summary>Stderr tail</summary>',
    '<div class="status" id="netsniper-import-result">',
    '<div class="status" id="netsniper-scan-start-result">',
    '<div class="status" id="netsniper-schedule-result">',
    '<td><details><summary>View details</summary><pre class="muted">${escapeHtml(safeAuditDetails(event))}</pre></details></td>',
    '<td><details><summary>View details</summary><pre class="muted">${operatorAuditEscape(operatorAuditSafeDetails(event))}</pre></details></td>',
    '<td><details><summary>View details</summary><pre class="muted">${cleanupEscape(cleanupAuditSafeDetails(event))}</pre></details></td>',
)

for fragment in required:
    if fragment not in source:
        raise SystemExit(f"missing progressive-disclosure fragment: {fragment}")

legacy_default_visible = (
    '<h4>Command preview</h4>\n            <pre><code>',
    '<h2>Detected paths</h2>\n      <pre id="netsniper-paths">',
    '<h2>Latest run metadata</h2>\n      <pre id="netsniper-latest-json">',
    '<pre id="netsniper-import-result">',
    '<pre id="netsniper-scan-start-result">',
    '<pre id="netsniper-schedule-result">',
    '<h3>Cancellation reason</h3>\n        <pre id="netsniper-live-job-cancel-reason-display">',
    '<h3>Stdout tail</h3>',
    '<h3>Stderr tail</h3>',
)

for fragment in legacy_default_visible:
    if fragment in source:
        raise SystemExit(
            f"default-visible technical surface remains: {fragment}"
        )

if '<details open' in source:
    raise SystemExit("technical details must default closed")

if "JSON.stringify(payload.receipt" in source:
    raise SystemExit("receipt diagnostic JSON is rendered by default")

print("static progressive-disclosure contract passed")
PY
echo "PASS: static progressive-disclosure contract"

echo "[v0.40 checkpoint 6] functional page rendering"
python3 -W error::SyntaxWarning - <<'PY'
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v040_checkpoint6"
spec = importlib.util.spec_from_file_location(module_name, module_path)

if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module

try:
    spec.loader.exec_module(module)
finally:
    sys.modules.pop(module_name, None)


netsniper_html = module.render_netsniper_page()

for fragment in (
    '<summary>Detected NetSniper paths</summary>',
    '<summary>Latest run metadata</summary>',
    '<summary>Cancellation evidence</summary>',
    '<summary>Stdout tail</summary>',
    '<summary>Stderr tail</summary>',
):
    if fragment not in netsniper_html:
        raise SystemExit(
            f"rendered NetSniper page missing: {fragment}"
        )

for element_id in (
    "netsniper-paths",
    "netsniper-latest-json",
    "netsniper-live-job-cancel-reason-display",
    "netsniper-live-job-stdout",
    "netsniper-live-job-stderr",
):
    if f'id="{element_id}"' not in netsniper_html:
        raise SystemExit(
            f"rendered NetSniper page lost element: {element_id}"
        )

users_html = module.dashboard_operator_users_shell_html()
session_html = module.dashboard_operator_session_shell_html()
reset_html = module.dashboard_operator_reset_shell_html()

if users_html.count("<details><summary>View details</summary>") < 1:
    raise SystemExit("user-management audit details are not collapsed")

if session_html.count("<details><summary>View details</summary>") < 1:
    raise SystemExit("operator access-audit details are not collapsed")

if reset_html.count("<details><summary>View details</summary>") < 1:
    raise SystemExit("telemetry-reset audit details are not collapsed")

# Preserve the explicit technical tools that were already correctly hidden.
for fragment in (
    'copyButton.textContent = "Copy /api/session JSON";',
    'output.id = "operator-session-json-output";',
    "output.hidden = true;",
):
    if fragment not in session_html:
        raise SystemExit(
            f"operator session explicit JSON control lost: {fragment}"
        )

combined = users_html + session_html + reset_html + netsniper_html

# Raw API links remain available for deliberate technical access.
for fragment in (
    'href="/api/admin/users"',
    'href="/api/access-audit?limit=50"',
    'href="/api/telemetry-cleanup/preview"',
    'href="/api/netsniper/status"',
):
    if fragment not in combined:
        raise SystemExit(f"raw API link lost: {fragment}")

print("functional page rendering checks passed")
PY
echo "PASS: functional page rendering"

echo "[v0.40 checkpoint 6] staged compatibility"
if [[ "${DELTAAEGIS_V040_SKIP_COMPAT:-0}" == "1" ]]; then
  echo "SKIP: compatibility checks delegated to flat validation"
else
  DELTAAEGIS_V040_SKIP_COMPAT=1 "tools/validate_v0_40_action_receipt_contract.sh"
  DELTAAEGIS_V040_SKIP_COMPAT=1 "tools/validate_v0_40_netsniper_action_receipts.sh"
  DELTAAEGIS_V040_SKIP_COMPAT=1 "tools/validate_v0_40_schedule_action_receipts.sh"
  DELTAAEGIS_V040_SKIP_COMPAT=1 "tools/validate_v0_40_trueaegis_action_receipts.sh"
  DELTAAEGIS_V040_SKIP_COMPAT=1 "tools/validate_v0_40_admin_workflow_action_receipts.sh"
fi
echo "PASS: staged compatibility"
echo "[v0.40 checkpoint 6] repository hygiene"
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
echo "PASS: DeltaAegis v0.40 progressive technical disclosure validator"
