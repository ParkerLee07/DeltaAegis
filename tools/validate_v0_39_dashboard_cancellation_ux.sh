#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

printf '%s\n' \
  "DeltaAegis v0.39 Dashboard Cancellation UX Validator" \
  "====================================================="

python3 -m py_compile deltaaegis.py

python3 - <<'PY'
from pathlib import Path

source = Path("deltaaegis.py").read_text(encoding="utf-8")

required = (
    'id="netsniper-live-job-cancel-form"',
    'class="live-job-cancel-form"',
    'id="netsniper-live-job-cancel-reason"',
    'maxlength="500"',
    'placeholder="Reason for stopping this active scan"',
    'required>',
    'id="netsniper-live-job-cancel"',
    'class="danger"',
    'id="netsniper-live-job-cancel-result"',
    'id="netsniper-live-job-cancel-requested-at"',
    'id="netsniper-live-job-cancel-requested-by"',
    'id="netsniper-live-job-cancelled-at"',
    'id="netsniper-live-job-cancel-reason-display"',
    "let selectedNetSniperJob = null;",
    "const canCancel = netSniperJobIsActive(job) && !job.cancel_requested_at;",
    "async function cancelSelectedNetSniperJob(event)",
    "A cancellation reason is required.",
    "window.confirm(",
    'fetch("/api/netsniper/scan-cancel"',
    'method: "POST"',
    'headers: {"Content-Type": "application/json"}',
    'body: JSON.stringify({job_id: jobId, reason: reason})',
    "await loadNetSniperScanJobs();",
    "await loadNetSniperJobDetail(jobId);",
    'addEventListener("submit", cancelSelectedNetSniperJob)',
    "the browser never supplies or signals a process PID",
)

for fragment in required:
    assert fragment in source, fragment

handler_start = source.index(
    "    async function cancelSelectedNetSniperJob(event)"
)
handler_end = source.index(
    "    function renderNetSniperScanJobs(payload)",
    handler_start,
)
handler = source[handler_start:handler_end]

for forbidden in (
    "process_pid",
    "os.kill",
    "killpg",
    "SIGTERM",
    "SIGKILL",
):
    assert forbidden not in handler, forbidden

assert "if (!jobId || !netSniperJobIsActive(job))" in handler
assert "if (!reason)" in handler
assert "button.disabled = true" in handler
assert "reasonInput.disabled = true" in handler
assert "response.status === 401 || response.status === 403" in handler

render_start = source.index(
    "    function renderNetSniperJobDetail(payload)"
)
render_end = source.index(
    "    async function loadNetSniperJobDetail(jobId)",
    render_start,
)
render = source[render_start:render_end]

assert "job.cancel_requested_at" in render
assert "job.cancel_requested_by" in render
assert "job.cancel_reason" in render
assert "job.cancelled_at" in render
assert "cancelForm.hidden = !canCancel" in render
assert "cancelButton.disabled = !canCancel" in render

print("PASS: active-job-only cancellation control")
print("PASS: required bounded cancellation reason")
print("PASS: explicit browser confirmation")
print("PASS: in-flight control disabling")
print("PASS: authenticated cancellation API submission")
print("PASS: immediate detail and ledger refresh")
print("PASS: cancellation metadata rendering")
print("PASS: cancellation-request state rendering")
print("PASS: terminal cancellation control suppression")
print("PASS: no browser PID or signal control")
print("PASS: DeltaAegis v0.39 dashboard cancellation UX validator")
PY

git diff --check
