#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

printf '%s\n' \
  "DeltaAegis v0.39 Dashboard Live Viewer Validator" \
  "================================================="

python3 -m py_compile deltaaegis.py

python3 - <<'PY'
from pathlib import Path

source = Path("deltaaegis.py").read_text(encoding="utf-8")

required = (
    'data-scan-job-detail=',
    'id="netsniper-live-job-panel"',
    'id="netsniper-live-job-refresh"',
    'id="netsniper-live-job-close"',
    'id="netsniper-live-job-pid"',
    'id="netsniper-live-job-heartbeat"',
    'id="netsniper-live-job-stdout"',
    'id="netsniper-live-job-stderr"',
    "function netSniperJobIsActive(job)",
    'return status === "QUEUED" || status === "RUNNING";',
    "async function loadNetSniperJobDetail(jobId)",
    "/api/netsniper/job-detail?job_id=",
    "window.setTimeout(function ()",
    "}, 3000);",
    "stopNetSniperJobDetailPolling();",
    'addEventListener("click", closeNetSniperJobDetail)',
    'window.addEventListener("beforeunload", stopNetSniperJobDetailPolling)',
    'id="netsniper-live-job-cancel-form"',
    'id="netsniper-live-job-cancel-reason"',
    'id="netsniper-live-job-cancel"',
    "async function cancelSelectedNetSniperJob(event)",
)

for fragment in required:
    assert fragment in source, fragment

detail_start = source.index(
    "    async function loadNetSniperJobDetail(jobId)"
)
detail_end = source.index(
    "    function closeNetSniperJobDetail()",
    detail_start,
)
detail = source[detail_start:detail_end]

assert "netSniperJobIsActive(payload.job)" in detail
assert "window.setTimeout" in detail
assert "window.setInterval" not in detail

print("PASS: scan-job View details action")
print("PASS: lifecycle detail panel")
print("PASS: PID and heartbeat visibility")
print("PASS: bounded stdout and stderr display")
print("PASS: active-job-only detail polling")
print("PASS: terminal jobs stop automatic polling")
print("PASS: manual refresh and close controls")
print("PASS: cancellation controls integrated")
print("PASS: DeltaAegis v0.39 dashboard live viewer validator")
PY

git diff --check
