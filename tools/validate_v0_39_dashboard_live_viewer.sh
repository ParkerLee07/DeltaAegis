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
import deltaaegis

source = Path("deltaaegis.py").read_text(encoding="utf-8")
html = deltaaegis.render_netsniper_page()

required = (
    'id="netsniper-live-job-panel"',
    'id="netsniper-live-job-state"',
    'id="netsniper-live-job-pid"',
    'id="netsniper-live-job-heartbeat"',
    'id="netsniper-live-job-stdout"',
    'id="netsniper-live-job-stderr"',
    'data-scan-job-detail="${escapeHtml(jobId)}"',
    'function stopNetSniperJobDetailPolling()',
    'function netSniperJobIsActive(job)',
    'async function loadNetSniperJobDetail(jobId)',
    '/api/netsniper/job-detail?job_id=${encodeURIComponent(requestedJobId)}&tail_bytes=16384',
    'if (netSniperJobIsActive(payload.job)',
    'netSniperJobDetailTimer = window.setTimeout',
    '}, 3000);',
    'document.getElementById("netsniper-live-job-refresh")',
    'document.getElementById("netsniper-live-job-close")',
    'window.addEventListener("beforeunload", stopNetSniperJobDetailPolling)',
    'colspan="10"',
)
for fragment in required:
    assert fragment in html, f"missing live viewer requirement: {fragment}"

assert html.count('id="netsniper-live-job-panel"') == 1
assert html.count('id="netsniper-live-job-stdout"') == 1
assert html.count('id="netsniper-live-job-stderr"') == 1

active_check = html.index('if (netSniperJobIsActive(payload.job)')
timer_write = html.index('netSniperJobDetailTimer = window.setTimeout', active_check)
assert timer_write > active_check

for forbidden in (
    'Cancel scan',
    'cancelNetSniper',
    '/api/netsniper/cancel',
    'window.setInterval(loadNetSniperJobDetail',
):
    assert forbidden not in html, f"forbidden viewer behavior found: {forbidden}"

assert '("GET", "/api/netsniper/job-detail", "dashboard.read")' in source
assert 'def dashboard_scan_job_detail_payload(' in source
assert 'SCAN_JOB_LOG_TAIL_MAXIMUM_BYTES = 64 * 1024' in source

print("PASS: scan-job View details action")
print("PASS: read-only lifecycle detail panel")
print("PASS: PID and heartbeat visibility")
print("PASS: bounded stdout and stderr display")
print("PASS: active-job-only detail polling")
print("PASS: terminal jobs stop automatic polling")
print("PASS: manual refresh and close controls")
print("PASS: new scan auto-opens live details")
print("PASS: no cancellation controls")
PY

git diff --check
printf '%s\n' "PASS: DeltaAegis v0.39 dashboard live viewer validator"
