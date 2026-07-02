#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

python3 - <<'PY'
from pathlib import Path
import re

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = [
    "DASHBOARD_SCHEDULE_WORKER_INTERVAL_SECONDS = 60",
    "def dashboard_run_due_schedule_tick(",
    "def dashboard_schedule_worker_loop(",
    "def dashboard_start_schedule_worker_thread(",
    "dashboard_run_due_schedule_tick(",
    "run_due_scan_schedules(",
    "max_runs=1",
    "stop_event.wait(safe_interval)",
    'name="deltaaegis-dashboard-schedule-worker"',
    "daemon=True",
    "--enable-scheduled-scans",
    "--no-enable-scheduled-scans",
    "--schedule-worker-interval-seconds",
    "Scheduler: enabled, checks due NetSniper schedules every",
    "Scheduler: disabled",
]

for needle in required:
    if needle not in text:
        raise SystemExit(f"[FAIL] missing scheduled scan worker requirement: {needle}")

worker_start = text.find("def dashboard_schedule_worker_loop(")
worker_end = text.find("def dashboard_start_schedule_worker_thread(", worker_start)
if worker_start < 0 or worker_end < 0:
    raise SystemExit("[FAIL] could not bound dashboard schedule worker loop")
worker_block = text[worker_start:worker_end]

for needle in [
    "while not stop_event.is_set():",
    "dashboard_run_due_schedule_tick(",
    "max_runs=1",
    "stop_event.wait(safe_interval)",
]:
    if needle not in worker_block:
        raise SystemExit(f"[FAIL] worker loop missing guardrail: {needle}")

tick_start = text.find("def dashboard_run_due_schedule_tick(")
tick_end = text.find("def dashboard_schedule_worker_loop(", tick_start)
if tick_start < 0 or tick_end < 0:
    raise SystemExit("[FAIL] could not bound dashboard schedule tick")
tick_block = text[tick_start:tick_end]

for needle in [
    "connection = connect(db_path)",
    "return run_due_scan_schedules(",
    "netsniper_path=netsniper_path or (dashboard_netsniper_root_path() / \"netsniper.sh\")",
    "runs_dir=runs_dir or dashboard_netsniper_runs_dir()",
    "logs_dir=logs_dir or DEFAULT_SCAN_LOGS",
    "connection.close()",
]:
    if needle not in tick_block:
        raise SystemExit(f"[FAIL] schedule tick missing expected safe path: {needle}")

dashboard_start = text.find("if getattr(args, \"enable_scheduled_scans\", True):")
if dashboard_start < 0:
    raise SystemExit("[FAIL] dashboard startup must gate scheduled scans behind enable_scheduled_scans")

shutdown_required = [
    "if dashboard_schedule_worker_stop is not None:",
    "dashboard_schedule_worker_stop.set()",
    "if dashboard_schedule_worker_thread is not None:",
    "dashboard_schedule_worker_thread.join(timeout=2.0)",
]
for needle in shutdown_required:
    if needle not in text:
        raise SystemExit(f"[FAIL] dashboard shutdown missing conditional worker cleanup: {needle}")

if "shell=True" in text:
    raise SystemExit("[FAIL] scheduled scan worker release must not use shell=True")

print("[PASS] v0.36 scheduled scan worker python checks passed")
PY

echo "[PASS] DeltaAegis v0.36 scheduled scan worker validation passed"
