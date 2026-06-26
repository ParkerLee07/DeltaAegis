#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

ok() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

grep -Fq 'DASHBOARD_SCHEDULE_WORKER_INTERVAL_SECONDS = 60' deltaaegis.py \
    || fail "missing dashboard schedule worker interval constant"

grep -Fq 'def dashboard_run_due_schedule_tick(' deltaaegis.py \
    || fail "missing dashboard schedule tick helper"

grep -Fq 'def dashboard_schedule_worker_loop(' deltaaegis.py \
    || fail "missing dashboard schedule worker loop"

grep -Fq 'def dashboard_start_schedule_worker_thread(' deltaaegis.py \
    || fail "missing dashboard schedule worker thread starter"

grep -Fq 'run_due_scan_schedules(' deltaaegis.py \
    || fail "dashboard schedule worker does not reuse due-schedule runner"

grep -Fq 'max_runs=1' deltaaegis.py \
    || fail "dashboard schedule worker does not limit each tick to one schedule"

grep -Fq 'threading.Event()' deltaaegis.py \
    || fail "dashboard schedule worker does not use a stop event"

grep -Fq 'name="deltaaegis-dashboard-schedule-worker"' deltaaegis.py \
    || fail "dashboard schedule worker thread is not named"

grep -Fq 'daemon=True' deltaaegis.py \
    || fail "dashboard schedule worker thread is not daemonized"

grep -Fq 'stop_event.wait(safe_interval)' deltaaegis.py \
    || fail "dashboard schedule worker does not sleep through stop_event.wait"

grep -Fq 'dashboard_start_schedule_worker_thread(' deltaaegis.py \
    || fail "dashboard server does not start schedule worker"

grep -Fq 'dashboard_schedule_worker_stop.set()' deltaaegis.py \
    || fail "dashboard server does not stop schedule worker"

grep -Fq 'dashboard_schedule_worker_thread.join(timeout=2.0)' deltaaegis.py \
    || fail "dashboard server does not join schedule worker"

if grep -Fq 'shell=True' deltaaegis.py; then
    fail "shell=True appeared in deltaaegis.py"
fi

python3 - <<'DELTA_31_5_PYTEST'
from pathlib import Path
import importlib.util
import sys
import tempfile
import time

spec = importlib.util.spec_from_file_location("deltaaegis", "deltaaegis.py")
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = module
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory() as tmp:
    tmp_path = Path(tmp)
    db_path = tmp_path / "deltaaegis.db"
    events_path = tmp_path / "events.jsonl"

    calls = []

    def fake_run_due_scan_schedules(
        connection,
        netsniper_path,
        runs_dir,
        logs_dir,
        events_path,
        max_runs=1,
    ):
        calls.append(
            {
                "netsniper_path": str(netsniper_path),
                "runs_dir": str(runs_dir),
                "logs_dir": str(logs_dir),
                "events_path": str(events_path),
                "max_runs": max_runs,
            }
        )
        return [{"action": "ran", "schedule_id": "test-schedule"}]

    module.run_due_scan_schedules = fake_run_due_scan_schedules

    tick_results = module.dashboard_run_due_schedule_tick(
        db_path=db_path,
        events_path=events_path,
        max_runs=1,
    )

    assert tick_results == [{"action": "ran", "schedule_id": "test-schedule"}]
    assert calls
    assert calls[-1]["max_runs"] == 1
    assert calls[-1]["events_path"] == str(events_path)

    loop_calls = []
    stop_event = module.threading.Event()

    def fake_tick_once(**kwargs):
        loop_calls.append(kwargs)
        stop_event.set()
        return []

    module.dashboard_run_due_schedule_tick = fake_tick_once

    module.dashboard_schedule_worker_loop(
        db_path=db_path,
        events_path=events_path,
        stop_event=stop_event,
        interval_seconds=1,
        quiet=True,
    )

    assert len(loop_calls) == 1
    assert loop_calls[0]["max_runs"] == 1

    thread_calls = []

    def fake_thread_tick(**kwargs):
        thread_calls.append(kwargs)
        return []

    module.dashboard_run_due_schedule_tick = fake_thread_tick

    thread, stop = module.dashboard_start_schedule_worker_thread(
        db_path=db_path,
        events_path=events_path,
        interval_seconds=1,
        quiet=True,
    )

    deadline = time.time() + 3
    while not thread_calls and time.time() < deadline:
        time.sleep(0.05)

    stop.set()
    thread.join(timeout=2)

    assert thread.daemon is True
    assert thread.name == "deltaaegis-dashboard-schedule-worker"
    assert thread_calls

print("[PASS] v0.31 dashboard schedule worker python checks passed")
DELTA_31_5_PYTEST

ok "DeltaAegis v0.31 dashboard schedule worker validation passed"
