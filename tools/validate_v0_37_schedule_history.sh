#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[v0.37 checkpoint 1] syntax check"
python3 -m py_compile deltaaegis.py

echo "[v0.37 checkpoint 1] static contract checks"
python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = {
    "permission matrix route": '("GET", "/api/netsniper/schedule-history", "dashboard.read")',
    "scan_jobs schedule_id schema": "schedule_id TEXT NOT NULL DEFAULT ''",
    "scan_jobs schedule_id index": "idx_scan_jobs_schedule_id",
    "scan_jobs schedule_id migration": 'ensure_column(connection, "scan_jobs", "schedule_id"',
    "create_scan_job schedule_id arg": "schedule_id: str | None = None",
    "query schedule history": "def query_scan_schedule_history(",
    "history payload": "def dashboard_netsniper_schedule_history_payload(",
    "history row converter": "def scan_schedule_history_row_to_dict(",
    "history GET route": 'if route == "/api/netsniper/schedule-history":',
    "scheduled job linkage": 'schedule_id=schedule["schedule_id"]',
    "schedule history table": 'id="netsniper-schedule-history-body"',
    "schedule history JS render": "function renderNetSniperScheduleHistory(",
    "schedule history JS load": "async function loadNetSniperScheduleHistory()",
}

missing = [name for name, needle in required.items() if needle not in text]
if missing:
    raise SystemExit("Missing required schedule-history markers: " + ", ".join(missing))

if "/api/netsniper/schedule-history" not in text:
    raise SystemExit("schedule-history API route missing")

if "arbitrary shell" not in text:
    raise SystemExit("safety boundary text unexpectedly missing")

print("static checks passed")
PY

echo "[v0.37 checkpoint 1] functional schedule-history smoke test"
python3 - <<'PY'
import tempfile
from pathlib import Path

import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    db_path = Path(tmp) / "deltaaegis.db"
    conn = deltaaegis.connect(db_path)

    columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(scan_jobs)").fetchall()
    }
    if "schedule_id" not in columns:
        raise SystemExit("scan_jobs.schedule_id column missing after schema init")

    manual_job = deltaaegis.create_scan_job(
        conn,
        "192.168.5.0/24",
        Path("/tmp/netsniper.sh"),
        Path("/tmp/netsniper-runs"),
        auto_ingest=False,
        scan_profile="quick",
    )
    if manual_job.get("schedule_id") != "":
        raise SystemExit("manual scan jobs must not be linked to a schedule")

    schedule = deltaaegis.create_scan_schedule(
        conn,
        name="Checkpoint History Test",
        target="192.168.5.0/24",
        scan_profile="balanced",
        cadence_minutes=60,
        enabled=True,
        auto_ingest=True,
    )

    scheduled_job = deltaaegis.create_scan_job(
        conn,
        schedule["target"],
        Path("/tmp/netsniper.sh"),
        Path("/tmp/netsniper-runs"),
        auto_ingest=True,
        scan_profile=schedule["scan_profile"],
        schedule_id=schedule["schedule_id"],
    )

    deltaaegis.update_scan_job(
        conn,
        scheduled_job["job_id"],
        status="COMPLETED",
        finished_at=deltaaegis.utc_now_text(),
        exit_code=0,
        bundle_path="/tmp/netsniper-runs/example/manifest.json",
        status_json={"status": "COMPLETE"},
        message="checkpoint history test complete",
    )

    row = conn.execute(
        "SELECT * FROM scan_jobs WHERE job_id = ?",
        (scheduled_job["job_id"],),
    ).fetchone()
    final_job = deltaaegis.scan_job_to_dict(row)

    deltaaegis.update_scan_schedule_after_job(
        conn,
        schedule["schedule_id"],
        schedule["cadence_minutes"],
        final_job,
    )
    conn.commit()

    payload = deltaaegis.dashboard_netsniper_schedule_history_payload(conn, limit=10)
    history = payload.get("history") or []

    if not payload.get("ok"):
        raise SystemExit("schedule-history payload did not return ok=true")

    matching = [
        item for item in history
        if item.get("schedule_id") == schedule["schedule_id"]
        and (item.get("job") or {}).get("job_id") == scheduled_job["job_id"]
    ]

    if not matching:
        raise SystemExit("schedule-history payload did not link schedule to scheduled job")

    item = matching[0]
    if item["job"]["schedule_id"] != schedule["schedule_id"]:
        raise SystemExit("scheduled job schedule_id was not preserved in history payload")

    if item["job"]["status"] != "COMPLETED":
        raise SystemExit("scheduled job status was not preserved in history payload")

print("functional smoke test passed")
PY

echo "[v0.37 checkpoint 1] PASS"
