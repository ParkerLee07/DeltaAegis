#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[v0.37 hotfix] syntax check"
python3 -m py_compile deltaaegis.py

echo "[v0.37 hotfix] static schedule-block retry checks"
python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = [
    "def active_scan_job_row(",
    'return active_scan_job_row(connection) is not None',
    'active_job = active_scan_job_row(connection)',
    '"action": "blocked"',
    '"scheduled scan blocked: another scan job is active; "',
    '"schedule remains due and will retry without cadence delay"',
    '"active_job": scan_job_to_dict(active_job)',
    '"schedule": schedule',
]

for needle in required:
    if needle not in text:
        raise SystemExit(f"missing schedule-block retry marker: {needle}")

forbidden = '''if active_scan_job_exists(connection):
            skipped = mark_scan_schedule_skipped(
                connection,
                schedule["schedule_id"],
                schedule["cadence_minutes"],
                "scheduled scan skipped: another scan job is active",
            )'''

if forbidden in text:
    raise SystemExit("active-job conflict still marks due schedules skipped/postponed")

print("static schedule-block retry checks passed")
PY

echo "[v0.37 hotfix] functional schedule-block retry smoke test"
python3 - <<'PY'
from datetime import datetime, timezone, timedelta
from pathlib import Path
import tempfile
import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "deltaaegis-schedule-block-retry.db"
    conn = deltaaegis.connect(db)

    active = deltaaegis.create_scan_job(
        conn,
        "192.168.10.0/24",
        Path("/tmp/netsniper.sh"),
        Path("/tmp/runs"),
        auto_ingest=True,
        scan_profile="accurate",
    )

    schedule = deltaaegis.create_scan_schedule(
        conn,
        name="blocked retry schedule",
        target="192.168.11.0/24",
        cadence_minutes=120,
        auto_ingest=True,
        scan_profile="accurate",
        enabled=True,
    )

    active_time = datetime.now(timezone.utc).isoformat(timespec="seconds")
    due_time = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(timespec="seconds")

    conn.execute(
        """
        UPDATE scan_jobs
        SET status = 'RUNNING',
            started_at = ?,
            updated_at = ?,
            message = 'active scan blocks schedule test'
        WHERE job_id = ?
        """,
        (
            active_time,
            active_time,
            active["job_id"],
        ),
    )

    conn.execute(
        """
        UPDATE scan_schedules
        SET next_run_at = ?,
            updated_at = ?,
            message = 'due schedule before blocked retry test'
        WHERE schedule_id = ?
        """,
        (
            due_time,
            due_time,
            schedule["schedule_id"],
        ),
    )

    conn.commit()

    before = conn.execute(
        """
        SELECT next_run_at, last_status, skip_count, message
        FROM scan_schedules
        WHERE schedule_id = ?
        """,
        (schedule["schedule_id"],),
    ).fetchone()

    results = deltaaegis.run_due_scan_schedules(
        conn,
        netsniper_path=Path("/tmp/netsniper.sh"),
        runs_dir=Path("/tmp/runs"),
        logs_dir=Path("/tmp/logs"),
        events_path=Path("/tmp/events.jsonl"),
        max_runs=1,
    )

    after = conn.execute(
        """
        SELECT next_run_at, last_status, skip_count, message
        FROM scan_schedules
        WHERE schedule_id = ?
        """,
        (schedule["schedule_id"],),
    ).fetchone()

    if len(results) != 1:
        raise SystemExit(f"expected one blocked result, got {len(results)}")

    if results[0].get("action") != "blocked":
        raise SystemExit(f"expected action=blocked, got {results[0].get('action')}")

    if results[0].get("active_job", {}).get("job_id") != active["job_id"]:
        raise SystemExit("blocked result did not include the active scan job")

    if after["next_run_at"] != before["next_run_at"]:
        raise SystemExit("blocked schedule next_run_at changed; it should remain due")

    if int(after["skip_count"] or 0) != int(before["skip_count"] or 0):
        raise SystemExit("blocked schedule skip_count changed; it should not be incremented")

    if after["last_status"] != before["last_status"]:
        raise SystemExit("blocked schedule last_status changed; it should not be marked SKIPPED")

    if after["message"] != before["message"]:
        raise SystemExit("blocked schedule message changed; blocked contention should not mutate schedule state")

    conn.close()

print("functional schedule-block retry smoke test passed")
PY

echo "[v0.37 hotfix] release metadata checks"
python3 - <<'PY'
from pathlib import Path

readme = Path("README.md").read_text(encoding="utf-8")
changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
release_gate = Path("tools/validate_v0_37_release.sh").read_text(encoding="utf-8")

if "blocked-schedule retry behavior" not in readme:
    raise SystemExit("README missing blocked-schedule retry summary")

if "blocked by another active scan remains due" not in changelog:
    raise SystemExit("CHANGELOG missing blocked-schedule retry fix")

if "validate_v0_37_schedule_block_retry.sh" not in release_gate:
    raise SystemExit("v0.37 release gate does not run schedule-block retry validator")

print("release metadata checks passed")
PY

echo "[v0.37 hotfix] PASS"
