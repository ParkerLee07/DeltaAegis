#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "DeltaAegis v0.42 Dead-Scan Watchdog Validator"
echo "==============================================="

echo "[v0.42 hotfix A] source syntax"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py
echo "PASS: source syntax"

echo "[v0.42 hotfix A] static watchdog contract"
python3 - <<'PY'
from pathlib import Path

source = Path("deltaaegis.py").read_text(encoding="utf-8")
required = (
    "# v0.42 hotfix checkpoint A: dead-scan watchdog",
    'SCAN_JOB_WATCHDOG_SCHEMA_VERSION = "deltaaegis-scan-watchdog-v1"',
    "SCAN_JOB_WATCHDOG_STALE_MINUTES = 10",
    "def scan_job_process_liveness(",
    "def scan_job_watchdog_evaluation(",
    "def scan_job_watchdog_recover_dead_jobs(",
    'for key in (\n        "heartbeat_at",',
    'actor="schedule_runner"',
    'actor="dashboard_startup"',
    'job["watchdog"] = scan_job_watchdog_evaluation(job)',
    '"PID_REUSE_OR_UNEXPECTED_PROCESS"',
    '"LIVE_PROCESS_STALE_HEARTBEAT"',
    '"PROCESS_IDENTITY_UNVERIFIABLE"',
    'status_json["watchdog"] = evidence',
)

for marker in required:
    if marker not in source:
        raise SystemExit(f"missing watchdog marker: {marker}")

watchdog_block = source[
    source.index("def scan_job_watchdog_recover_dead_jobs("):
    source.index("def mark_stale_active_scan_jobs_failed(")
]
if "os.kill(" in watchdog_block or "terminate_scan_process_group(" in watchdog_block:
    raise SystemExit("automatic watchdog must not signal processes")

print("PASS: static watchdog contract")
PY

echo "[v0.42 hotfix A] functional liveness classification"
python3 - <<'PY'
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    db = root / "watchdog.db"
    proc = root / "proc"
    proc.mkdir()
    conn = deltaaegis.connect(db)
    now = datetime.now(timezone.utc)
    stale = (now - timedelta(minutes=30)).isoformat()
    fresh = (now - timedelta(minutes=2)).isoformat()
    netsniper = root / "netsniper.sh"
    netsniper.write_text("#!/usr/bin/env bash\n", encoding="utf-8")

    def create(target, *, status, timestamp, pid):
        job = deltaaegis.create_scan_job(
            conn,
            target,
            netsniper,
            root / "runs",
            auto_ingest=True,
            scan_profile="balanced",
        )
        conn.execute(
            """
            UPDATE scan_jobs
            SET status = ?, created_at = ?, updated_at = ?,
                started_at = ?, heartbeat_at = ?, process_pid = ?,
                stdout_log = ?, stderr_log = ?
            WHERE job_id = ?
            """,
            (
                status,
                timestamp,
                timestamp,
                timestamp if status == "RUNNING" else None,
                timestamp if status == "RUNNING" else None,
                pid,
                str(root / f"{job['job_id']}.stdout.log"),
                str(root / f"{job['job_id']}.stderr.log"),
                job["job_id"],
            ),
        )
        return job

    missing = create("192.168.10.0/24", status="RUNNING", timestamp=stale, pid=10101)
    queued = create("192.168.11.0/24", status="QUEUED", timestamp=stale, pid=None)
    reused = create("192.168.12.0/24", status="RUNNING", timestamp=stale, pid=10102)
    live_stale = create("192.168.13.0/24", status="RUNNING", timestamp=stale, pid=10103)
    fresh_missing = create("192.168.14.0/24", status="RUNNING", timestamp=fresh, pid=10104)
    conn.commit()

    (proc / "10102").mkdir()
    (proc / "10102" / "cmdline").write_bytes(b"/usr/bin/sleep\x001000\x00")
    (proc / "10103").mkdir()
    (proc / "10103" / "cmdline").write_bytes(
        b"/bin/bash\x00" + str(netsniper).encode() + b"\x00--non-interactive\x00"
    )

    report = deltaaegis.scan_job_watchdog_recover_dead_jobs(
        conn,
        now=now,
        stale_minutes=10,
        proc_root=proc,
        actor="validator",
    )

    expected_recovered = {missing["job_id"], queued["job_id"], reused["job_id"]}
    if set(report["recovered_job_ids"]) != expected_recovered:
        raise SystemExit(f"unexpected recovered jobs: {report['recovered_job_ids']}")
    if set(report["review_job_ids"]) != {live_stale["job_id"]}:
        raise SystemExit("live expected stale process was not held for review")

    for job_id in expected_recovered:
        row = conn.execute("SELECT * FROM scan_jobs WHERE job_id = ?", (job_id,)).fetchone()
        item = deltaaegis.scan_job_to_dict(row)
        if item["status"] != "FAILED":
            raise SystemExit(f"{job_id}: not marked FAILED")
        if item["exit_code"] != 130:
            raise SystemExit(f"{job_id}: exit code evidence missing")
        evidence = item["status_json"].get("watchdog") or {}
        if evidence.get("result") != "MARKED_FAILED":
            raise SystemExit(f"{job_id}: watchdog evidence missing")
        if not item.get("finished_at"):
            raise SystemExit(f"{job_id}: finished_at missing")

    live_status = conn.execute(
        "SELECT status FROM scan_jobs WHERE job_id = ?",
        (live_stale["job_id"],),
    ).fetchone()["status"]
    fresh_status = conn.execute(
        "SELECT status FROM scan_jobs WHERE job_id = ?",
        (fresh_missing["job_id"],),
    ).fetchone()["status"]
    if live_status != "RUNNING":
        raise SystemExit("live expected process was changed")
    if fresh_status != "RUNNING":
        raise SystemExit("fresh active row was changed")

    print("PASS: missing process recovery")
    print("PASS: stale queued-job recovery")
    print("PASS: PID-reuse recovery")
    print("PASS: live expected process held for review")
    print("PASS: fresh active row preserved")
    print("PASS: durable watchdog evidence")
    conn.close()
PY

echo "[v0.42 hotfix A] due-schedule retry after recovery"
python3 - <<'PY'
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    db = root / "schedule-retry.db"
    proc = root / "proc"
    proc.mkdir()
    netsniper = root / "netsniper.sh"
    netsniper.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    conn = deltaaegis.connect(db)
    now = datetime.now(timezone.utc)
    stale = (now - timedelta(minutes=30)).isoformat()
    due = (now - timedelta(minutes=5)).isoformat()

    blocker = deltaaegis.create_scan_job(
        conn,
        "192.168.20.0/24",
        netsniper,
        root / "runs",
        auto_ingest=True,
        scan_profile="balanced",
    )
    conn.execute(
        """
        UPDATE scan_jobs
        SET status = 'RUNNING', started_at = ?, heartbeat_at = ?,
            updated_at = ?, process_pid = 20202
        WHERE job_id = ?
        """,
        (stale, stale, stale, blocker["job_id"]),
    )
    schedule = deltaaegis.create_scan_schedule(
        conn,
        name="watchdog retry",
        target="192.168.21.0/24",
        scan_profile="balanced",
        cadence_minutes=120,
        enabled=True,
        auto_ingest=False,
    )
    conn.execute(
        "UPDATE scan_schedules SET next_run_at = ? WHERE schedule_id = ?",
        (due, schedule["schedule_id"]),
    )
    conn.commit()

    original_root = deltaaegis.SCAN_JOB_WATCHDOG_PROC_ROOT
    original_execute = deltaaegis.execute_scan_job
    deltaaegis.SCAN_JOB_WATCHDOG_PROC_ROOT = proc

    def fake_execute(connection, job_id, target, netsniper_path, runs_dir,
                     logs_dir, events_path, auto_ingest=False,
                     scan_profile="balanced"):
        finished = deltaaegis.utc_now_text()
        deltaaegis.update_scan_job(
            connection,
            job_id,
            status="COMPLETED",
            started_at=finished,
            heartbeat_at=finished,
            finished_at=finished,
            exit_code=0,
            status_json={"status": "completed"},
            message="watchdog retry validator completed",
        )
        connection.commit()
        row = connection.execute(
            "SELECT * FROM scan_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        return deltaaegis.scan_job_to_dict(row)

    deltaaegis.execute_scan_job = fake_execute
    try:
        results = deltaaegis.run_due_scan_schedules(
            conn,
            netsniper_path=netsniper,
            runs_dir=root / "runs",
            logs_dir=root / "logs",
            events_path=root / "events.jsonl",
            max_runs=1,
        )
    finally:
        deltaaegis.execute_scan_job = original_execute
        deltaaegis.SCAN_JOB_WATCHDOG_PROC_ROOT = original_root

    if len(results) != 1 or results[0].get("action") != "ran":
        raise SystemExit(f"due schedule did not run after recovery: {results}")
    blocker_status = conn.execute(
        "SELECT status FROM scan_jobs WHERE job_id = ?",
        (blocker["job_id"],),
    ).fetchone()["status"]
    if blocker_status != "FAILED":
        raise SystemExit("dead blocker was not recovered")

    print("PASS: dead blocker recovered before active-job check")
    print("PASS: overdue schedule ran in the same scheduler pass")
    conn.close()
PY

echo "[v0.42 hotfix A] scan-job detail visibility"
python3 - <<'PY'
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    conn = deltaaegis.connect(root / "detail.db")
    job = deltaaegis.create_scan_job(
        conn,
        "192.168.30.0/24",
        root / "netsniper.sh",
        root / "runs",
    )
    old = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    conn.execute(
        """
        UPDATE scan_jobs
        SET status = 'RUNNING', started_at = ?, heartbeat_at = ?,
            updated_at = ?, process_pid = 30303
        WHERE job_id = ?
        """,
        (old, old, old, job["job_id"]),
    )
    conn.commit()
    payload = deltaaegis.dashboard_scan_job_detail_payload(
        conn,
        job["job_id"],
        logs_root=root,
    )
    watchdog = payload.get("job", {}).get("watchdog") or {}
    if watchdog.get("classification") != "DEAD_PROCESS_STALE_ROW":
        raise SystemExit(f"unexpected detail watchdog payload: {watchdog}")
    print("PASS: scan-job detail exposes watchdog classification")
    conn.close()
PY

echo "[v0.42 hotfix A] compatibility boundary"
echo "PASS: predecessor recovery compatibility is owned by the release gate"

echo "[v0.42 hotfix A] repository hygiene"
git diff --check
echo "PASS: repository hygiene"

echo "PASS: DeltaAegis v0.42 dead-scan watchdog validator"
