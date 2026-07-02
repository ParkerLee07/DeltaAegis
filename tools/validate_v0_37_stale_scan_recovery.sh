#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[v0.37 hotfix] syntax check"
python3 -m py_compile deltaaegis.py

echo "[v0.37 hotfix] static stale-scan recovery checks"
python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = [
    'STALE_SCAN_JOB_RECOVERY_CONFIRMATION = "MARK STALE SCANS FAILED"',
    'STALE_SCAN_JOB_DEFAULT_MINUTES = 360',
    'def query_stale_active_scan_jobs(',
    'def mark_stale_active_scan_jobs_failed(',
    'def dashboard_netsniper_stale_scan_recovery_payload(',
    '"/api/netsniper/stale-scan-fail"',
    '"admin.telemetry.cleanup"',
    'Mark stale active scans failed',
    'TrueAegis validation is configured and launched separately',
    'NetSniper schedules do not automatically run TrueAegis',
    'recoverStaleNetSniperScans',
]

for needle in required:
    if needle not in text:
        raise SystemExit(f"missing stale-scan recovery marker: {needle}")

if 'shell=True' in text:
    raise SystemExit("stale scan recovery must not introduce shell=True")

print("static stale-scan recovery checks passed")
PY

echo "[v0.37 hotfix] functional stale-scan recovery smoke test"
python3 - <<'PY'
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sqlite3
import tempfile
import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "deltaaegis-stale-scan.db"
    conn = deltaaegis.connect(db)

    fresh_job = deltaaegis.create_scan_job(
        conn,
        "192.168.10.0/24",
        Path("/tmp/netsniper.sh"),
        Path("/tmp/runs"),
        auto_ingest=True,
        scan_profile="balanced",
    )

    stale_job = deltaaegis.create_scan_job(
        conn,
        "192.168.11.0/24",
        Path("/tmp/netsniper.sh"),
        Path("/tmp/runs"),
        auto_ingest=True,
        scan_profile="accurate",
    )

    now = datetime.now(timezone.utc)
    fresh_time = (now - timedelta(minutes=5)).isoformat()
    stale_time = (now - timedelta(hours=12)).isoformat()

    conn.execute(
        """
        UPDATE scan_jobs
        SET status = 'RUNNING',
            created_at = ?,
            updated_at = ?,
            started_at = ?,
            message = 'fresh active test job'
        WHERE job_id = ?
        """,
        (fresh_time, fresh_time, fresh_time, fresh_job["job_id"]),
    )

    conn.execute(
        """
        UPDATE scan_jobs
        SET status = 'RUNNING',
            created_at = ?,
            updated_at = ?,
            started_at = ?,
            message = 'stale active test job'
        WHERE job_id = ?
        """,
        (stale_time, stale_time, stale_time, stale_job["job_id"]),
    )
    conn.commit()

    stale = deltaaegis.query_stale_active_scan_jobs(conn, stale_minutes=360)

    if len(stale) != 1:
        raise SystemExit(f"expected one stale active job, got {len(stale)}")

    if stale[0]["job_id"] != stale_job["job_id"]:
        raise SystemExit("wrong job identified as stale")

    try:
        deltaaegis.dashboard_netsniper_stale_scan_recovery_payload(
            conn,
            {"confirmation": "wrong", "stale_minutes": 360},
        )
    except deltaaegis.DashboardAdminUserActionError:
        pass
    else:
        raise SystemExit("stale recovery accepted missing/wrong confirmation")

    payload = deltaaegis.dashboard_netsniper_stale_scan_recovery_payload(
        conn,
        {
            "confirmation": deltaaegis.STALE_SCAN_JOB_RECOVERY_CONFIRMATION,
            "stale_minutes": 360,
        },
    )

    if payload.get("recovered_count") != 1:
        raise SystemExit(f"expected one recovered job, got {payload.get('recovered_count')}")

    stale_row = conn.execute(
        "SELECT status, exit_code, message FROM scan_jobs WHERE job_id = ?",
        (stale_job["job_id"],),
    ).fetchone()

    fresh_row = conn.execute(
        "SELECT status FROM scan_jobs WHERE job_id = ?",
        (fresh_job["job_id"],),
    ).fetchone()

    if stale_row["status"] != "FAILED":
        raise SystemExit("stale job was not marked FAILED")

    if int(stale_row["exit_code"]) != 130:
        raise SystemExit("stale job exit_code was not set to 130")

    if "blocking scheduled scans" not in stale_row["message"]:
        raise SystemExit("stale job recovery message is missing expected text")

    if fresh_row["status"] != "RUNNING":
        raise SystemExit("fresh active job should not have been marked failed")

    conn.close()

print("functional stale-scan recovery smoke test passed")
PY

echo "[v0.37 hotfix] README/CHANGELOG checks"
python3 - <<'PY'
from pathlib import Path

readme = Path("README.md").read_text(encoding="utf-8")
changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
release_gate = Path("tools/validate_v0_37_release.sh").read_text(encoding="utf-8")

required_readme = [
    "ADMIN-only stale scan-job recovery",
    "NetSniper schedules run NetSniper and optional auto-ingest only",
    "TrueAegis validation remains a separate guarded workflow",
]

for needle in required_readme:
    if needle not in readme:
        raise SystemExit(f"missing README stale-scan/TrueAegis marker: {needle}")

required_changelog = [
    "stale active NetSniper scan-job recovery",
    "TrueAegis validation is configured and launched separately",
]

for needle in required_changelog:
    if needle not in changelog:
        raise SystemExit(f"missing CHANGELOG stale-scan/TrueAegis marker: {needle}")

if "validate_v0_37_stale_scan_recovery.sh" not in release_gate:
    raise SystemExit("v0.37 release gate does not run stale-scan recovery validator")

print("README/CHANGELOG checks passed")
PY

echo "[v0.37 hotfix] PASS"
