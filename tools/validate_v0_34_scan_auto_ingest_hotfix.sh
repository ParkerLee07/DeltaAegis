#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

python3 - <<'PY'
from pathlib import Path
import os
import stat
import tempfile
import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    db_path = root / "deltaaegis.db"
    events_path = root / "events.jsonl"
    logs_dir = root / "logs"
    netsniper_root = root / "NetSniper"
    runs_dir = netsniper_root / "runs"
    netsniper = netsniper_root / "netsniper.sh"

    runs_dir.mkdir(parents=True)
    logs_dir.mkdir(parents=True)

    script = (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'target=""\n'
        'profile="balanced"\n'
        "while [[ $# -gt 0 ]]; do\n"
        '  case "$1" in\n'
        '    --target) target="${2:-}"; shift 2 ;;\n'
        '    --profile) profile="${2:-balanced}"; shift 2 ;;\n'
        "    *) shift ;;\n"
        "  esac\n"
        "done\n"
        'run_dir="${DELTAAEGIS_TEST_RUNS_DIR}/fake-run-001"\n'
        'mkdir -p "$run_dir"\n'
        'cat > "$run_dir/manifest.json" <<EOF\n'
        "{\n"
        '  "status": "COMPLETE",\n'
        '  "target": "'"$target"'",\n'
        '  "network_scope": "'"$target"'",\n'
        '  "scan_profile_effective": "'"$profile"'",\n'
        '  "scan_profile_requested": "'"$profile"'",\n'
        '  "scan_id": "fake-scan-001",\n'
        '  "scanner_version": "netsniper-test",\n'
        '  "created_at": "2026-07-01T00:00:00+00:00"\n'
        "}\n"
        "EOF\n"
        'printf \'{"status":"COMPLETE","run_dir":"%s","target":"%s","return_code":0}\\n\' "$run_dir" "$target"\n'
    )

    netsniper.write_text(script, encoding="utf-8")
    netsniper.chmod(netsniper.stat().st_mode | stat.S_IXUSR)

    os.environ["DELTAAEGIS_NETSNIPER_ROOT"] = str(netsniper_root)
    os.environ["DELTAAEGIS_TEST_RUNS_DIR"] = str(runs_dir)

    connection = deltaaegis.connect(db_path)

    tables = {
        row["name"]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert "scan_schedules" in tables, tables

    scan_job_columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(scan_jobs)")
    }
    assert "scan_profile" in scan_job_columns, scan_job_columns

    captured = {}
    original_thread = deltaaegis.dashboard_start_scan_job_thread

    def fake_start_thread(**kwargs):
        captured.update(kwargs)
        return None

    deltaaegis.dashboard_start_scan_job_thread = fake_start_thread
    try:
        payload = deltaaegis.dashboard_netsniper_scan_start_payload(
            connection,
            {"target": "192.168.56.0/24", "scan_profile": "balanced"},
            db_path=db_path,
            events_path=events_path,
        )
    finally:
        deltaaegis.dashboard_start_scan_job_thread = original_thread

    job_id = payload["job_id"]
    row = connection.execute(
        "SELECT auto_ingest, scan_profile FROM scan_jobs WHERE job_id = ?",
        (job_id,),
    ).fetchone()
    assert row is not None
    assert int(row["auto_ingest"]) == 1, dict(row)
    assert payload.get("auto_ingest") is True, payload
    assert captured.get("auto_ingest") is True, captured
    assert captured.get("scan_profile") == "balanced", captured

    deltaaegis.update_scan_job(
        connection,
        job_id,
        status="COMPLETED",
        finished_at=deltaaegis.utc_now_text(),
        exit_code=0,
        message="synthetic dashboard launch complete",
    )
    connection.commit()

    ingest_calls = []
    original_ingest = deltaaegis.ingest_manifest

    def fake_ingest_manifest(conn, manifest_path, export_path):
        ingest_calls.append((Path(manifest_path), Path(export_path)))
        conn.execute(
            """
            INSERT INTO snapshots (
                scan_id, manifest_path, target, network_scope, scanner_version,
                scan_profile, created_at, imported_at, bundle_status, quality_status,
                quality_reason, xml_exit_status, hosts_up, hosts_down, hosts_total,
                mac_backed_assets, identity_coverage, is_accepted_baseline
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "fake-scan-001", str(manifest_path), "192.168.57.0/24",
                "192.168.57.0/24", "netsniper-test", "balanced",
                deltaaegis.utc_now_text(), deltaaegis.utc_now_text(),
                "COMPLETE", "ACCEPTED", "synthetic auto-ingest validator",
                "success", 1, 0, 1, 1, 1.0, 1,
            ),
        )
        return "IMPORTED fake-scan-001"

    deltaaegis.ingest_manifest = fake_ingest_manifest
    try:
        job = deltaaegis.create_scan_job(
            connection, "192.168.57.0/24", netsniper, runs_dir,
            auto_ingest=True, scan_profile="balanced",
        )
        connection.commit()

        final_job = deltaaegis.execute_scan_job(
            connection, job["job_id"], "192.168.57.0/24",
            netsniper, runs_dir, logs_dir, events_path,
            auto_ingest=True, scan_profile="balanced",
        )
    finally:
        deltaaegis.ingest_manifest = original_ingest

    assert final_job["status"] == "COMPLETED", final_job
    assert "auto-ingest=IMPORTED fake-scan-001" in final_job["message"], final_job
    assert ingest_calls, "execute_scan_job did not call ingest_manifest"
    snapshot = connection.execute(
        "SELECT quality_status FROM snapshots WHERE scan_id = 'fake-scan-001'"
    ).fetchone()
    assert snapshot is not None and snapshot["quality_status"] == "ACCEPTED"

    schedule = deltaaegis.create_scan_schedule(
        connection,
        name="Synthetic Auto Ingest Schedule",
        target="192.168.58.0/24",
        scan_profile="balanced",
        cadence_minutes=60,
        enabled=True,
        auto_ingest=True,
    )
    connection.commit()

    execute_calls = []
    original_execute = deltaaegis.execute_scan_job

    def fake_execute_scan_job(
        conn, job_id, target, netsniper_path, runs_dir_arg,
        logs_dir_arg, events_path_arg, auto_ingest=False,
        scan_profile="balanced",
    ):
        execute_calls.append({
            "job_id": job_id,
            "target": target,
            "auto_ingest": auto_ingest,
            "scan_profile": scan_profile,
        })
        deltaaegis.update_scan_job(
            conn,
            job_id,
            status="COMPLETED",
            finished_at=deltaaegis.utc_now_text(),
            bundle_path=str(runs_dir / "fake-run-002"),
            exit_code=0,
            message=f"scheduled fake scan completed auto_ingest={auto_ingest}",
        )
        conn.commit()
        row = conn.execute("SELECT * FROM scan_jobs WHERE job_id = ?", (job_id,)).fetchone()
        return deltaaegis.scan_job_to_dict(row)

    deltaaegis.execute_scan_job = fake_execute_scan_job
    try:
        schedule_results = deltaaegis.run_due_scan_schedules(
            connection, netsniper, runs_dir, logs_dir, events_path, max_runs=1,
        )
    finally:
        deltaaegis.execute_scan_job = original_execute

    assert execute_calls, "schedule runner did not execute a due scan"
    assert execute_calls[0]["auto_ingest"] is True, execute_calls
    assert execute_calls[0]["scan_profile"] == "balanced", execute_calls
    assert schedule_results and schedule_results[0]["action"] in {"ran", "executed"}, schedule_results

    refreshed = connection.execute(
        "SELECT last_status, last_job_id FROM scan_schedules WHERE schedule_id = ?",
        (schedule["schedule_id"],),
    ).fetchone()
    assert refreshed is not None
    assert refreshed["last_status"] == "COMPLETED", dict(refreshed)
    assert refreshed["last_job_id"], dict(refreshed)

print("[PASS] v0.34 NetSniper auto-ingest hotfix checks passed")
PY

echo "[PASS] DeltaAegis v0.34 NetSniper auto-ingest hotfix validation passed"
