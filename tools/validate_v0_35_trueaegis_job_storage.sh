#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

grep -Fq 'TRUEAEGIS_JOB_STATUSES' deltaaegis.py
grep -Fq 'CREATE TABLE IF NOT EXISTS trueaegis_jobs' deltaaegis.py
grep -Fq 'idx_trueaegis_jobs_status' deltaaegis.py
grep -Fq '("GET", "/api/trueaegis-jobs", "dashboard.read")' deltaaegis.py
grep -Fq 'def create_trueaegis_job(' deltaaegis.py
grep -Fq 'def update_trueaegis_job(' deltaaegis.py
grep -Fq 'def query_trueaegis_jobs(' deltaaegis.py
grep -Fq 'def dashboard_trueaegis_jobs_payload(' deltaaegis.py
grep -Fq 'elif route == "/api/trueaegis-jobs":' deltaaegis.py

python3 - <<'PY'
from pathlib import Path
import importlib.util
import sys
import tempfile

module_path = Path("deltaaegis.py")
spec = importlib.util.spec_from_file_location("deltaaegis_v035_storage", module_path)
delta = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = delta
assert spec.loader is not None
spec.loader.exec_module(delta)

with tempfile.TemporaryDirectory() as tmp:
    tmp_path = Path(tmp)
    db_path = tmp_path / "deltaaegis.db"
    manifest_path = tmp_path / "manifest.json"
    trueaegis_path = tmp_path / "trueaegis.py"
    manifest_path.write_text('{"schema_version":"netsniper-run-v3","status":"COMPLETE","scan_id":"scan-test","target":"192.168.1.0/24"}', encoding="utf-8")
    trueaegis_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    connection = delta.connect(db_path)
    try:
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(trueaegis_jobs)").fetchall()
        }
        required = {
            "job_id", "status", "scan_id", "network_scope", "manifest_path",
            "trueaegis_path", "validation_results_path", "validation_run_id",
            "imported_observations", "correlation_count", "stdout_log_path",
            "stderr_log_path", "exit_code", "message", "created_at", "updated_at",
            "started_at", "completed_at",
        }
        missing = required - columns
        assert not missing, f"trueaegis_jobs missing columns: {sorted(missing)}"

        job = delta.create_trueaegis_job(
            connection,
            scan_id="scan-test",
            network_scope="192.168.1.0/24",
            manifest_path=manifest_path,
            trueaegis_path=trueaegis_path,
        )
        connection.commit()

        assert job["status"] == "QUEUED"
        assert job["scan_id"] == "scan-test"
        assert job["network_scope"] == "192.168.1.0/24"
        assert job["manifest_path"] == str(manifest_path)
        assert job["trueaegis_path"] == str(trueaegis_path)

        delta.update_trueaegis_job(
            connection,
            job["job_id"],
            status="RUNNING",
            started_at="2026-07-01T00:00:00Z",
            message="TrueAegis validation running",
        )
        delta.update_trueaegis_job(
            connection,
            job["job_id"],
            status="COMPLETED",
            completed_at="2026-07-01T00:01:00Z",
            validation_results_path=str(tmp_path / "validation.json"),
            validation_run_id="trueaegis-test",
            imported_observations=2,
            correlation_count=1,
            exit_code=0,
            message="TrueAegis validation completed",
        )
        connection.commit()

        payload = delta.dashboard_trueaegis_jobs_payload(connection, limit=5)
        assert len(payload) == 1
        row = payload[0]
        assert row["job_id"] == job["job_id"]
        assert row["status"] == "COMPLETED"
        assert row["imported_observations"] == 2
        assert row["correlation_count"] == 1
        assert row["exit_code"] == 0

        filtered = delta.dashboard_trueaegis_jobs_payload(
            connection,
            limit=5,
            status="COMPLETED",
            scope="192.168.1.0/24",
        )
        assert len(filtered) == 1

        try:
            delta.update_trueaegis_job(connection, job["job_id"], status="INVALID")
        except delta.DeltaAegisError:
            pass
        else:
            raise AssertionError("invalid TrueAegis job status was accepted")
    finally:
        connection.close()

print("[PASS] v0.35 TrueAegis job storage python checks passed")
PY

echo "[PASS] DeltaAegis v0.35 TrueAegis job storage validation passed"
