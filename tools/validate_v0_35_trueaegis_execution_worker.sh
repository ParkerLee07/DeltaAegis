#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

grep -Fq '("POST", "/api/trueaegis/run", "scan.start")' deltaaegis.py
grep -Fq 'def active_trueaegis_job_exists(' deltaaegis.py
grep -Fq 'def latest_trueaegis_validation_results_path(' deltaaegis.py
grep -Fq 'def execute_trueaegis_job(' deltaaegis.py
grep -Fq 'def dashboard_trueaegis_validation_worker(' deltaaegis.py
grep -Fq 'def dashboard_start_trueaegis_job_thread(' deltaaegis.py
grep -Fq 'def dashboard_trueaegis_validation_start_payload(' deltaaegis.py
grep -Fq 'route == "/api/trueaegis/run"' deltaaegis.py
grep -Fq 'subprocess.run(' deltaaegis.py

python3 - <<'PY'
from pathlib import Path
import importlib.util
import json
import sys
import tempfile

module_path = Path("deltaaegis.py")
spec = importlib.util.spec_from_file_location("deltaaegis_v035_execute", module_path)
delta = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = delta
spec.loader.exec_module(delta)


def insert_snapshot_fixture(connection, manifest_path):
    snapshot_values = {
        "scan_id": "scan-exec-001",
        "manifest_path": str(manifest_path),
        "target": "192.168.1.0/24",
        "network_scope": "192.168.1.0/24",
        "scanner_version": "netsniper-test",
        "telemetry_contract": "netsniper-run-v3",
        "schema_version": "netsniper-run-v3",
        "manifest_schema_version": "netsniper-run-v3",
        "scan_profile": "balanced",
        "created_at": "2026-07-01T00:00:00Z",
        "imported_at": "2026-07-01T00:00:01Z",
        "quality_status": "ACCEPTED",
        "quality_reason": "fixture",
        "bundle_status": "COMPLETE",
        "xml_exit_status": "ok",
        "hosts_up": 1,
        "hosts_total": 1,
        "identity_coverage": 1.0,
        "is_accepted_baseline": 1,
    }
    snapshot_columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(snapshots)").fetchall()
    }
    insert_values = {
        key: value
        for key, value in snapshot_values.items()
        if key in snapshot_columns
    }

    def default_value(column_name, column_type):
        lower_name = str(column_name or "").lower()
        lower_type = str(column_type or "").lower()
        if lower_name == "bundle_status":
            return "COMPLETE"
        if lower_name == "quality_status":
            return "ACCEPTED"
        if lower_name == "quality_reason":
            return "fixture"
        if lower_name == "xml_exit_status":
            return "ok"
        if lower_name == "identity_coverage":
            return 1.0
        if lower_name.endswith("_json"):
            return "{}"
        if lower_name.endswith("_at"):
            return "2026-07-01T00:00:00Z"
        if lower_name.startswith("is_"):
            return 1
        if "count" in lower_name or lower_name.startswith("hosts_"):
            return 0
        if "int" in lower_type:
            return 0
        if "real" in lower_type or "float" in lower_type or "double" in lower_type:
            return 0.0
        return ""

    for row in connection.execute("PRAGMA table_info(snapshots)").fetchall():
        name = row["name"]
        if name in insert_values or row["pk"]:
            continue
        if row["notnull"] and row["dflt_value"] is None:
            insert_values[name] = default_value(name, row["type"])

    required = {"scan_id", "manifest_path"}
    missing = required - set(insert_values)
    assert not missing, f"snapshots table missing required fixture columns: {sorted(missing)}"

    columns_sql = ", ".join(insert_values)
    placeholders = ", ".join("?" for _ in insert_values)
    connection.execute(
        f"INSERT INTO snapshots ({columns_sql}) VALUES ({placeholders})",
        tuple(insert_values.values()),
    )


with tempfile.TemporaryDirectory() as tmp:
    tmp_path = Path(tmp)
    db_path = tmp_path / "deltaaegis.db"
    logs_dir = tmp_path / "trueaegis-logs"
    manifest_path = tmp_path / "netsniper-run" / "manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps({
            "schema_version": "netsniper-run-v3",
            "status": "COMPLETE",
            "scan_id": "scan-exec-001",
            "target": "192.168.1.0/24",
        }),
        encoding="utf-8",
    )

    trueaegis_path = tmp_path / "TrueAegis" / "trueaegis.py"
    trueaegis_path.parent.mkdir(parents=True)
    trueaegis_path.write_text(
        '''#!/usr/bin/env python3
import json
import sys
from datetime import datetime
from pathlib import Path

base = Path(__file__).resolve().parent
out_dir = base / "validation_results"
out_dir.mkdir(parents=True, exist_ok=True)
manifest = Path(sys.argv[1])
assert manifest.name == "manifest.json"
assert "--validate" in sys.argv
assert "--quiet" in sys.argv
out = out_dir / ("validation_" + datetime.utcnow().strftime("%Y%m%d-%H%M%S") + ".json")
out.write_text(json.dumps([
    {
        "finding_id": "HTTP_EXPOSED",
        "host": "192.168.1.10",
        "port": 80,
        "protocol": "http",
        "transport": "tcp",
        "status": "CONFIRMED",
        "validated": True,
        "safe": False,
        "confidence": "HIGH",
        "summary": "Synthetic validation output"
    }
], indent=2), encoding="utf-8")
print(f"validation_results={out}")
''',
        encoding="utf-8",
    )
    trueaegis_path.chmod(0o755)

    connection = delta.connect(db_path)
    try:
        insert_snapshot_fixture(connection, manifest_path)
        connection.commit()

        context = delta.dashboard_trueaegis_orchestration_context_payload(
            connection,
            scope="192.168.1.0/24",
            trueaegis_path=trueaegis_path,
        )
        assert context["ready_to_start"] is True, context
        assert context["execution_enabled"] is False

        job = delta.create_trueaegis_job(
            connection,
            scan_id="scan-exec-001",
            network_scope="192.168.1.0/24",
            manifest_path=manifest_path,
            trueaegis_path=trueaegis_path,
        )
        connection.commit()

        result = delta.execute_trueaegis_job(
            connection,
            job_id=job["job_id"],
            manifest_path=manifest_path,
            trueaegis_path=trueaegis_path,
            logs_dir=logs_dir,
        )

        assert result["status"] == "COMPLETED", result
        assert result["exit_code"] == 0, result
        assert result["validation_results_path"], result
        assert Path(result["validation_results_path"]).is_file(), result
        assert Path(result["stdout_log_path"]).is_file(), result
        assert Path(result["stderr_log_path"]).is_file(), result
        assert result["imported_observations"] == 1, result
        assert result["validation_run_id"], result

        active = delta.active_trueaegis_job_exists(connection)
        assert active is False, active

        latest_output = delta.latest_trueaegis_validation_results_path(
            trueaegis_path.parent / "validation_results"
        )
        assert latest_output == Path(result["validation_results_path"])
    finally:
        connection.close()

print("[PASS] v0.35 TrueAegis execution worker python checks passed")
PY

echo "[PASS] DeltaAegis v0.35 TrueAegis execution worker validation passed"
