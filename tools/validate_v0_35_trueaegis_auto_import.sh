#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

grep -Fq 'def import_trueaegis_job_results(' deltaaegis.py
grep -Fq 'import_trueaegis_job_results(' deltaaegis.py
grep -Fq 'validation_run_id=validation_run_id' deltaaegis.py
grep -Fq 'imported_observations=imported_observations' deltaaegis.py
grep -Fq 'correlation_count=correlation_count' deltaaegis.py
grep -Fq 'if route == "/api/trueaegis/run":' deltaaegis.py
grep -Fq 'trueaegis_run_failed' deltaaegis.py

python3 - <<'PY'
from pathlib import Path
import importlib.util
import json
import sys
import tempfile

module_path = Path("deltaaegis.py")
spec = importlib.util.spec_from_file_location("deltaaegis_v035_auto_import", module_path)
delta = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = delta
spec.loader.exec_module(delta)


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
    if lower_name == "risk_level":
        return "LOW"
    if lower_name == "risk_score":
        return 0
    if lower_name == "state":
        return "open"
    if lower_name == "protocol":
        return "tcp"
    if lower_name.endswith("_json"):
        return "{}"
    if lower_name.endswith("_at") or lower_name in {"created_at", "updated_at"}:
        return "2026-07-01T00:00:00Z"
    if lower_name.startswith("is_"):
        return 1
    if lower_name in {"port", "hosts_up", "hosts_total"}:
        return 0
    if "count" in lower_name or lower_name.startswith("hosts_"):
        return 0
    if "int" in lower_type:
        return 0
    if "real" in lower_type or "float" in lower_type or "double" in lower_type:
        return 0.0
    return ""


def insert_dynamic(connection, table, values):
    table_info = connection.execute(f"PRAGMA table_info({table})").fetchall()
    columns = {row["name"] for row in table_info}
    insert_values = {
        key: value
        for key, value in values.items()
        if key in columns
    }

    for row in table_info:
        name = row["name"]
        if name in insert_values or row["pk"]:
            continue
        if row["notnull"] and row["dflt_value"] is None:
            insert_values[name] = default_value(name, row["type"])

    columns_sql = ", ".join(insert_values)
    placeholders = ", ".join("?" for _ in insert_values)
    connection.execute(
        f"INSERT INTO {table} ({columns_sql}) VALUES ({placeholders})",
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
            "scan_id": "scan-auto-001",
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
        insert_dynamic(
            connection,
            "snapshots",
            {
                "scan_id": "scan-auto-001",
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
            },
        )
        insert_dynamic(
            connection,
            "asset_observations",
            {
                "scan_id": "scan-auto-001",
                "asset_key": "asset-fixture-1",
                "ip_address": "192.168.1.10",
                "mac_address": "aa:bb:cc:dd:ee:ff",
                "hostname": "fixture-host",
                "vendor": "fixture",
                "device_type": "Web Server",
                "identity_class": "IP_MAC",
                "risk_score": 10,
                "risk_level": "LOW",
            },
        )
        insert_dynamic(
            connection,
            "service_observations",
            {
                "scan_id": "scan-auto-001",
                "asset_key": "asset-fixture-1",
                "protocol": "tcp",
                "port": 80,
                "state": "open",
                "service_name": "http",
                "product": "fixture-http",
                "version": "1.0",
            },
        )
        connection.commit()

        job = delta.create_trueaegis_job(
            connection,
            scan_id="scan-auto-001",
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
        assert result["validation_run_id"], result
        assert result["imported_observations"] == 1, result
        assert result["correlation_count"] == 1, result

        validation_run = connection.execute(
            "SELECT * FROM validation_runs WHERE validation_run_id = ?",
            (result["validation_run_id"],),
        ).fetchone()
        assert validation_run is not None, result

        observation_count = connection.execute(
            "SELECT COUNT(*) AS count FROM validation_observations WHERE validation_run_id = ?",
            (result["validation_run_id"],),
        ).fetchone()["count"]
        assert observation_count == 1, observation_count

        correlation_count = connection.execute(
            "SELECT COUNT(*) AS count FROM validation_correlations WHERE validation_run_id = ?",
            (result["validation_run_id"],),
        ).fetchone()["count"]
        assert correlation_count == 1, correlation_count
    finally:
        connection.close()

print("[PASS] v0.35 TrueAegis auto-import and correlation python checks passed")
PY

echo "[PASS] DeltaAegis v0.35 TrueAegis auto-import validation passed"
