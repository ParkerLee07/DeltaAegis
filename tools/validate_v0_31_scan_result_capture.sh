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

grep -Fq 'decoder.raw_decode' deltaaegis.py \
    || fail "NetSniper stdout parser does not parse pretty JSON"

grep -Fq 'def find_completed_netsniper_manifest_for_scan(' deltaaegis.py \
    || fail "missing completed-manifest fallback helper"

grep -Fq 'except KeyboardInterrupt as exc:' deltaaegis.py \
    || fail "scan wrapper does not persist KeyboardInterrupt failures"

grep -Fq 'exit_code=130' deltaaegis.py \
    || fail "KeyboardInterrupt failure does not use exit code 130"

python3 - <<'DELTA_31_7_PYTEST'
from pathlib import Path
import importlib.util
import json
import os
import sys
import tempfile
import textwrap

spec = importlib.util.spec_from_file_location("deltaaegis", "deltaaegis.py")
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = module
spec.loader.exec_module(module)

pretty_stdout = """
noise before
[+] Manifest: /tmp/example/runs/20260629-000000/manifest.json
{
  "status": "completed",
  "target": "192.168.56.0/30",
  "return_code": 0,
  "run_dir": "/tmp/example/runs/20260629-000000",
  "manifest_path": "/tmp/example/runs/20260629-000000/manifest.json"
}
"""

parsed = module.extract_netsniper_status_json(pretty_stdout)
assert parsed["run_dir"] == "/tmp/example/runs/20260629-000000"
assert parsed["manifest_path"].endswith("manifest.json")
assert parsed["return_code"] == 0

with tempfile.TemporaryDirectory() as tmp:
    tmp_path = Path(tmp)
    fake_root = tmp_path / "NetSniper"
    runs_dir = fake_root / "runs"
    logs_dir = tmp_path / "logs"
    events_path = tmp_path / "events.jsonl"
    db_path = tmp_path / "deltaaegis.db"

    fake_root.mkdir()
    runs_dir.mkdir()

    fake_script = fake_root / "netsniper.sh"
    fake_script.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            from pathlib import Path
            import json
            import time

            run_id = time.strftime("%Y%m%d-%H%M%S")
            run_dir = Path.cwd() / "runs" / run_id
            run_dir.mkdir(parents=True, exist_ok=True)

            manifest = {
                "schema_version": "netsniper-run-v2",
                "status": "COMPLETE",
                "scan_id": run_id,
                "scanner_version": "v1.9.0-fake",
                "target": "192.168.56.0/30",
                "scan_profile": "FAST_MONITORED_TCP",
                "scan_profile_requested": "quick",
                "scan_profile_effective": "quick"
            }

            (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            print("NetSniper completed without machine-readable final JSON")
            """
        ),
        encoding="utf-8",
    )
    fake_script.chmod(0o755)

    connection = module.connect(db_path)

    job = module.create_scan_job(
        connection,
        "192.168.56.0/30",
        fake_script,
        runs_dir,
        auto_ingest=False,
        scan_profile="quick",
    )
    connection.commit()

    result = module.execute_scan_job(
        connection,
        job["job_id"],
        "192.168.56.0/30",
        fake_script,
        runs_dir,
        logs_dir,
        events_path,
        auto_ingest=False,
        scan_profile="quick",
    )

    assert result["status"] == "COMPLETED"
    assert result["scan_profile"] == "quick"
    assert result["bundle_path"]
    assert result["status_json"]["run_dir"] == result["bundle_path"]
    assert result["status_json"]["manifest_path"].endswith("manifest.json")
    assert "bundle=" in result["message"]

    interrupted_job = module.create_scan_job(
        connection,
        "192.168.56.0/30",
        fake_script,
        runs_dir,
        auto_ingest=False,
        scan_profile="quick",
    )
    connection.commit()

    real_run = module.subprocess.run

    def fake_interrupt(*args, **kwargs):
        raise KeyboardInterrupt()

    module.subprocess.run = fake_interrupt

    try:
        try:
            module.execute_scan_job(
                connection,
                interrupted_job["job_id"],
                "192.168.56.0/30",
                fake_script,
                runs_dir,
                logs_dir,
                events_path,
                auto_ingest=False,
                scan_profile="quick",
            )
        except module.DeltaAegisError as exc:
            assert "interrupted" in str(exc)
        else:
            raise AssertionError("KeyboardInterrupt was not converted to DeltaAegisError")
    finally:
        module.subprocess.run = real_run

    row = connection.execute(
        "SELECT * FROM scan_jobs WHERE job_id = ?",
        (interrupted_job["job_id"],),
    ).fetchone()
    failed = module.scan_job_to_dict(row)
    assert failed["status"] == "FAILED"
    assert failed["exit_code"] == 130
    assert "interrupted" in failed["message"]

print("[PASS] v0.31 scan result capture python checks passed")
DELTA_31_7_PYTEST

ok "DeltaAegis v0.31 scan result capture validation passed"
