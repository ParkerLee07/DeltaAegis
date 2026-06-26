#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

grep -Fq 'import threading' deltaaegis.py \
    || fail "missing threading import"

grep -Fq 'def dashboard_netsniper_scan_worker' deltaaegis.py \
    || fail "missing dashboard scan worker"

grep -Fq 'def dashboard_start_scan_job_thread' deltaaegis.py \
    || fail "missing scan thread starter"

grep -Fq 'threading.Thread(' deltaaegis.py \
    || fail "scan worker is not launched through threading.Thread"

grep -Fq 'daemon=True' deltaaegis.py \
    || fail "scan worker thread is not daemonized"

grep -Fq 'require_permission("scan.start")' deltaaegis.py \
    || fail "dashboard scan-start route is not ADMIN-gated"

grep -Fq 'netsniper_scan_start_failed' deltaaegis.py \
    || fail "dashboard scan-start route does not return scan-start failure JSON"

grep -Fq 'dashboard_netsniper_scan_start_payload(' deltaaegis.py \
    || fail "dashboard POST route does not call scan-start payload helper"

if grep -nE 'shell=True' deltaaegis.py; then
    fail "unsafe subprocess shell=True pattern found"
fi

python3 - <<'PY'
import os
import sqlite3
import tempfile
import time
from pathlib import Path

import deltaaegis as da

with tempfile.TemporaryDirectory() as tmpdir:
    tmp = Path(tmpdir)
    db_path = tmp / "deltaaegis.db"
    events_path = tmp / "events.jsonl"
    fake_root = tmp / "NetSniper"
    fake_root.mkdir()

    fake_script = fake_root / "netsniper.sh"
    fake_script.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
run_dir="$PWD/runs/validator-run"
mkdir -p "$run_dir"
cat > "$run_dir/manifest.json" <<'JSON'
{
  "scan_id": "validator-run",
  "status": "COMPLETE",
  "scanner_version": "validator"
}
JSON
printf '{"status":"COMPLETE","return_code":0,"run_dir":"%s","manifest_path":"%s"}\\n' "$run_dir" "$run_dir/manifest.json"
exit 0
""",
        encoding="utf-8",
    )
    fake_script.chmod(0o755)

    old_root = os.environ.get("DELTAAEGIS_NETSNIPER_ROOT")
    os.environ["DELTAAEGIS_NETSNIPER_ROOT"] = str(fake_root)

    try:
        connection = da.connect(db_path)

        try:
            da.dashboard_netsniper_scan_start_payload(
                connection,
                {"target": "8.8.8.0/24"},
                db_path,
                events_path,
            )
        except da.DeltaAegisError:
            pass
        else:
            raise AssertionError("public CIDR was accepted by dashboard scan-start helper")

        result = da.dashboard_netsniper_scan_start_payload(
            connection,
            {"target": "192.168.5.0/24"},
            db_path,
            events_path,
        )

        assert result["ok"] is True, result
        assert result["status"] == "QUEUED", result
        assert result["target"] == "192.168.5.0/24", result
        assert "background worker" in result["message"], result

        job_id = result["job_id"]

        deadline = time.time() + 8
        final_row = None

        while time.time() < deadline:
            poll = da.connect(db_path)
            poll.row_factory = sqlite3.Row
            row = poll.execute(
                """
                SELECT job_id, status, exit_code, stdout_log, stderr_log, message
                FROM scan_jobs
                WHERE job_id = ?
                """,
                (job_id,),
            ).fetchone()
            poll.close()

            if row and row["status"] in {"COMPLETED", "FAILED"}:
                final_row = row
                break

            time.sleep(0.2)

        assert final_row is not None, "scan job did not finish"
        assert final_row["status"] == "COMPLETED", dict(final_row)
        assert final_row["exit_code"] == 0, dict(final_row)
        assert final_row["stdout_log"], dict(final_row)
        assert Path(final_row["stdout_log"]).is_file(), dict(final_row)

    finally:
        if old_root is None:
            os.environ.pop("DELTAAEGIS_NETSNIPER_ROOT", None)
        else:
            os.environ["DELTAAEGIS_NETSNIPER_ROOT"] = old_root

print("[PASS] v0.29 dashboard scan-start background execution python checks passed")
PY

pass "DeltaAegis v0.29 dashboard scan-start background validation passed"
