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

grep -Fq 'id="netsniper-scan-profile"' deltaaegis.py \
    || fail "dashboard missing scan profile selector"

grep -Fq 'body: JSON.stringify({target: target, scan_profile: scanProfile})' deltaaegis.py \
    || fail "dashboard JS does not POST scan_profile"

grep -Fq 'const scanProfile = profileInput ? profileInput.value.trim() : "balanced";' deltaaegis.py \
    || fail "dashboard JS does not define scanProfile before POST"

grep -Fq 'payload.get("scan_profile")' deltaaegis.py \
    || fail "dashboard helper does not read scan_profile"

grep -Fq 'scan_profile=safe_profile' deltaaegis.py \
    || fail "dashboard helper does not pass scan_profile into job/thread"

grep -Fq '"scan_profile": scan_profile' deltaaegis.py \
    || fail "dashboard scan thread kwargs do not carry scan_profile"

grep -Fq 'execute_scan_job(' deltaaegis.py \
    || fail "missing execute_scan_job call"

grep -Fq 'scan_profile=scan_profile' deltaaegis.py \
    || fail "dashboard worker does not pass scan_profile into execute_scan_job"

grep -Fq '<th>Profile</th>' deltaaegis.py \
    || fail "scan jobs table missing Profile header"

grep -Fq '${escapeHtml(job.scan_profile || "balanced")}' deltaaegis.py \
    || fail "scan jobs table does not render job.scan_profile"

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
printf '%s\n' "$@" > "$PWD/args.txt"
run_dir="$PWD/runs/profile-validator-run"
mkdir -p "$run_dir"
cat > "$run_dir/manifest.json" <<'JSON'
{
  "scan_id": "profile-validator-run",
  "status": "COMPLETE",
  "scanner_version": "validator",
  "schema_version": "netsniper-run-v2",
  "target": "192.168.5.0/24",
  "files": {}
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

        result = da.dashboard_netsniper_scan_start_payload(
            connection,
            {"target": "192.168.5.0/24", "scan_profile": "accurate"},
            db_path,
            events_path,
        )

        assert result["ok"] is True, result
        assert result["scan_profile"] == "accurate", result
        assert result["job"]["scan_profile"] == "accurate", result

        job_id = result["job_id"]
        deadline = time.time() + 8
        final_row = None

        while time.time() < deadline:
            poll = da.connect(db_path)
            poll.row_factory = sqlite3.Row
            row = poll.execute(
                """
                SELECT job_id, status, exit_code, scan_profile, stdout_log, stderr_log, message
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
        assert final_row["scan_profile"] == "accurate", dict(final_row)

        args_text = (fake_root / "args.txt").read_text(encoding="utf-8")
        assert "--profile" in args_text, args_text
        assert "accurate" in args_text, args_text

    finally:
        if old_root is None:
            os.environ.pop("DELTAAEGIS_NETSNIPER_ROOT", None)
        else:
            os.environ["DELTAAEGIS_NETSNIPER_ROOT"] = old_root

print("[PASS] v0.30 dashboard profile-aware scan-start python checks passed")
PY

pass "DeltaAegis v0.30 dashboard scan profile UI validation passed"
