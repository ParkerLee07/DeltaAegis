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

grep -Fq '"scan.start": "ADMIN"' deltaaegis.py \
    || fail "missing ADMIN-only scan.start permission"

grep -Fq '"/api/netsniper/scan-start"' deltaaegis.py \
    || fail "missing /api/netsniper/scan-start route policy"

grep -Fq 'def dashboard_active_scan_job' deltaaegis.py \
    || fail "missing dashboard_active_scan_job helper"

grep -Fq 'def dashboard_netsniper_scan_start_payload' deltaaegis.py \
    || fail "missing dashboard_netsniper_scan_start_payload helper"

grep -Fq 'validate_private_cidr(target)' deltaaegis.py \
    || fail "scan-start helper does not validate private CIDR"

grep -Fq "status IN ('QUEUED', 'RUNNING')" deltaaegis.py \
    || fail "missing one-active-job guard"

grep -Fq 'NetSniper script not found' deltaaegis.py \
    || fail "missing NetSniper script existence check"

if grep -nE 'shell=True' deltaaegis.py; then
    fail "unsafe subprocess shell=True pattern found"
fi

python3 - <<'PY2'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")
checks = {
    "build_netsniper_headless_command": "def build_netsniper_headless_command",
    "dashboard_netsniper_scan_start_payload": "def dashboard_netsniper_scan_start_payload",
}

for name, marker in checks.items():
    start = text.find(marker)
    if start == -1:
        raise AssertionError(f"missing section: {name}")

    next_def = text.find("\ndef ", start + 1)
    section = text[start:] if next_def == -1 else text[start:next_def]

    if "os.system(" in section:
        raise AssertionError(f"os.system found in {name}")

    if "shell=True" in section:
        raise AssertionError(f"shell=True found in {name}")

print("[PASS] v0.29 guarded scan sections do not use shell execution")
PY2

python3 - <<'PY'
import tempfile
from pathlib import Path
import deltaaegis as da

with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "deltaaegis.db"
    fake_root = Path(tmpdir) / "NetSniper"
    fake_root.mkdir()
    fake_script = fake_root / "netsniper.sh"
    fake_script.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    fake_script.chmod(0o755)

    con = da.connect(db_path)

    try:
        da.validate_private_cidr("8.8.8.0/24")
    except da.DeltaAegisError:
        pass
    else:
        raise AssertionError("public CIDR was accepted")

    command = da.build_netsniper_headless_command(fake_script, "192.168.5.0/24")
    assert isinstance(command, list), command
    assert "--non-interactive" in command, command
    assert "--json-status" in command, command
    assert "192.168.5.0/24" in command, command

    job = da.create_scan_job(
        con,
        "192.168.5.0/24",
        fake_script,
        fake_root / "runs",
        auto_ingest=False,
    )
    con.commit()

    active = da.dashboard_active_scan_job(con)
    assert active is not None, active
    assert active["job_id"] == job["job_id"], (active, job)
    assert active["status"] == "QUEUED", active

print("[PASS] v0.29 scan-start foundation python checks passed")
PY

pass "DeltaAegis v0.29 scan-start foundation validation passed"
