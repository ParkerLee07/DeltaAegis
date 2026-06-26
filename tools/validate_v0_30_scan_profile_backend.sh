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

grep -Fq 'ALLOWED_NETSNIPER_SCAN_PROFILES = {"quick", "balanced", "accurate"}' deltaaegis.py \
    || fail "missing v0.30 allowed NetSniper profile set"

grep -Fq 'def validate_netsniper_scan_profile' deltaaegis.py \
    || fail "missing NetSniper scan profile validator"

grep -Fq '"scan_jobs", "scan_profile"' deltaaegis.py \
    || fail "missing scan_jobs.scan_profile migration"

grep -Fq 'scan_profile TEXT NOT NULL DEFAULT' deltaaegis.py \
    || fail "missing scan_jobs.scan_profile schema column"

grep -Fq '"--profile",' deltaaegis.py \
    || fail "NetSniper command builder does not include --profile"

grep -Fq 'p.add_argument("--profile", choices=["quick", "balanced", "accurate"], default="balanced"' deltaaegis.py \
    || fail "scan-start CLI does not expose --profile"

grep -Fq 'profile={item.get' deltaaegis.py \
    || fail "scan-jobs CLI output does not show profile"

if grep -nE 'shell=True' deltaaegis.py; then
    fail "unsafe subprocess shell=True pattern found"
fi

python3 - <<'PY'
import tempfile
from pathlib import Path

import deltaaegis as da

with tempfile.TemporaryDirectory() as tmpdir:
    tmp = Path(tmpdir)
    db_path = tmp / "deltaaegis.db"
    fake_root = tmp / "NetSniper"
    fake_root.mkdir()
    fake_script = fake_root / "netsniper.sh"
    fake_script.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    fake_script.chmod(0o755)

    con = da.connect(db_path)

    assert da.validate_netsniper_scan_profile(None) == "balanced"
    assert da.validate_netsniper_scan_profile("") == "balanced"
    assert da.validate_netsniper_scan_profile("BALANCED") == "balanced"
    assert da.validate_netsniper_scan_profile("accurate") == "accurate"
    assert da.validate_netsniper_scan_profile("quick") == "quick"

    for bad in ("deep", "fake"):
        try:
            da.validate_netsniper_scan_profile(bad)
        except da.DeltaAegisError:
            pass
        else:
            raise AssertionError(f"invalid profile accepted: {bad}")

    command = da.build_netsniper_headless_command(fake_script, "192.168.5.0/24", "accurate")
    assert command == [
        str(fake_script),
        "--non-interactive",
        "--target",
        "192.168.5.0/24",
        "--greenbone",
        "no",
        "--json-status",
        "--profile",
        "accurate",
    ], command

    job = da.create_scan_job(
        con,
        "192.168.5.0/24",
        fake_script,
        fake_root / "runs",
        auto_ingest=False,
        scan_profile="accurate",
    )
    con.commit()
    assert job["scan_profile"] == "accurate", job

    row = con.execute(
        "SELECT job_id, scan_profile FROM scan_jobs WHERE job_id = ?",
        (job["job_id"],),
    ).fetchone()
    assert row["scan_profile"] == "accurate", dict(row)

    rows = da.query_scan_jobs(con, limit=5)
    payload = da.scan_job_to_dict(rows[0])
    assert payload["scan_profile"] == "accurate", payload

print("[PASS] v0.30 scan profile backend python checks passed")
PY

pass "DeltaAegis v0.30 scan profile backend validation passed"
