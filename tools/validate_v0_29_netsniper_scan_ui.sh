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

grep -Fq 'id="netsniper-scan-start-form"' deltaaegis.py \
    || fail "NetSniper page missing scan-start form"

grep -Fq 'id="netsniper-scan-target"' deltaaegis.py \
    || fail "NetSniper page missing target CIDR input"

grep -Fq 'id="netsniper-scan-start"' deltaaegis.py \
    || fail "NetSniper page missing scan-start button"

grep -Fq 'id="netsniper-scan-start-result"' deltaaegis.py \
    || fail "NetSniper page missing scan-start result output"

grep -Fq 'id="netsniper-scan-jobs-body"' deltaaegis.py \
    || fail "NetSniper page missing scan jobs table body"

grep -Fq 'function startNetSniperScan' deltaaegis.py \
    || fail "NetSniper page missing startNetSniperScan JS function"

grep -Fq 'fetch("/api/netsniper/scan-start"' deltaaegis.py \
    || fail "NetSniper page does not POST to /api/netsniper/scan-start"

grep -Fq 'fetch("/api/scan-jobs?limit=10"' deltaaegis.py \
    || fail "NetSniper page does not poll scan jobs"

grep -Fq 'ADMIN role required to start NetSniper scans' deltaaegis.py \
    || fail "NetSniper page does not communicate ADMIN-only launch boundary"

grep -Fq 'does not run arbitrary shell commands' deltaaegis.py \
    || fail "NetSniper page no longer documents no-raw-shell boundary"

if grep -nE 'shell=True' deltaaegis.py; then
    fail "unsafe subprocess shell=True pattern found"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

db="$tmpdir/deltaaegis.db"
events="$tmpdir/events.jsonl"
fake_root="$tmpdir/NetSniper"
mkdir -p "$fake_root/runs"

cat > "$fake_root/netsniper.sh" <<'NS'
#!/usr/bin/env bash
set -euo pipefail
run_dir="$PWD/runs/ui-validator-run"
mkdir -p "$run_dir"
cat > "$run_dir/manifest.json" <<'JSON'
{
  "scan_id": "ui-validator-run",
  "status": "COMPLETE",
  "scanner_version": "validator"
}
JSON
printf '{"status":"COMPLETE","return_code":0,"run_dir":"%s","manifest_path":"%s"}\n' "$run_dir" "$run_dir/manifest.json"
exit 0
NS

chmod +x "$fake_root/netsniper.sh"

port="18129"
dashboard_log="$tmpdir/dashboard.log"

DELTAAEGIS_NETSNIPER_ROOT="$fake_root" \
python3 deltaaegis.py \
    --db "$db" \
    --events "$events" \
    dashboard \
    --host 127.0.0.1 \
    --port "$port" \
    --no-require-login \
    >"$dashboard_log" 2>&1 &

pid="$!"
trap 'kill "$pid" 2>/dev/null || true; rm -rf "$tmpdir"' EXIT

python3 - "$port" <<'PY'
import json
import sys
import time
import urllib.error
import urllib.request

port = sys.argv[1]
base = f"http://127.0.0.1:{port}"

deadline = time.time() + 8
while time.time() < deadline:
    try:
        with urllib.request.urlopen(base + "/netsniper", timeout=1) as response:
            html = response.read().decode("utf-8")
            assert 'id="netsniper-scan-start-form"' in html, html[:500]
            assert 'id="netsniper-scan-target"' in html, html[:500]
            assert 'fetch("/api/netsniper/scan-start"' in html, html[:500]
            break
    except Exception:
        time.sleep(0.2)
else:
    raise AssertionError("dashboard /netsniper page did not become ready")

def post_json(path, payload):
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        base + path,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=3) as response:
        return json.loads(response.read().decode("utf-8"))

result = post_json("/api/netsniper/scan-start", {"target": "192.168.5.0/24"})
assert result.get("ok") is True, result
assert result.get("job_id"), result
assert result.get("status") == "QUEUED", result

job_id = result["job_id"]

deadline = time.time() + 8
while time.time() < deadline:
    with urllib.request.urlopen(base + "/api/scan-jobs?limit=10", timeout=2) as response:
        payload = json.loads(response.read().decode("utf-8"))

    if isinstance(payload, list):
        jobs = payload
    else:
        jobs = payload.get("jobs") or payload.get("scan_jobs") or payload.get("items") or []
    matching = [job for job in jobs if job.get("job_id") == job_id]

    if matching and matching[0].get("status") in {"COMPLETED", "FAILED"}:
        assert matching[0]["status"] == "COMPLETED", matching[0]
        break

    time.sleep(0.2)
else:
    raise AssertionError("dashboard scan-start job did not complete through HTTP route")

print("[PASS] v0.29 NetSniper scan UI HTTP checks passed")
PY

pass "DeltaAegis v0.29 NetSniper scan UI validation passed"
