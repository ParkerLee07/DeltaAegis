#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/DeltaAegis}" || {
  echo "[-] Could not enter DeltaAegis repo."
  exit 1
}

DB_PATH="/tmp/deltaaegis-v0.9-dashboard-investigation-controls.db"
EVENTS_PATH="/tmp/deltaaegis-v0.9-dashboard-investigation-controls-events.jsonl"
INGEST_LOG="/tmp/deltaaegis-v0.9-dashboard-investigation-controls-ingest.log"

rm -f "$DB_PATH" "$EVENTS_PATH" "$INGEST_LOG"

echo "[*] Running syntax check..."
python3 -m py_compile deltaaegis.py

echo "[*] Running live tests..."
pytest -q

echo "[*] Running persistent investigation validator..."
./tools/validate_v0_9_persistent_investigation_status.sh

echo "[*] Building temporary database from NetSniper runs..."
python3 deltaaegis.py \
  --db "$DB_PATH" \
  --runs-dir "$HOME/NetSniper/runs" \
  --events "$EVENTS_PATH" \
  ingest >"$INGEST_LOG"

tail -10 "$INGEST_LOG"

echo
echo "[*] Validating dashboard investigation controls over HTTP..."

python3 - "$DB_PATH" <<'PY'
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import deltaaegis as da

db_path = Path(sys.argv[1])
conn = da.connect(db_path)
assets = da.dashboard_assets_payload(conn, limit=200)

if not assets:
    raise SystemExit("[-] No assets available for dashboard control validation.")

asset = assets[0]
asset_key = asset.get("asset_key")
scope = asset.get("network_scope")

if not asset_key or not scope:
    raise SystemExit(f"[-] Could not select asset/scope: {asset}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

cmd = [
    sys.executable,
    "deltaaegis.py",
    "--db",
    str(db_path),
    "dashboard",
    "--host",
    "127.0.0.1",
    "--port",
    str(port),
    "--quiet",
]

proc = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
)

base = f"http://127.0.0.1:{port}"

try:
    for _ in range(60):
        try:
            with urllib.request.urlopen(f"{base}/healthz", timeout=1) as response:
                if response.read().decode("utf-8") == "ok":
                    break
        except Exception:
            time.sleep(0.25)
    else:
        output = proc.stdout.read() if proc.stdout else ""
        raise SystemExit(f"[-] Dashboard did not start.\n{output}")

    html = urllib.request.urlopen(f"{base}/", timeout=5).read().decode("utf-8")

    required_html = [
        "save-investigation-status",
        "bindInvestigationStatusForm",
        "/api/investigate-asset",
        "Status Source",
        "Inferred Status",
    ]

    missing_html = [item for item in required_html if item not in html]

    if missing_html:
        raise SystemExit(f"[-] Dashboard HTML missing controls: {missing_html}")

    reason = "v0.9 dashboard investigation controls validation"

    body = json.dumps(
        {
            "identifier": asset_key,
            "scope": scope,
            "status": "MONITORING",
            "reason": reason,
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        f"{base}/api/investigate-asset",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )

    with urllib.request.urlopen(request, timeout=5) as response:
        payload = json.loads(response.read().decode("utf-8"))

    if not payload.get("ok"):
        raise SystemExit(f"[-] POST did not return ok=true: {payload}")

    detail = payload.get("asset_detail") or {}
    investigation = detail.get("investigation") or {}

    if investigation.get("status") != "MONITORING":
        raise SystemExit(f"[-] Expected MONITORING, got {investigation.get('status')}")

    if investigation.get("status_source") != "persisted":
        raise SystemExit(
            f"[-] Expected persisted source, got {investigation.get('status_source')}"
        )

    persisted = investigation.get("persisted_status") or {}

    if persisted.get("reason") != reason:
        raise SystemExit(f"[-] Persisted reason mismatch: {persisted}")

    query = urllib.parse.urlencode(
        {
            "identifier": asset_key,
            "scope": scope,
        }
    )

    with urllib.request.urlopen(f"{base}/api/asset?{query}", timeout=5) as response:
        loaded_detail = json.loads(response.read().decode("utf-8"))

    loaded_investigation = (loaded_detail.get("investigation") or {})

    if loaded_investigation.get("status") != "MONITORING":
        raise SystemExit(
            "[-] Reloaded asset detail did not preserve persisted status: "
            f"{loaded_investigation}"
        )

    if loaded_investigation.get("status_source") != "persisted":
        raise SystemExit(
            "[-] Reloaded asset detail did not report persisted status source: "
            f"{loaded_investigation}"
        )

    print("[+] PASS: dashboard POST saved persisted investigation status.")
    print(f"[*] Asset: {asset_key}")
    print(f"[*] Scope: {scope}")
    print(f"[*] Status: {loaded_investigation.get('status')}")
    print(f"[*] Source: {loaded_investigation.get('status_source')}")

finally:
    proc.terminate()

    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
PY

echo
echo "[+] PASS: DeltaAegis v0.9 dashboard investigation controls validation succeeded."
