#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/DeltaAegis}" || {
  echo "[-] Could not enter DeltaAegis repo."
  exit 1
}

DB_PATH="/tmp/deltaaegis-v0.9-persistent-investigation.db"
EVENTS_PATH="/tmp/deltaaegis-v0.9-persistent-investigation-events.jsonl"
INGEST_LOG="/tmp/deltaaegis-v0.9-persistent-investigation-ingest.log"

rm -f "$DB_PATH" "$EVENTS_PATH" "$INGEST_LOG"

echo "[*] Running syntax check..."
python3 -m py_compile deltaaegis.py

echo "[*] Running live tests..."
pytest -q

echo "[*] Running existing v0.9 clickable investigation validator..."
./tools/validate_v0_9_clickable_investigation_rows.sh

echo "[*] Building temporary database from NetSniper runs..."
python3 deltaaegis.py \
  --db "$DB_PATH" \
  --runs-dir "$HOME/NetSniper/runs" \
  --events "$EVENTS_PATH" \
  ingest >"$INGEST_LOG"

tail -10 "$INGEST_LOG"

echo
echo "[*] Selecting asset for persistent investigation status..."
read -r ASSET_KEY SCOPE < <(
  python3 - "$DB_PATH" <<'PY'
import sys
from pathlib import Path

import deltaaegis as da

conn = da.connect(Path(sys.argv[1]))
assets = da.dashboard_assets_payload(conn, limit=200)

if not assets:
    raise SystemExit("[-] No assets available.")

asset = assets[0]
print(asset.get("asset_key"), asset.get("network_scope"))
PY
)

if [ -z "${ASSET_KEY:-}" ] || [ -z "${SCOPE:-}" ]; then
  echo "[-] Could not select asset/scope."
  exit 1
fi

echo "[*] Selected asset: $ASSET_KEY"
echo "[*] Selected scope: $SCOPE"

echo
echo "[*] Setting persisted investigation status..."
python3 deltaaegis.py \
  --db "$DB_PATH" \
  investigate-asset "$ASSET_KEY" \
  --scope "$SCOPE" \
  --status REVIEWING \
  --reason "v0.9 persistent investigation validation"

echo
echo "[*] Validating persisted status in asset detail payload..."

python3 - "$DB_PATH" "$ASSET_KEY" "$SCOPE" <<'PY'
import sys
from pathlib import Path

import deltaaegis as da

db_path = Path(sys.argv[1])
asset_key = sys.argv[2]
scope = sys.argv[3]

conn = da.connect(db_path)
detail = da.dashboard_asset_detail_payload(conn, asset_key, scope=scope)

if not detail.get("found"):
    raise SystemExit(f"[-] Asset detail lookup failed: {detail}")

investigation = detail.get("investigation") or {}

if investigation.get("status") != "REVIEWING":
    raise SystemExit(f"[-] Expected REVIEWING, got {investigation.get('status')}")

if investigation.get("status_source") != "persisted":
    raise SystemExit(
        f"[-] Expected status_source=persisted, got {investigation.get('status_source')}"
    )

if not investigation.get("inferred_status"):
    raise SystemExit("[-] Expected inferred_status to remain available.")

persisted = investigation.get("persisted_status") or {}

expected_reason = "v0.9 persistent investigation validation"

if persisted.get("status") != "REVIEWING":
    raise SystemExit(f"[-] Persisted status mismatch: {persisted}")

if persisted.get("reason") != expected_reason:
    raise SystemExit(f"[-] Persisted reason mismatch: {persisted}")

history = conn.execute(
    """
    SELECT status, reason
    FROM asset_investigation_history
    WHERE asset_key = ?
      AND network_scope = ?
    ORDER BY investigation_id DESC
    LIMIT 1
    """,
    (asset_key, scope),
).fetchone()

if history is None:
    raise SystemExit("[-] No investigation history row was written.")

if history["status"] != "REVIEWING":
    raise SystemExit(f"[-] History status mismatch: {history['status']}")

if history["reason"] != expected_reason:
    raise SystemExit(f"[-] History reason mismatch: {history['reason']}")

html = da.dashboard_index_html()

required_html = [
    "Investigation Summary",
    "Status Source",
    "Inferred Status",
    "status_source",
    "inferred_status",
]

missing_html = [item for item in required_html if item not in html]

if missing_html:
    raise SystemExit(f"[-] Dashboard HTML missing persisted-status marker(s): {missing_html}")

print("[+] PASS: persisted investigation status overrides inferred status.")
print(f"[*] Asset: {asset_key}")
print(f"[*] Scope: {scope}")
print(f"[*] Status: {investigation.get('status')}")
print(f"[*] Inferred: {investigation.get('inferred_status')}")
print(f"[*] Source: {investigation.get('status_source')}")
PY

echo
echo "[+] PASS: DeltaAegis v0.9 persistent investigation status validation succeeded."
