#!/usr/bin/env bash
set -euo pipefail

DELTA_DIR="${DELTA_DIR:-$HOME/DeltaAegis}"
NETSNIPER_DIR="${NETSNIPER_DIR:-$HOME/NetSniper}"

DB_PATH="/tmp/deltaaegis-v0.7-final-verifier.db"
EVENTS_PATH="/tmp/deltaaegis-v0.7-final-verifier-events.jsonl"

cd "$DELTA_DIR" || {
  echo "[-] Could not enter DeltaAegis repo: $DELTA_DIR"
  exit 1
}

rm -f "$DB_PATH" "$EVENTS_PATH"

echo "[*] DeltaAegis v0.7 final intelligence pipeline verifier"
echo

echo "[*] Checking NetSniper v1.4 analysis validator..."
if [ -x "$NETSNIPER_DIR/tools/validate_v1_4_analysis.sh" ]; then
  (
    cd "$NETSNIPER_DIR"
    ./tools/validate_v1_4_analysis.sh
  )
else
  echo "[-] Missing NetSniper analysis validator."
  echo "    Expected: $NETSNIPER_DIR/tools/validate_v1_4_analysis.sh"
  exit 1
fi

echo
echo "[*] Checking NetSniper v1.4 bundle validator..."
if [ -x "$NETSNIPER_DIR/tools/validate_v1_4_bundle.sh" ]; then
  (
    cd "$NETSNIPER_DIR"
    ./tools/validate_v1_4_bundle.sh
  )
else
  echo "[-] Missing NetSniper bundle validator."
  echo "    Expected: $NETSNIPER_DIR/tools/validate_v1_4_bundle.sh"
  exit 1
fi

echo
echo "[*] Checking DeltaAegis syntax and live tests..."
cd "$DELTA_DIR"
python3 -m py_compile deltaaegis.py
pytest -q

echo
echo "[*] Checking DeltaAegis v0.7 classification storage..."
./tools/validate_v0_7_classification_storage.sh "$DB_PATH" "$NETSNIPER_DIR/runs" "$EVENTS_PATH"

echo
echo "[*] Checking DeltaAegis v0.7 classification event engine..."
./tools/validate_v0_7_classification_events.sh

echo
echo "[*] Checking DeltaAegis v0.7 baseline-noise handling..."
./tools/validate_v0_7_classification_baseline_noise_fix.sh

echo
echo "[*] Final database summary:"
python3 - "$DB_PATH" <<'PY'
import sqlite3
import sys

db_path = sys.argv[1]
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

snapshots = conn.execute("SELECT COUNT(*) AS count FROM snapshots").fetchone()["count"]
assets = conn.execute("SELECT COUNT(*) AS count FROM asset_observations").fetchone()["count"]
events = conn.execute("SELECT COUNT(*) AS count FROM delta_events").fetchone()["count"]

classification = conn.execute(
    """
    SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN classification_decision = 'classified' THEN 1 ELSE 0 END) AS classified,
        SUM(CASE WHEN classification_decision = 'possible' THEN 1 ELSE 0 END) AS possible,
        SUM(CASE WHEN classification_decision = 'unknown' THEN 1 ELSE 0 END) AS unknown,
        SUM(CASE WHEN classification_evidence_json IS NOT NULL AND classification_evidence_json != '[]' THEN 1 ELSE 0 END) AS with_evidence
    FROM asset_observations
    """
).fetchone()

print(f"    snapshots: {snapshots}")
print(f"    asset observations: {assets}")
print(f"    delta events: {events}")
print(f"    classification records: {classification['total']}")
print(f"    classified: {classification['classified']}")
print(f"    possible: {classification['possible']}")
print(f"    unknown: {classification['unknown']}")
print(f"    with evidence: {classification['with_evidence']}")
PY

echo
echo "[+] PASS: NetSniper v1.4 → DeltaAegis v0.7 intelligence pipeline is healthy."
