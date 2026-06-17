#!/usr/bin/env bash
set -euo pipefail

DB_PATH="${1:-/tmp/deltaaegis-v0.7-classification-storage-test.db}"
RUNS_DIR="${2:-$HOME/NetSniper/runs}"
EVENTS_PATH="${3:-/tmp/deltaaegis-v0.7-classification-storage-events.jsonl}"

cd "${REPO_DIR:-$HOME/DeltaAegis}" || {
  echo "[-] Could not enter DeltaAegis repo."
  exit 1
}

rm -f "$DB_PATH" "$EVENTS_PATH"

echo "[*] Ingesting NetSniper runs into temporary DeltaAegis DB..."
echo "    DB:     $DB_PATH"
echo "    Runs:   $RUNS_DIR"
echo "    Events: $EVENTS_PATH"

python3 deltaaegis.py --db "$DB_PATH" --runs-dir "$RUNS_DIR" --events "$EVENTS_PATH" ingest

echo
echo "[*] Validating v0.7 classification columns and stored values..."

python3 - "$DB_PATH" <<'PY'
import sqlite3
import sys

db_path = sys.argv[1]
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

required_columns = {
    "device_type_confidence",
    "classification_type",
    "classification_primary_type",
    "classification_confidence",
    "classification_confidence_label",
    "classification_decision",
    "classification_method",
    "classification_json",
    "classification_evidence_json",
    "classification_contradictions_json",
    "classification_candidates_json",
}

columns = {row[1] for row in conn.execute("PRAGMA table_info(asset_observations)")}
missing = sorted(required_columns - columns)

if missing:
    print("[-] Missing columns:")
    for item in missing:
        print(f"    {item}")
    sys.exit(1)

summary = conn.execute(
    """
    SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN classification_decision = 'classified' THEN 1 ELSE 0 END) AS classified,
        SUM(CASE WHEN classification_decision = 'possible' THEN 1 ELSE 0 END) AS possible,
        SUM(CASE WHEN classification_decision = 'unknown' THEN 1 ELSE 0 END) AS unknown,
        SUM(CASE WHEN classification_type IS NOT NULL AND classification_type != '' THEN 1 ELSE 0 END) AS with_type,
        SUM(CASE WHEN classification_evidence_json IS NOT NULL AND classification_evidence_json != '[]' THEN 1 ELSE 0 END) AS with_evidence
    FROM asset_observations
    """
).fetchone()

print("[*] Storage summary:")
for key in summary.keys():
    print(f"    {key}: {summary[key]}")

if int(summary["total"] or 0) == 0:
    print("[-] No asset observations were stored.")
    sys.exit(1)

if int(summary["with_type"] or 0) == 0:
    print("[-] No classification_type values were stored.")
    sys.exit(1)

rows = conn.execute(
    """
    SELECT
        scan_id,
        asset_key,
        ip_address,
        device_type,
        device_type_confidence,
        classification_decision,
        classification_type,
        classification_confidence,
        classification_evidence_json
    FROM asset_observations
    WHERE classification_type IS NOT NULL
    ORDER BY scan_id DESC, classification_confidence DESC, ip_address
    LIMIT 20
    """
).fetchall()

print()
print("[*] Preview:")
for row in rows:
    print(
        f"{row['scan_id']}  {row['ip_address']:<15} "
        f"{str(row['device_type']):<42} "
        f"{str(row['device_type_confidence']):>3}  "
        f"{str(row['classification_decision']):<10} "
        f"{str(row['classification_type']):<42} "
        f"{str(row['classification_confidence']):>3}"
    )

print()
print("[+] PASS: DeltaAegis stored NetSniper v1.4 classification intelligence.")
PY
