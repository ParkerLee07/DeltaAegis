#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

fixture="examples/trueaegis-fixtures/basic-validation/validation_results.json"
if [[ ! -f "$fixture" ]]; then
    echo "[FAIL] Missing fixture: $fixture" >&2
    exit 1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

db="$tmpdir/deltaaegis-trueaegis.db"

python3 deltaaegis.py --db "$db" validation-ingest "$fixture" > "$tmpdir/ingest.out"
grep -Fq "Imported TrueAegis validation run:" "$tmpdir/ingest.out"
grep -Fq "Results: 5" "$tmpdir/ingest.out"
grep -Fq "CONFIRMED: 1" "$tmpdir/ingest.out"
grep -Fq "REACHABLE: 1" "$tmpdir/ingest.out"
grep -Fq "PROTECTED: 1" "$tmpdir/ingest.out"
grep -Fq "PROTOCOL_MISMATCH: 1" "$tmpdir/ingest.out"
grep -Fq "NOT_REACHABLE: 1" "$tmpdir/ingest.out"

python3 deltaaegis.py --db "$db" validations --limit 10 > "$tmpdir/list.out"
grep -Fq "HTTP_EXPOSED" "$tmpdir/list.out"
grep -Fq "SMB_EXPOSED" "$tmpdir/list.out"
grep -Fq "status=PROTECTED" "$tmpdir/list.out"

python3 deltaaegis.py --db "$db" validations --status CONFIRMED --limit 10 > "$tmpdir/confirmed.out"
grep -Fq "status=CONFIRMED" "$tmpdir/confirmed.out"

python3 - "$db" <<'PY_CHECK'
import json
import sqlite3
import sys
from pathlib import Path

db = Path(sys.argv[1])
connection = sqlite3.connect(db)
connection.row_factory = sqlite3.Row

run = connection.execute(
    "SELECT * FROM validation_runs LIMIT 1"
).fetchone()
assert run is not None, "missing validation_runs row"
assert run["result_count"] == 5, run["result_count"]
assert run["source_format"] == "trueaegis-validation-list-v1"

counts = json.loads(run["status_counts_json"])
expected_counts = {
    "CONFIRMED": 1,
    "REACHABLE": 1,
    "PROTECTED": 1,
    "PROTOCOL_MISMATCH": 1,
    "NOT_REACHABLE": 1,
}
assert counts == expected_counts, counts

rows = connection.execute(
    """
    SELECT finding_id, host, port, status, validated, safe, confidence,
           details_json, evidence_json, metadata_json, raw_json
    FROM validation_observations
    ORDER BY row_index ASC
    """
).fetchall()

assert len(rows) == 5, len(rows)

statuses = {row["status"] for row in rows}
assert statuses == set(expected_counts), statuses

protected = [row for row in rows if row["status"] == "PROTECTED"][0]
assert protected["finding_id"] == "SMB_EXPOSED"
assert protected["validated"] == 1
assert protected["safe"] == 1
assert protected["confidence"] == "HIGH"

for row in rows:
    assert row["host"], row
    assert row["finding_id"], row
    assert json.loads(row["details_json"]) is not None
    assert json.loads(row["evidence_json"]) is not None
    assert json.loads(row["metadata_json"]) is not None
    assert json.loads(row["raw_json"]) is not None

print("[PASS] v0.33 TrueAegis storage database checks passed")
PY_CHECK

# Re-ingest should be deterministic and should not duplicate observations.
python3 deltaaegis.py --db "$db" validation-ingest "$fixture" >/dev/null

python3 - "$db" <<'PY_IDEMPOTENT'
import sqlite3
import sys
from pathlib import Path

connection = sqlite3.connect(Path(sys.argv[1]))
run_count = connection.execute("SELECT COUNT(*) FROM validation_runs").fetchone()[0]
observation_count = connection.execute("SELECT COUNT(*) FROM validation_observations").fetchone()[0]
assert run_count == 1, run_count
assert observation_count == 5, observation_count
print("[PASS] v0.33 TrueAegis storage idempotency checks passed")
PY_IDEMPOTENT

echo "[PASS] DeltaAegis v0.33 TrueAegis validation storage checks passed"
