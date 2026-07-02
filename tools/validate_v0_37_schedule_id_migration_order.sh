#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[v0.37 hotfix] syntax check"
python3 -m py_compile deltaaegis.py

echo "[v0.37 hotfix] static migration-order check"
python3 - <<'PY'
from pathlib import Path
import re

text = Path("deltaaegis.py").read_text(encoding="utf-8")

match = re.search(r'(SCHEMA_SQL\s*=\s*""")(.*?)("""\s*\n)', text, flags=re.S)
if not match:
    raise SystemExit("could not locate SCHEMA_SQL")

schema_block = match.group(2)

if "idx_scan_jobs_schedule_id" in schema_block:
    raise SystemExit("schedule_id index still exists inside SCHEMA_SQL and can break older DBs")

required = [
    'ensure_column(connection, "scan_jobs", "schedule_id"',
    'CREATE INDEX IF NOT EXISTS idx_scan_jobs_schedule_id',
    'ON scan_jobs(schedule_id)',
]

for needle in required:
    if needle not in text:
        raise SystemExit(f"missing migration-time schedule_id marker: {needle}")

print("static migration-order check passed")
PY

echo "[v0.37 hotfix] legacy-db migration smoke test"
python3 - <<'PY'
from pathlib import Path
import re
import sqlite3
import tempfile
import deltaaegis

source = Path("deltaaegis.py").read_text(encoding="utf-8")

schema_match = re.search(r'SCHEMA_SQL\s*=\s*"""(.*?)"""', source, flags=re.S)
if not schema_match:
    raise SystemExit("could not locate SCHEMA_SQL")

schema = schema_match.group(1)

table_match = re.search(
    r'CREATE TABLE IF NOT EXISTS scan_jobs\s*\((.*?)\);',
    schema,
    flags=re.S,
)

if not table_match:
    raise SystemExit("could not locate scan_jobs table definition")

body = table_match.group(1)
legacy_lines = []

for line in body.splitlines():
    if "schedule_id" in line:
        continue
    legacy_lines.append(line)

legacy_body = "\n".join(legacy_lines).rstrip()

# Clean up a trailing comma if schedule_id was the last column.
legacy_body = re.sub(r',\s*$', '', legacy_body, flags=re.S)

legacy_create = f"CREATE TABLE scan_jobs ({legacy_body});"

with tempfile.TemporaryDirectory() as tmp:
    db_path = Path(tmp) / "legacy-scan-jobs.db"

    conn = sqlite3.connect(db_path)
    conn.execute(legacy_create)
    conn.commit()
    conn.close()

    migrated = deltaaegis.connect(db_path)

    columns = [row[1] for row in migrated.execute("PRAGMA table_info(scan_jobs)").fetchall()]
    if "schedule_id" not in columns:
        raise SystemExit("scan_jobs.schedule_id was not added during legacy migration")

    indexes = [row[1] for row in migrated.execute("PRAGMA index_list(scan_jobs)").fetchall()]
    if "idx_scan_jobs_schedule_id" not in indexes:
        raise SystemExit("idx_scan_jobs_schedule_id was not created after legacy migration")

    migrated.close()

print("legacy-db migration smoke test passed")
PY

echo "[v0.37 hotfix] PASS"
