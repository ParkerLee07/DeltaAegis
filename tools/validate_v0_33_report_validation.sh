#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

fixture="examples/trueaegis-fixtures/basic-validation/validation_results.json"
if [[ ! -f "$fixture" ]]; then
    echo "[FAIL] Missing fixture: $fixture" >&2
    exit 1
fi

grep -Fq "def append_report_trueaegis_validation_section" deltaaegis.py
grep -Fq "## TrueAegis Validation Evidence" deltaaegis.py
grep -Fq "validation-ingest /path/to/validation_results.json" deltaaegis.py
grep -Fq "TrueAegis validation observations" deltaaegis.py

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

db="$tmpdir/deltaaegis-v033-report.db"
report="$tmpdir/report.md"

python3 deltaaegis.py --db "$db" validation-ingest "$fixture" >/dev/null
python3 deltaaegis.py --db "$db" report --output "$report" >/dev/null

grep -Fq "## TrueAegis Validation Evidence" "$report"
grep -Fq "Validation runs" "$report"
grep -Fq "Observations" "$report"
grep -Fq "### Validation Status Counts" "$report"
grep -Fq "CONFIRMED" "$report"
grep -Fq "PROTECTED" "$report"
grep -Fq "SMB_EXPOSED" "$report"
grep -Fq "v0.33" "$report"

python3 - "$report" <<'PY_CHECK'
from pathlib import Path
import sys

report = Path(sys.argv[1]).read_text(encoding="utf-8")
required = [
    "TrueAegis validation observations",
    "TrueAegis confirmed/protected observations",
    "This section summarizes imported TrueAegis validation output.",
    "Recent Validation Observations",
]
missing = [item for item in required if item not in report]
if missing:
    raise SystemExit(f"missing report markers: {missing}")
print("[PASS] v0.33 report validation evidence checks passed")
PY_CHECK

echo "[PASS] DeltaAegis v0.33 report validation evidence checks passed"
