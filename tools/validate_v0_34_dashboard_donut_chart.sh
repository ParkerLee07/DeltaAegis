#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

grep -Fq 'const donutColors = [' deltaaegis.py
grep -Fq 'const donutBackground = `conic-gradient(${stops})`;' deltaaegis.py
grep -Fq 'style="background: ${esc(donutBackground)}"' deltaaegis.py
grep -Fq 'class="siem-legend-swatch"' deltaaegis.py
grep -Fq 'validate_v0_34_dashboard_donut_chart.sh' tools/validate_v0_34_release.sh

python3 - <<'PY'
from pathlib import Path
import re

text = Path("deltaaegis.py").read_text(encoding="utf-8")

match = re.search(
    r"function renderDistributionPanel\(targetId, rows, emptyMessage\) \{.*?\n    \}\n\n    function renderExecutiveCharts",
    text,
    flags=re.S,
)

assert match, "renderDistributionPanel function was not found"
body = match.group(0)

assert "background: conic-gradient(#22d3ee 0deg" not in body, (
    "renderDistributionPanel still relies on the static placeholder donut gradient"
)
assert "items.map((row, index)" in body, "donut renderer must iterate every distribution row"
assert "start.toFixed(2)" in body and "end.toFixed(2)" in body, (
    "dynamic donut slice boundaries are missing"
)
assert "index === items.length - 1 ? 360" in body, (
    "last donut slice should close at 360 degrees to avoid visible gaps"
)
assert "siem-legend-swatch" in body, "legend rows should expose matching color swatches"

print("[PASS] v0.34 dashboard donut chart renderer checks passed")
PY

echo "[PASS] DeltaAegis v0.34 dashboard donut chart validation passed"
