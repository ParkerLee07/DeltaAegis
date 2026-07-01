#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

grep -Fq 'api(scopedPath("/api/current-risk?limit=10000"))' deltaaegis.py
grep -Fq 'const riskRows = countBy(currentRisk, row => row.level || "INFO");' deltaaegis.py
grep -Fq 'validate_v0_34_dashboard_risk_distribution_scope.sh' tools/validate_v0_34_release.sh

python3 - <<'PY'
from pathlib import Path
import re

text = Path("deltaaegis.py").read_text(encoding="utf-8")

fetch_block = re.search(
    r"const \[scopes, summary, scanContext, currentState, investigationCenter, scanJobs, assets, currentRisk, historicalRisk, portBehavior, events, alerts, annotations\] = await Promise\.all\(\[(.*?)\]\);",
    text,
    flags=re.S,
)

assert fetch_block, "dashboard Promise.all fetch block not found"
block = fetch_block.group(1)

assert '/api/current-risk?limit=10000' in block, (
    "Executive dashboard risk distribution must fetch the full current-risk inventory, not only top 10 rows"
)
assert 'api(scopedPath("/api/current-risk?limit=10")),' not in block, (
    "Top-10 current-risk fetch would make the donut chart appear all-critical on mixed networks"
)

render_block = re.search(
    r"function renderExecutiveCharts\(summary, currentRisk, portBehavior, investigationCenter, assets, events, alerts\) \{.*?\n    \}",
    text,
    flags=re.S,
)

assert render_block, "renderExecutiveCharts function not found"
assert "const riskRows = countBy(currentRisk, row => row.level || \"INFO\");" in render_block.group(0), (
    "Executive risk distribution should count levels from the full currentRisk payload"
)

print("[PASS] v0.34 dashboard risk distribution scope checks passed")
PY

echo "[PASS] DeltaAegis v0.34 dashboard risk distribution scope validation passed"
