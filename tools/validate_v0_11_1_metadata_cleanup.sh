#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

cd "$ROOT_DIR"

[[ -f README.md ]] || fail "Missing README.md"
[[ -f CHANGELOG.md ]] || fail "Missing CHANGELOG.md"
[[ -f deltaaegis.py ]] || fail "Missing deltaaegis.py"

grep -q 'Current release: \*\*DeltaAegis v0.11.1 — Metadata Cleanup\*\*' README.md \
  || fail "README current release does not point to v0.11.1"

grep -q 'NetSniper v1.7' README.md \
  || fail "README does not mention NetSniper v1.7"

grep -q 'python3 deltaaegis.py intelligence' README.md \
  || fail "README does not document the intelligence command"

grep -q '## v0.11.1 — Metadata Cleanup' CHANGELOG.md \
  || fail "CHANGELOG does not include v0.11.1"

grep -q 'DeltaAegis v0.11.1 Summary' deltaaegis.py \
  || fail "CLI summary still has stale version text"

grep -q 'DeltaAegis v0.11.1 NetSniper v1.7 intelligence review dashboard' deltaaegis.py \
  || fail "argparse description still has stale version text"

if sed -n '/## Current Release/,/^## /p' README.md | grep -q 'DeltaAegis v0.10.0'; then
  fail "README Current Release section still contains stale v0.10.0 text"
fi

python3 - <<'PY'
from pathlib import Path

for name in ["README.md", "CHANGELOG.md"]:
    text = Path(name).read_text(encoding="utf-8")
    count = text.count("```")
    if count % 2:
        raise SystemExit(f"{name} has uneven Markdown code fences")
PY

python3 -m py_compile deltaaegis.py
pytest -q

./tools/validate_v0_11_intelligence_artifacts.sh
./tools/validate_v0_11_dashboard_intelligence.sh

pass "DeltaAegis v0.11.1 metadata cleanup validation passed"
