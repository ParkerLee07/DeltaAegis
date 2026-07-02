#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[v0.37 hotfix] syntax check"
python3 -m py_compile deltaaegis.py

echo "[v0.37 hotfix] dashboard query import checks"
python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

if "urllib.parse.parse_qs" not in text:
    raise SystemExit("dashboard query parsing marker missing")

if "import urllib.parse" not in text:
    raise SystemExit("missing import urllib.parse for dashboard query parsing")

print("dashboard query import checks passed")
PY

echo "[v0.37 hotfix] dashboard query parsing smoke test"
python3 - <<'PY'
import urllib.parse

parsed = urllib.parse.urlparse("/api/netsniper/schedule-history?limit=10")
query = urllib.parse.parse_qs(parsed.query or "")

if query.get("limit") != ["10"]:
    raise SystemExit("urllib.parse query parsing smoke test failed")

print("dashboard query parsing smoke test passed")
PY

echo "[v0.37 hotfix] PASS"
