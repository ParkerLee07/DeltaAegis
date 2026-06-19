#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_DIR="${1:-/home/parker/NetSniper/runs/20260619-134116}"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

[[ -f "$ROOT_DIR/deltaaegis.py" ]] || fail "Missing deltaaegis.py"
[[ -f "$BUNDLE_DIR/manifest.json" ]] || fail "Missing NetSniper bundle manifest"

grep -q 'dashboard_netsniper_intelligence_summary_payload' "$ROOT_DIR/deltaaegis.py" \
  || fail "Missing dashboard v1.7 intelligence payload"

grep -q 'netsniper_intelligence_summary' "$ROOT_DIR/deltaaegis.py" \
  || fail "Dashboard summary does not expose netsniper_intelligence_summary"

grep -q 'NetSniper v1.7 Bundle Intelligence' "$ROOT_DIR/deltaaegis.py" \
  || fail "Dashboard does not render v1.7 bundle intelligence block"

grep -q 'v1.7 Review Queue Sample' "$ROOT_DIR/deltaaegis.py" \
  || fail "Dashboard does not render v1.7 review queue sample"

grep -q 'False Confidence' "$ROOT_DIR/deltaaegis.py" \
  || fail "Dashboard does not render false-confidence count"

python3 -m py_compile "$ROOT_DIR/deltaaegis.py"

tmp_db="$(mktemp /tmp/deltaaegis-v0-11-dashboard-XXXXXX.db)"
tmp_events="$(mktemp /tmp/deltaaegis-v0-11-dashboard-events-XXXXXX.jsonl)"
tmp_runs="$(mktemp -d /tmp/deltaaegis-v0-11-dashboard-runs-XXXXXX)"
trap 'rm -f "$tmp_db" "$tmp_events"; rm -rf "$tmp_runs"' EXIT

ln -s "$BUNDLE_DIR" "$tmp_runs/$(basename "$BUNDLE_DIR")"

python3 "$ROOT_DIR/deltaaegis.py" \
  --db "$tmp_db" \
  --runs-dir "$tmp_runs" \
  --events "$tmp_events" \
  ingest >/tmp/deltaaegis-v0-11-dashboard-ingest.out

python3 - "$ROOT_DIR" "$tmp_db" <<'PY'
import importlib.util
import sys
from pathlib import Path

root = Path(sys.argv[1])
db_path = Path(sys.argv[2])

spec = importlib.util.spec_from_file_location("deltaaegis", root / "deltaaegis.py")
module = importlib.util.module_from_spec(spec)
sys.modules["deltaaegis"] = module
spec.loader.exec_module(module)

connection = module.connect(db_path)
payload = module.dashboard_summary_payload(connection)

intel = payload.get("netsniper_intelligence_summary")
if not isinstance(intel, dict):
    raise SystemExit("netsniper_intelligence_summary payload missing")

if not intel.get("available"):
    raise SystemExit("netsniper_intelligence_summary payload is not available")

checks = {
    "host_count": 82,
    "classified_count": 13,
    "possible_or_review_count": 33,
    "unknown_count": 36,
    "false_confidence_candidate_count": 0,
    "unknown_with_exposed_services_count": 0,
}

for key, expected in checks.items():
    actual = int(intel.get(key, -1))
    if actual != expected:
        raise SystemExit(f"{key} expected {expected}, got {actual}")

if not intel.get("top_device_types"):
    raise SystemExit("top_device_types missing from dashboard payload")

if not intel.get("confidence_band_counts"):
    raise SystemExit("confidence_band_counts missing from dashboard payload")

if not intel.get("review_queue"):
    raise SystemExit("review_queue missing from dashboard payload")

print("[PASS] Dashboard v0.11 NetSniper intelligence payload validated")
PY

pass "DeltaAegis v0.11 dashboard exposes NetSniper v1.7 intelligence summary"
