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

cd "$ROOT_DIR"

[[ -f deltaaegis.py ]] || fail "Missing deltaaegis.py"
[[ -f "$BUNDLE_DIR/manifest.json" ]] || fail "Missing NetSniper v1.7 manifest"
[[ -f "$BUNDLE_DIR/analysis.enriched.json" ]] || fail "Missing NetSniper v1.7 analysis.enriched.json"

grep -q 'dashboard_netsniper_intelligence_host_payload' deltaaegis.py \
  || fail "Missing dashboard per-host intelligence payload"

grep -q 'route == "/api/intelligence-host"' deltaaegis.py \
  || fail "Missing /api/intelligence-host route"

python3 -m py_compile deltaaegis.py
pytest -q

tmp_db="$(mktemp /tmp/deltaaegis-v0-12-dashboard-api-XXXXXX.db)"
tmp_events="$(mktemp /tmp/deltaaegis-v0-12-dashboard-api-events-XXXXXX.jsonl)"
tmp_runs="$(mktemp -d /tmp/deltaaegis-v0-12-dashboard-api-runs-XXXXXX)"
trap 'rm -f "$tmp_db" "$tmp_events"; rm -rf "$tmp_runs"' EXIT

ln -s "$BUNDLE_DIR" "$tmp_runs/$(basename "$BUNDLE_DIR")"

python3 deltaaegis.py \
  --db "$tmp_db" \
  --runs-dir "$tmp_runs" \
  --events "$tmp_events" \
  ingest >/tmp/deltaaegis-v0-12-dashboard-api-ingest.out

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
payload = module.dashboard_netsniper_intelligence_host_payload(
    connection,
    "192.168.4.1",
)

if not payload.get("found"):
    raise SystemExit("Expected dashboard intelligence host payload to be found")

classification = payload.get("classification") or {}

checks = {
    "host_id": "192.168.4.1",
    "ip": "192.168.4.1",
}

for key, expected in checks.items():
    actual = payload.get(key)
    if actual != expected:
        raise SystemExit(f"{key} expected {expected!r}, got {actual!r}")

classification_checks = {
    "primary_type": "Web Server / Web Application Host",
    "confidence": 15,
    "confidence_band": "weak",
    "decision": "possible",
    "siem_action": "review_queue",
    "evidence_count": 1,
    "contradiction_count": 0,
}

for key, expected in classification_checks.items():
    actual = classification.get(key)
    if actual != expected:
        raise SystemExit(f"classification.{key} expected {expected!r}, got {actual!r}")

evidence = payload.get("evidence") or []
if not evidence:
    raise SystemExit("Expected evidence list")

if evidence[0].get("id") != "http_80":
    raise SystemExit(f"Expected first evidence id http_80, got {evidence[0].get('id')!r}")

observed = payload.get("observed") or {}
if "tcp/80" not in observed.get("open_ports", []):
    raise SystemExit("Expected observed open_ports to include tcp/80")

print("[PASS] Dashboard per-host intelligence payload validated")
PY

pass "DeltaAegis v0.12 dashboard intelligence host API validated"
