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

grep -q 'netsniper_intelligence_hosts' deltaaegis.py \
  || fail "Missing per-host intelligence table"

grep -q 'store_netsniper_intelligence_hosts' deltaaegis.py \
  || fail "Missing per-host intelligence storage function"

grep -q 'sub.add_parser("intelligence-hosts"' deltaaegis.py \
  || fail "Missing intelligence-hosts CLI command"

grep -q 'sub.add_parser("intelligence-host"' deltaaegis.py \
  || fail "Missing intelligence-host CLI command"

grep -q 'args.command == "intelligence-hosts"' deltaaegis.py \
  || fail "Missing intelligence-hosts dispatcher"

grep -q 'args.command == "intelligence-host"' deltaaegis.py \
  || fail "Missing intelligence-host dispatcher"

python3 -m py_compile deltaaegis.py
pytest -q

tmp_db="$(mktemp /tmp/deltaaegis-v0-12-drilldown-XXXXXX.db)"
tmp_events="$(mktemp /tmp/deltaaegis-v0-12-drilldown-events-XXXXXX.jsonl)"
tmp_runs="$(mktemp -d /tmp/deltaaegis-v0-12-drilldown-runs-XXXXXX)"
trap 'rm -f "$tmp_db" "$tmp_events"; rm -rf "$tmp_runs"' EXIT

ln -s "$BUNDLE_DIR" "$tmp_runs/$(basename "$BUNDLE_DIR")"

python3 deltaaegis.py \
  --db "$tmp_db" \
  --runs-dir "$tmp_runs" \
  --events "$tmp_events" \
  ingest >/tmp/deltaaegis-v0-12-ingest.out

python3 deltaaegis.py \
  --db "$tmp_db" \
  --events "$tmp_events" \
  intelligence-hosts --limit 12 --action review_queue >/tmp/deltaaegis-v0-12-hosts.out

python3 deltaaegis.py \
  --db "$tmp_db" \
  --events "$tmp_events" \
  intelligence-host 192.168.4.1 >/tmp/deltaaegis-v0-12-host.out

grep -q 'Host Intelligence Review Queue' /tmp/deltaaegis-v0-12-hosts.out \
  || fail "intelligence-hosts did not print review queue heading"

grep -q '192.168.4.1' /tmp/deltaaegis-v0-12-hosts.out \
  || fail "intelligence-hosts did not include 192.168.4.1"

grep -q 'Web Server / Web Application Host' /tmp/deltaaegis-v0-12-host.out \
  || fail "host drilldown missing expected primary type"

grep -q 'Confidence:[[:space:]]*15 (weak)' /tmp/deltaaegis-v0-12-host.out \
  || fail "host drilldown missing expected confidence"

grep -q 'SIEM Action:[[:space:]]*review_queue' /tmp/deltaaegis-v0-12-host.out \
  || fail "host drilldown missing expected SIEM action"

grep -q 'http_80' /tmp/deltaaegis-v0-12-host.out \
  || fail "host drilldown missing expected evidence id"

python3 - "$tmp_db" <<'PY'
import sqlite3
import sys

db = sys.argv[1]
conn = sqlite3.connect(db)
conn.row_factory = sqlite3.Row

total = conn.execute(
    "SELECT COUNT(*) AS count FROM netsniper_intelligence_hosts"
).fetchone()["count"]

if int(total) != 82:
    raise SystemExit(f"Expected 82 per-host intelligence rows, got {total}")

row = conn.execute(
    """
    SELECT *
    FROM netsniper_intelligence_hosts
    WHERE host_id = '192.168.4.1'
    """
).fetchone()

if row is None:
    raise SystemExit("Missing 192.168.4.1 per-host intelligence row")

checks = {
    "primary_type": "Web Server / Web Application Host",
    "confidence": 15,
    "confidence_band": "weak",
    "decision": "possible",
    "siem_action": "review_queue",
    "evidence_count": 1,
    "contradiction_count": 0,
}

for key, expected in checks.items():
    actual = row[key]
    if isinstance(expected, int):
        actual = int(actual)
    if actual != expected:
        raise SystemExit(f"{key} expected {expected!r}, got {actual!r}")

print("[PASS] Stored v0.12 per-host drilldown rows validated")
PY

pass "DeltaAegis v0.12 per-host intelligence drilldown CLI validated"
