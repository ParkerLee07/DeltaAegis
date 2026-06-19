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
[[ -f "$BUNDLE_DIR/manifest.json" ]] || fail "Missing NetSniper v1.7 manifest: $BUNDLE_DIR/manifest.json"
[[ -f "$BUNDLE_DIR/classification_quality.json" ]] || fail "Missing classification_quality.json"
[[ -f "$BUNDLE_DIR/analysis.enriched.json" ]] || fail "Missing analysis.enriched.json"

grep -q 'CREATE TABLE IF NOT EXISTS netsniper_intelligence_summaries' "$ROOT_DIR/deltaaegis.py" \
  || fail "Missing v0.11 intelligence summary table"

grep -q 'ensure_netsniper_intelligence_schema' "$ROOT_DIR/deltaaegis.py" \
  || fail "Missing v0.11 intelligence schema helper"

grep -q 'store_netsniper_intelligence_summary' "$ROOT_DIR/deltaaegis.py" \
  || fail "Missing v0.11 intelligence storage function"

grep -q 'analysis_enriched_json' "$ROOT_DIR/deltaaegis.py" \
  || fail "Missing analysis_enriched_json awareness"

grep -q 'classification_quality_json' "$ROOT_DIR/deltaaegis.py" \
  || fail "Missing classification_quality_json awareness"

grep -q 'classification_quality_markdown' "$ROOT_DIR/deltaaegis.py" \
  || fail "Missing classification_quality_markdown awareness"

grep -q 'sub.add_parser("intelligence"' "$ROOT_DIR/deltaaegis.py" \
  || fail "Missing intelligence CLI command"

grep -q 'args.command == "intelligence"' "$ROOT_DIR/deltaaegis.py" \
  || fail "Missing intelligence command dispatcher"

python3 -m py_compile "$ROOT_DIR/deltaaegis.py"

tmp_db="$(mktemp /tmp/deltaaegis-v0-11-intel-XXXXXX.db)"
tmp_events="$(mktemp /tmp/deltaaegis-v0-11-events-XXXXXX.jsonl)"
tmp_runs="$(mktemp -d /tmp/deltaaegis-v0-11-runs-XXXXXX)"
trap 'rm -f "$tmp_db" "$tmp_events"; rm -rf "$tmp_runs"' EXIT

ln -s "$BUNDLE_DIR" "$tmp_runs/$(basename "$BUNDLE_DIR")"

python3 "$ROOT_DIR/deltaaegis.py" \
  --db "$tmp_db" \
  --runs-dir "$tmp_runs" \
  --events "$tmp_events" \
  ingest >/tmp/deltaaegis-v0-11-ingest.out

python3 "$ROOT_DIR/deltaaegis.py" \
  --db "$tmp_db" \
  --events "$tmp_events" \
  intelligence >/tmp/deltaaegis-v0-11-intelligence.out

grep -q 'Hosts:[[:space:]]*82' /tmp/deltaaegis-v0-11-intelligence.out \
  || fail "Expected 82 hosts in intelligence output"

grep -q 'Classified:[[:space:]]*13' /tmp/deltaaegis-v0-11-intelligence.out \
  || fail "Expected 13 classified hosts in intelligence output"

grep -q 'Possible / review:[[:space:]]*33' /tmp/deltaaegis-v0-11-intelligence.out \
  || fail "Expected 33 possible/review hosts in intelligence output"

grep -q 'Unknown:[[:space:]]*36' /tmp/deltaaegis-v0-11-intelligence.out \
  || fail "Expected 36 unknown hosts in intelligence output"

grep -q 'False-confidence candidates:[[:space:]]*0' /tmp/deltaaegis-v0-11-intelligence.out \
  || fail "Expected 0 false-confidence candidates"

grep -q 'Unknown exposed services:[[:space:]]*0' /tmp/deltaaegis-v0-11-intelligence.out \
  || fail "Expected 0 unknown exposed-service hosts"

python3 - "$tmp_db" <<'PY'
import sqlite3
import sys

db = sys.argv[1]
conn = sqlite3.connect(db)
conn.row_factory = sqlite3.Row

row = conn.execute(
    "SELECT * FROM netsniper_intelligence_summaries ORDER BY imported_at DESC LIMIT 1"
).fetchone()

if row is None:
    raise SystemExit("No v0.11 intelligence summary row was stored")

checks = {
    "host_count": 82,
    "classified_count": 13,
    "possible_or_review_count": 33,
    "unknown_count": 36,
    "false_confidence_candidate_count": 0,
    "unknown_with_exposed_services_count": 0,
}

for key, expected in checks.items():
    actual = int(row[key])
    if actual != expected:
        raise SystemExit(f"{key} expected {expected}, got {actual}")

print("[PASS] Stored v0.11 intelligence summary row validated")
PY

pass "DeltaAegis v0.11 stores NetSniper v1.7 intelligence artifacts"
pass "DeltaAegis v0.11 intelligence CLI command works"
