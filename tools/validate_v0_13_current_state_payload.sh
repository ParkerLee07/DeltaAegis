#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BUNDLE_DIR="${1:-/home/parker/NetSniper/runs/20260623-123007}"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

[ -d "$BUNDLE_DIR" ] || fail "Bundle directory not found: $BUNDLE_DIR"

for file in manifest.json hosts.txt analysis.json analysis.enriched.json classification_quality.json; do
    [ -s "$BUNDLE_DIR/$file" ] || fail "Missing bundle file: $BUNDLE_DIR/$file"
done

grep -q 'def dashboard_current_state_payload' deltaaegis.py \
    || fail "dashboard_current_state_payload function is missing"

grep -q '"/api/current-state"' deltaaegis.py \
    || fail "/api/current-state route is missing"

scan_id="$(jq -r '.scan_id' "$BUNDLE_DIR/manifest.json")"
target="$(jq -r '.target' "$BUNDLE_DIR/manifest.json")"
expected_hosts="$(jq -r '.host_count' "$BUNDLE_DIR/classification_quality.json")"
expected_classified="$(jq -r '.classified_count' "$BUNDLE_DIR/classification_quality.json")"
expected_possible="$(jq -r '.possible_or_review_count' "$BUNDLE_DIR/classification_quality.json")"
expected_unknown="$(jq -r '.unknown_count' "$BUNDLE_DIR/classification_quality.json")"
expected_false_confidence="$(jq -r '.false_confidence_candidate_count' "$BUNDLE_DIR/classification_quality.json")"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

mkdir -p "$tmpdir/runs"
ln -s "$BUNDLE_DIR" "$tmpdir/runs/$scan_id"

tmpdb="$tmpdir/deltaaegis.db"
tmpevents="$tmpdir/events.jsonl"

python3 deltaaegis.py \
    --db "$tmpdb" \
    --runs-dir "$tmpdir/runs" \
    --events "$tmpevents" \
    ingest >/tmp/deltaaegis_v0_13_current_state_ingest.out

python3 - "$tmpdb" "$scan_id" "$target" "$expected_hosts" "$expected_classified" "$expected_possible" "$expected_unknown" "$expected_false_confidence" <<'PY'
import sqlite3
import sys

import deltaaegis

(
    db_path,
    scan_id,
    target,
    expected_hosts_raw,
    expected_classified_raw,
    expected_possible_raw,
    expected_unknown_raw,
    expected_false_confidence_raw,
) = sys.argv[1:9]

expected_hosts = int(expected_hosts_raw)
expected_classified = int(expected_classified_raw)
expected_possible = int(expected_possible_raw)
expected_unknown = int(expected_unknown_raw)
expected_false_confidence = int(expected_false_confidence_raw)

con = sqlite3.connect(db_path)
con.row_factory = sqlite3.Row

payload = deltaaegis.dashboard_current_state_payload(con, scope=target)

if not payload.get("available"):
    raise SystemExit(f"current-state payload was unavailable: {payload}")

if payload["scan_id"] != scan_id:
    raise SystemExit(f"scan_id {payload['scan_id']} != expected {scan_id}")

if payload["target"] != target:
    raise SystemExit(f"target {payload['target']} != expected {target}")

if payload["quality_status"] != "ACCEPTED":
    raise SystemExit(f"quality_status {payload['quality_status']} != ACCEPTED")

if int(payload["assets"]) != expected_hosts:
    raise SystemExit(f"assets {payload['assets']} != expected {expected_hosts}")

if int(payload["intelligence_hosts"]) != expected_hosts:
    raise SystemExit(
        f"intelligence_hosts {payload['intelligence_hosts']} != expected {expected_hosts}"
    )

if int(payload["hosts_up"]) != expected_hosts:
    raise SystemExit(f"hosts_up {payload['hosts_up']} != expected {expected_hosts}")

if int(payload["assets"]) != int(payload["intelligence_hosts"]):
    raise SystemExit("assets and intelligence_hosts do not match")

if int(payload["service_observed_assets"]) > int(payload["assets"]):
    raise SystemExit("service_observed_assets exceeds total assets")

expected_discovery_only = int(payload["assets"]) - int(payload["service_observed_assets"])
if int(payload["discovery_only_or_no_open_service_assets"]) != expected_discovery_only:
    raise SystemExit("discovery-only asset count is inconsistent")

if int(payload["classified"]) != expected_classified:
    raise SystemExit(f"classified {payload['classified']} != expected {expected_classified}")

if int(payload["possible_or_review"]) != expected_possible:
    raise SystemExit(
        f"possible_or_review {payload['possible_or_review']} != expected {expected_possible}"
    )

if int(payload["unknown"]) != expected_unknown:
    raise SystemExit(f"unknown {payload['unknown']} != expected {expected_unknown}")

if int(payload["false_confidence_candidates"]) != expected_false_confidence:
    raise SystemExit(
        "false_confidence_candidates "
        f"{payload['false_confidence_candidates']} != expected {expected_false_confidence}"
    )

snapshot = payload.get("snapshot") or {}
asset_summary = snapshot.get("asset_summary") or {}

if int(asset_summary.get("observed_assets") or 0) != expected_hosts:
    raise SystemExit("snapshot.asset_summary.observed_assets does not match current assets")

print(f"[PASS] current-state scan_id={payload['scan_id']}")
print(f"[PASS] assets={payload['assets']}")
print(f"[PASS] intelligence_hosts={payload['intelligence_hosts']}")
print(f"[PASS] service_observed_assets={payload['service_observed_assets']}")
print(
    "[PASS] discovery_only_or_no_open_service_assets="
    f"{payload['discovery_only_or_no_open_service_assets']}"
)
print(f"[PASS] classified={payload['classified']}")
print(f"[PASS] possible_or_review={payload['possible_or_review']}")
print(f"[PASS] unknown={payload['unknown']}")
PY

pass "DeltaAegis v0.13 current-state payload validation passed"
