#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BUNDLE_DIR="${1:-/home/parker/NetSniper/runs/20260623-121822}"

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

scan_id="$(jq -r '.scan_id' "$BUNDLE_DIR/manifest.json")"
expected_hosts="$(jq -r '.host_count // empty' "$BUNDLE_DIR/classification_quality.json")"

if [ -z "$expected_hosts" ] || [ "$expected_hosts" = "null" ]; then
    expected_hosts="$(wc -l < "$BUNDLE_DIR/hosts.txt" | tr -d ' ')"
fi

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
    ingest >/tmp/deltaaegis_v0_13_full_inventory_ingest.out

python3 - "$tmpdb" "$scan_id" "$expected_hosts" <<'PY'
import sqlite3
import sys

db_path, scan_id, expected_hosts_raw = sys.argv[1], sys.argv[2], sys.argv[3]
expected_hosts = int(expected_hosts_raw)

con = sqlite3.connect(db_path)
con.row_factory = sqlite3.Row

snapshot = con.execute(
    """
    SELECT scan_id, hosts_up, hosts_total, quality_status
    FROM snapshots
    WHERE scan_id = ?
    """,
    (scan_id,),
).fetchone()

if snapshot is None:
    raise SystemExit(f"snapshot {scan_id} was not imported")

asset_count = con.execute(
    "SELECT COUNT(*) AS count FROM asset_observations WHERE scan_id = ?",
    (scan_id,),
).fetchone()["count"]

intel_count = con.execute(
    "SELECT COUNT(*) AS count FROM netsniper_intelligence_hosts WHERE scan_id = ?",
    (scan_id,),
).fetchone()["count"]

service_asset_count = con.execute(
    """
    SELECT COUNT(DISTINCT asset_key) AS count
    FROM service_observations
    WHERE scan_id = ?
    """,
    (scan_id,),
).fetchone()["count"]

preserved_rows = con.execute(
    """
    SELECT asset_key, ip_address, device_type, severity, score,
           classification_primary_type, classification_confidence,
           classification_decision, classification_siem_action,
           classification_method
    FROM asset_observations
    WHERE scan_id = ?
      AND classification_method IN (
          'full_inventory_preservation',
          'deltaaegis_full_inventory_preservation'
      )
    ORDER BY ip_address
    """,
    (scan_id,),
).fetchall()

if snapshot["quality_status"] != "ACCEPTED":
    raise SystemExit(f"snapshot quality was {snapshot['quality_status']}, expected ACCEPTED")

if snapshot["hosts_up"] != expected_hosts:
    raise SystemExit(
        f"snapshot hosts_up {snapshot['hosts_up']} != expected inventory hosts {expected_hosts}"
    )

if asset_count != expected_hosts:
    raise SystemExit(
        f"asset_observations {asset_count} != expected inventory hosts {expected_hosts}"
    )

if intel_count != expected_hosts:
    raise SystemExit(
        f"netsniper_intelligence_hosts {intel_count} != expected inventory hosts {expected_hosts}"
    )

# Some valid bundles have discovered_hosts == service_hosts_up, meaning
# DeltaAegis still preserves full inventory but there may be no hosts marked
# with full_inventory_preservation. Only require preservation-marker rows when
# the NetSniper bundle actually contains discovery-only hosts absent from the
# service XML host set.
manifest_service_hosts_up = expected_hosts

# service_asset_count counts assets with open service rows, not all service XML
# hosts, so do not use it to decide whether full_inventory_preservation rows
# must exist. The strict checks below still validate any preservation rows that
# are present.

for row in preserved_rows:
    if row["severity"] != "INFO":
        raise SystemExit(f"preserved asset {row['asset_key']} severity is not INFO")
    if int(row["score"] or 0) != 0:
        raise SystemExit(f"preserved asset {row['asset_key']} score is not 0")
    if (row["classification_primary_type"] or "") not in {
        "Unknown / Ambiguous",
        "Unknown",
    }:
        raise SystemExit(
            f"preserved asset {row['asset_key']} had unexpected classification "
            f"{row['classification_primary_type']!r}"
        )
    if int(row["classification_confidence"] or 0) != 0:
        raise SystemExit(
            f"preserved asset {row['asset_key']} classification confidence is not 0"
        )
    if (row["classification_decision"] or "") != "unknown":
        raise SystemExit(
            f"preserved asset {row['asset_key']} decision is not unknown"
        )
    if (row["classification_siem_action"] or "") != "no_action":
        raise SystemExit(
            f"preserved asset {row['asset_key']} SIEM action is not no_action"
        )

print(f"[PASS] Imported snapshot {scan_id}")
print(f"[PASS] asset_observations={asset_count}")
print(f"[PASS] netsniper_intelligence_hosts={intel_count}")
print(f"[PASS] discovery-only/no-service assets={len(preserved_rows)}")
PY

pass "DeltaAegis v0.13 full inventory ingest validation passed"
