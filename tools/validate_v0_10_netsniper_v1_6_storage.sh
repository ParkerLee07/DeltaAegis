#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${REPO_DIR:-$HOME/DeltaAegis}"
cd "$REPO_DIR" || {
  echo "[-] Could not enter DeltaAegis repo: $REPO_DIR"
  exit 1
}

echo "[*] Validating DeltaAegis v0.10 NetSniper v1.6 storage support..."

python3 -m py_compile deltaaegis.py

python3 - <<'PY'
from pathlib import Path
from dataclasses import fields
import json
import tempfile

import deltaaegis as da

required_columns = {
    "classification_confidence_band",
    "classification_calibrated_decision",
    "classification_siem_action",
    "classification_calibration_reason",
    "classification_validation_state",
    "classification_contradiction_count",
    "classification_validator_summary_json",
    "classification_validators_json",
}

snapshot_fields = {field.name for field in fields(da.Snapshot)}

with tempfile.TemporaryDirectory() as temp:
    db_path = Path(temp) / "deltaaegis-v0.10-storage.db"
    connection = da.connect(db_path)

    columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(asset_observations)")
    }

    missing = sorted(required_columns - columns)
    if missing:
        raise SystemExit(f"missing v1.6 storage columns: {missing}")

    asset = da.AssetObservation(
        asset_key="ip:192.0.2.20",
        identity_class="IP_ONLY",
        identity_confidence="HIGH",
        identity_source="SERVICE_XML",
        ip_address="192.0.2.20",
        mac_address=None,
        vendor=None,
        hostname="insert-demo",
        device_type="Web Server / Web Application Host",
        severity="LOW",
        score=10,
        services=[],
        findings=[],
        device_type_confidence=80,
        classification_type="Web Server / Web Application Host",
        classification_primary_type="Web Server / Web Application Host",
        classification_confidence=80,
        classification_confidence_label="confirmed",
        classification_decision="classified",
        classification_method="weighted_evidence",
        classification_json="{}",
        classification_evidence_json="[]",
        classification_contradictions_json="[]",
        classification_candidates_json="[]",
        classification_confidence_band="confirmed",
        classification_calibrated_decision="classified",
        classification_siem_action="alert_eligible",
        classification_calibration_reason="Synthetic insert validation.",
        classification_validation_state="confirmed",
        classification_contradiction_count=0,
        classification_validator_summary_json=json.dumps({"total": 1, "confirmed": 1}),
        classification_validators_json=json.dumps([
            {"name": "synthetic_validator", "state": "confirmed"}
        ]),
    )

    snapshot_kwargs = {
        "scan_id": "synthetic-v0.10-storage",
        "manifest_path": "/tmp/synthetic-manifest.json",
        "manifest_schema_version": "netsniper-run-v2",
        "target": "192.0.2.0/24",
        "scanner_version": "v1.6.0",
        "scan_profile": "synthetic",
        "created_at": "2026-06-19T00:00:00Z",
        "bundle_status": "COMPLETE",
        "xml_exit_status": "success",
        "hosts_up": 1,
        "hosts_down": 0,
        "hosts_total": 1,
        "identity_coverage": 0.0,
        "assets": {asset.asset_key: asset},
        "profile_fingerprint": "synthetic",
        "monitored_ports": [],
        "protocols": [],
        "discovery_interface": None,
        "nmap_version": None,
        "scan_started_at": None,
        "scan_completed_at": None,
        "neighbors_captured_at": None,
    }

    snapshot = da.Snapshot(**{
        key: value
        for key, value in snapshot_kwargs.items()
        if key in snapshot_fields
    })

    da.insert_snapshot(connection, snapshot, "ACCEPTED", "synthetic")
    connection.commit()

    row = connection.execute(
        """
        SELECT
            classification_confidence_band,
            classification_calibrated_decision,
            classification_siem_action,
            classification_calibration_reason,
            classification_validation_state,
            classification_contradiction_count,
            classification_validator_summary_json,
            classification_validators_json
        FROM asset_observations
        WHERE scan_id = ?
          AND asset_key = ?
        """,
        ("synthetic-v0.10-storage", asset.asset_key),
    ).fetchone()

    if row is None:
        raise SystemExit("inserted asset row was not found")

    expected = {
        "classification_confidence_band": "confirmed",
        "classification_calibrated_decision": "classified",
        "classification_siem_action": "alert_eligible",
        "classification_calibration_reason": "Synthetic insert validation.",
        "classification_validation_state": "confirmed",
        "classification_contradiction_count": 0,
    }

    actual = {key: row[key] for key in expected}

    if actual != expected:
        raise SystemExit(f"inserted row mismatch: {actual!r}")

    summary = json.loads(row["classification_validator_summary_json"])
    validators = json.loads(row["classification_validators_json"])

    if summary.get("confirmed") != 1:
        raise SystemExit(f"validator summary mismatch: {summary!r}")

    if not validators or validators[0].get("name") != "synthetic_validator":
        raise SystemExit(f"validators mismatch: {validators!r}")

    snapshot_payload = da._classification_snapshot(asset)
    if snapshot_payload.get("classification_siem_action") != "alert_eligible":
        raise SystemExit(f"snapshot payload missing v1.6 fields: {snapshot_payload!r}")

print("[+] PASS: DeltaAegis stores, inserts, and snapshots NetSniper v1.6 classification fields.")
PY

echo "[+] PASS: DeltaAegis v0.10 NetSniper v1.6 storage validation succeeded."
