#!/usr/bin/env python3
"""Validate the intentional v0.45 transition from legacy v0.44 v2 receipts.

The v0.44 Stage 4 fixture expected legacy netsniper-run-v2 bundles to be
ACCEPTED and to emit an absence-derived finding-removal event.  The approved
v0.45 policy instead defaults those bundles to DEGRADED, preserves positive
service/finding additions, and blocks the removal.  Every unrelated Stage 4
contract remains delegated to the unchanged v0.44 validator.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import deltaaegis as facade  # noqa: E402
from tools import validate_v0_44_stage4_ingest as legacy  # noqa: E402


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def validate_snapshot_normalization(characterization: dict) -> None:
    for relative, expected in characterization["fixtures"].items():
        snapshot = facade.load_snapshot(ROOT / relative)
        check(
            legacy.snapshot_digest(snapshot, relative)
            == expected["snapshot_sha256"],
            f"normalized snapshot changed for {relative}",
        )


def validate_policy_transition() -> None:
    fixtures = [
        (
            "examples/demo-emergency-alert/runs/"
            "20260617-000000-demo-baseline/manifest.json",
            "IMPORT demo-emergency-baseline-001: quality=DEGRADED, "
            "assets=1, mac_identity=100%, events=0",
        ),
        (
            "examples/demo-emergency-alert/runs/"
            "20260617-000500-demo-emergency/manifest.json",
            "IMPORT demo-emergency-alert-002: quality=DEGRADED, "
            "assets=1, mac_identity=100%, events=10",
        ),
    ]
    with tempfile.TemporaryDirectory(
        prefix="deltaaegis-v045-v044-ingest-transition-"
    ) as temporary:
        root = Path(temporary)
        original_evidence_root = facade.DEFAULT_TELEMETRY_EVIDENCE
        facade.DEFAULT_TELEMETRY_EVIDENCE = root / "telemetry-evidence"
        connection = facade.connect(root / "transition.db")
        try:
            for relative, expected_receipt in fixtures:
                receipt = facade.ingest_manifest(
                    connection,
                    ROOT / relative,
                    root / "events.jsonl",
                )
                check(
                    receipt == expected_receipt,
                    f"unexpected v0.45 transition receipt for {relative}: "
                    f"{receipt!r}",
                )

            decisions = connection.execute(
                """
                SELECT run_id, automated_state, current_state,
                       reason_codes_json, effect_policy_json
                FROM telemetry_quality_decisions
                ORDER BY run_id
                """
            ).fetchall()
            check(len(decisions) == 2, "expected two durable quality decisions")
            for row in decisions:
                check(
                    row["automated_state"] == "DEGRADED"
                    and row["current_state"] == "DEGRADED",
                    f"legacy v2 run was not degraded: {row['run_id']}",
                )
                reason_codes = set(json.loads(row["reason_codes_json"]))
                check(
                    "legacy_v2_compatibility" in reason_codes,
                    f"legacy compatibility reason missing: {row['run_id']}",
                )
                effects = json.loads(row["effect_policy_json"])
                check(
                    effects.get("apply_absence_mutations") == "blocked",
                    "degraded absence mutation was not blocked",
                )
                check(
                    effects.get("resolve_alerts") == "blocked",
                    "degraded alert resolution was not blocked",
                )
                check(
                    effects.get("create_alerts")
                    == "positive_observations_only",
                    "degraded positive-alert boundary changed",
                )

            event_types = [
                str(row[0])
                for row in connection.execute(
                    "SELECT event_type FROM delta_events ORDER BY event_id"
                ).fetchall()
            ]
            check(len(event_types) == 10, "expected ten positive-only events")
            check(
                event_types.count("MONITORED_SERVICE_OPENED") == 5,
                "expected five positive service-open events",
            )
            check(
                event_types.count("NETSNIPER_FINDING_ADDED") == 5,
                "expected five positive finding-added events",
            )
            check(
                "MONITORED_SERVICE_CLOSED" not in event_types
                and "NETSNIPER_FINDING_REMOVED" not in event_types,
                "degraded run emitted an absence-derived event",
            )

            projected_findings = {
                str(row[0])
                for row in connection.execute(
                    "SELECT finding_id FROM telemetry_current_findings"
                ).fetchall()
            }
            check(
                "BASELINE_WEB_AND_SSH_ONLY" in projected_findings,
                "degraded absence removed the baseline finding",
            )
            check(
                len(projected_findings) == 6,
                "positive finding projection did not preserve all evidence",
            )
        finally:
            connection.close()
            facade.DEFAULT_TELEMETRY_EVIDENCE = original_evidence_root


def main() -> int:
    print("DeltaAegis v0.45 / v0.44 Ingest Policy Transition Validator")
    print("=============================================================")
    characterization = legacy.load_characterization()
    legacy.validate_ownership_and_facade(characterization)
    print("PASS: unchanged v0.44 ingest ownership and facade contracts")
    validate_snapshot_normalization(characterization)
    print("PASS: unchanged v0.44 normalized fixture snapshots")
    legacy.validate_trust_boundaries()
    print("PASS: unchanged bundle finalization and confinement boundaries")
    legacy.validate_scope_and_identity_rules()
    print("PASS: unchanged scope and identity rules")
    validate_policy_transition()
    print("PASS: legacy v2 is degraded with positive-only delta effects")
    print("PASS: DeltaAegis v0.45 intentional Stage 4 policy transition")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
