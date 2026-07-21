#!/usr/bin/env python3
"""Validate v0.45 ACCEPTED/DEGRADED projection effect boundaries."""

from __future__ import annotations

from dataclasses import dataclass, field
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "deltaaegis_core" / "current_state.py"


def require(condition, message):
    if not condition:
        raise SystemExit(f"[FAIL] {message}")


def load_module():
    spec = importlib.util.spec_from_file_location(
        "deltaaegis_v045_current_state",
        MODULE,
    )
    if spec is None or spec.loader is None:
        raise SystemExit("[FAIL] could not load current_state module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@dataclass
class Service:
    protocol: str
    port: int
    state: str = "open"
    service_name: str | None = None
    product: str | None = None
    version: str | None = None


@dataclass
class Asset:
    asset_key: str
    ip_address: str
    identity_class: str = "GLOBAL_MAC"
    identity_confidence: str = "STRONG"
    identity_source: str = "mac"
    mac_address: str | None = "00:11:22:33:44:55"
    vendor: str | None = "Fixture"
    hostname: str | None = "fixture"
    device_type: str | None = "server"
    device_type_confidence: int | None = 80
    classification_type: str | None = "server"
    classification_primary_type: str | None = "server"
    classification_confidence: int | None = 80
    classification_confidence_label: str | None = "classified"
    classification_decision: str | None = "classified"
    classification_method: str | None = "fixture"
    classification_json: str = "{}"
    classification_evidence_json: str = '["e1"]'
    classification_contradictions_json: str = "[]"
    classification_candidates_json: str = "[]"
    classification_confidence_band: str | None = "strong"
    classification_calibrated_decision: str | None = "classified"
    classification_siem_action: str | None = "monitor"
    classification_calibration_reason: str | None = "fixture"
    classification_validation_state: str | None = "confirmed"
    classification_contradiction_count: int | None = 0
    classification_validator_summary_json: str = "{}"
    classification_validators_json: str = "[]"
    severity: str | None = "MEDIUM"
    score: int | None = 30
    services: list[Service] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)


@dataclass
class Snapshot:
    scan_id: str
    target: str
    network_scope: str
    created_at: str
    assets: dict[str, Asset]


def schema(connection):
    connection.executescript(
        """
        CREATE TABLE asset_lifecycle (
            network_scope TEXT NOT NULL,
            asset_key TEXT NOT NULL,
            identity_class TEXT NOT NULL,
            state TEXT NOT NULL,
            missing_count INTEGER NOT NULL,
            current_ip TEXT NOT NULL,
            mac_address TEXT,
            vendor TEXT,
            hostname TEXT,
            first_seen_scan_id TEXT NOT NULL,
            last_seen_scan_id TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            removed_at TEXT,
            PRIMARY KEY(network_scope, asset_key)
        );
        """
    )


def decision(state, decision_id, negative):
    return {
        "decision_id": decision_id,
        "current_state": state,
        "coverage_capabilities": {
            "negative_evidence_allowed": negative,
        },
    }


def main():
    current = load_module()
    with tempfile.TemporaryDirectory(prefix="deltaaegis-v045-effects-") as tmp:
        connection = sqlite3.connect(Path(tmp) / "test.db")
        connection.row_factory = sqlite3.Row
        schema(connection)
        before_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        require(
            before_tables == {"asset_lifecycle"},
            "v0.45 projection tables were not lazy before first feature use",
        )
        require(current.current_assets(connection) == [], "empty lazy projection changed")
        after_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        require(
            {
                "telemetry_current_assets",
                "telemetry_current_services",
                "telemetry_current_findings",
            } <= after_tables,
            "first projection feature use did not initialize lazy storage",
        )

        accepted_asset = Asset(
            asset_key="mac:00:11:22:33:44:55",
            ip_address="192.168.1.10",
            score=50,
            services=[Service("tcp", 22, service_name="ssh")],
        )
        removed_later = Asset(
            asset_key="mac:00:11:22:33:44:66",
            ip_address="192.168.1.20",
            services=[Service("tcp", 80, service_name="http")],
        )
        first = Snapshot(
            "accepted-1",
            "192.168.1.0/24",
            "192.168.1.0/24",
            "2026-07-17T14:00:00+00:00",
            {
                accepted_asset.asset_key: accepted_asset,
                removed_later.asset_key: removed_later,
            },
        )
        current.apply_snapshot(
            connection,
            first,
            decision("ACCEPTED", "d1", True),
        )

        degraded_asset = Asset(
            asset_key=accepted_asset.asset_key,
            ip_address="192.168.1.11",
            classification_confidence=60,
            classification_evidence_json='["e1"]',
            services=[Service("tcp", 443, service_name="https")],
            findings=[
                {
                    "finding_id": "degraded-high",
                    "score": 90,
                    "port": 443,
                }
            ],
        )
        degraded_asset.classification_json = json.dumps(
            {
                "semantic_fingerprint": "degraded-same",
                "deltaaegis_context": {
                    "semantic_fingerprint": "degraded-same",
                    "operator_disposition": "review_only",
                },
            }
        )
        degraded = Snapshot(
            "degraded-1",
            "192.168.1.0/24",
            "192.168.1.0/24",
            "2026-07-17T15:00:00+00:00",
            {degraded_asset.asset_key: degraded_asset},
        )
        current.apply_snapshot(
            connection,
            degraded,
            decision("DEGRADED", "d2", False),
        )

        still_present = connection.execute(
            "SELECT 1 FROM telemetry_current_assets "
            "WHERE asset_key = ?",
            (removed_later.asset_key,),
        ).fetchone()
        require(
            still_present is not None,
            "DEGRADED evidence removed an unobserved asset",
        )
        old_service = connection.execute(
            "SELECT 1 FROM telemetry_current_services "
            "WHERE asset_key = ? AND port = 22",
            (accepted_asset.asset_key,),
        ).fetchone()
        new_service = connection.execute(
            "SELECT 1 FROM telemetry_current_services "
            "WHERE asset_key = ? AND port = 443",
            (accepted_asset.asset_key,),
        ).fetchone()
        require(old_service is not None, "DEGRADED evidence closed an old service")
        require(new_service is not None, "DEGRADED positive service was not added")
        degraded_service_row = connection.execute(
            "SELECT accepted_evidence_seen FROM telemetry_current_services "
            "WHERE asset_key = ? AND port = 443",
            (accepted_asset.asset_key,),
        ).fetchone()
        degraded_finding_row = connection.execute(
            "SELECT accepted_evidence_seen FROM telemetry_current_findings "
            "WHERE asset_key = ? AND finding_id = 'degraded-high'",
            (accepted_asset.asset_key,),
        ).fetchone()
        require(
            degraded_service_row is not None
            and int(degraded_service_row["accepted_evidence_seen"]) == 0,
            "new DEGRADED service inherited unrelated accepted provenance",
        )
        require(
            degraded_finding_row is not None
            and int(degraded_finding_row["accepted_evidence_seen"]) == 0,
            "new DEGRADED finding inherited unrelated accepted provenance",
        )

        synthetic_risk = current.merge_risk_rows(
            connection,
            [],
            scope="192.168.1.0/24",
            limit=100,
            risk_level=lambda score: (
                "CRITICAL" if score >= 85
                else "HIGH" if score >= 65
                else "MEDIUM" if score >= 35
                else "LOW" if score >= 15
                else "INFO"
            ),
        )
        accepted_projection_risk = next(
            row
            for row in synthetic_risk
            if row["subject_key"] == accepted_asset.asset_key
        )
        require(
            int(accepted_projection_risk["score"]) == 64,
            "DEGRADED risk contribution was not capped at 64",
        )
        require(
            int(accepted_projection_risk["accepted_supported_score"]) == 52,
            "accepted-supported risk provenance was not preserved",
        )

        lifecycle_rows = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM asset_lifecycle"
            ).fetchall()
        ]
        filtered = current.merge_asset_rows(
            connection,
            lifecycle_rows,
            scope="192.168.1.0/24",
            state="ACTIVE",
            identity="GLOBAL_MAC",
            limit=100,
        )
        require(
            filtered
            and all(
                row["state"] == "ACTIVE"
                and row["identity_class"] == "GLOBAL_MAC"
                for row in filtered
            ),
            "projected asset merge bypassed state/identity filters",
        )
        detail = current.augment_asset_detail(
            connection,
            {
                "found": True,
                "asset_key": accepted_asset.asset_key,
                "network_scope": "192.168.1.0/24",
            },
        )
        require(
            detail.get("telemetry_projection", {}).get("services"),
            "asset detail did not expose projected positive services",
        )
        projected = connection.execute(
            "SELECT classification_confidence FROM telemetry_current_assets "
            "WHERE asset_key = ?",
            (accepted_asset.asset_key,),
        ).fetchone()
        require(
            int(projected["classification_confidence"]) == 80,
            "weaker/review-only degraded classification replaced accepted evidence",
        )

        missing_fingerprint_asset = Asset(
            asset_key=accepted_asset.asset_key,
            ip_address="192.168.1.12",
            classification_confidence=99,
            classification_decision="confirmed",
            classification_calibrated_decision="confirmed",
            classification_evidence_json='["e1", "e2", "e3"]',
            classification_validation_state="confirmed",
            classification_json=json.dumps(
                {
                    "deltaaegis_context": {
                        "operator_disposition": "apply",
                    }
                }
            ),
        )
        missing_fingerprint_snapshot = Snapshot(
            "degraded-missing-fingerprint",
            "192.168.1.0/24",
            "192.168.1.0/24",
            "2026-07-17T15:30:00+00:00",
            {
                missing_fingerprint_asset.asset_key:
                    missing_fingerprint_asset
            },
        )
        current.apply_snapshot(
            connection,
            missing_fingerprint_snapshot,
            decision("DEGRADED", "d2b", False),
        )
        projected = connection.execute(
            "SELECT classification_confidence FROM telemetry_current_assets "
            "WHERE asset_key = ?",
            (accepted_asset.asset_key,),
        ).fetchone()
        require(
            int(projected["classification_confidence"]) == 80,
            "DEGRADED classification without semantic fingerprint replaced evidence",
        )

        degraded_only = Asset(
            asset_key="ip:192.168.1.30",
            ip_address="192.168.1.30",
            identity_class="IP_ONLY",
            mac_address=None,
            score=95,
            services=[Service("tcp", 8080, service_name="http-proxy")],
            findings=[{"finding_id": "f1", "score": 90, "port": 8080}],
        )
        degraded_two = Snapshot(
            "degraded-2",
            "192.168.1.0/24",
            "192.168.1.0/24",
            "2026-07-17T16:00:00+00:00",
            {degraded_only.asset_key: degraded_only},
        )
        current.apply_snapshot(
            connection,
            degraded_two,
            decision("DEGRADED", "d3", False),
        )
        ceiling = current.risk_ceiling_for_asset(
            connection,
            scope="192.168.1.0/24",
            asset_key=degraded_only.asset_key,
        )
        require(ceiling == 64, "degraded-only risk ceiling is not 64")
        degraded_risk_rows = current.merge_risk_rows(
            connection,
            [],
            scope="192.168.1.0/24",
            limit=100,
            risk_level=lambda score: (
                "CRITICAL" if score >= 85
                else "HIGH" if score >= 65
                else "MEDIUM" if score >= 35
                else "LOW" if score >= 15
                else "INFO"
            ),
        )
        degraded_risk = next(
            row
            for row in degraded_risk_rows
            if row["subject_key"] == degraded_only.asset_key
        )
        require(
            int(degraded_risk["score"]) == 64
            and degraded_risk["level"] == "MEDIUM",
            "degraded-only risk row exceeded the approved MEDIUM ceiling",
        )

        accepted_high = Asset(
            asset_key="mac:00:11:22:33:44:77",
            ip_address="192.168.1.40",
            mac_address="00:11:22:33:44:77",
            score=90,
            services=[Service("tcp", 8443, service_name="https-alt")],
        )
        accepted_high_snapshot = Snapshot(
            "accepted-high",
            "192.168.1.0/24",
            "192.168.1.0/24",
            "2026-07-17T16:15:00+00:00",
            {accepted_high.asset_key: accepted_high},
        )
        current.apply_snapshot(
            connection,
            accepted_high_snapshot,
            decision("ACCEPTED", "d3b", False),
        )
        accepted_high_degraded = Asset(
            asset_key=accepted_high.asset_key,
            ip_address="192.168.1.41",
            mac_address="00:11:22:33:44:77",
            score=95,
            services=[
                Service("tcp", 8443, service_name="https-alt"),
                Service("tcp", 9443, service_name="https-admin"),
            ],
            findings=[
                {
                    "finding_id": "degraded-high-extra",
                    "score": 95,
                    "port": 9443,
                }
            ],
        )
        accepted_high_degraded.classification_json = json.dumps(
            {
                "deltaaegis_context": {
                    "operator_disposition": "review_only",
                    "semantic_fingerprint": "accepted-high-degraded",
                }
            }
        )
        accepted_high_degraded_snapshot = Snapshot(
            "degraded-high-extra",
            "192.168.1.0/24",
            "192.168.1.0/24",
            "2026-07-17T16:30:00+00:00",
            {accepted_high.asset_key: accepted_high_degraded},
        )
        current.apply_snapshot(
            connection,
            accepted_high_degraded_snapshot,
            decision("DEGRADED", "d3c", False),
        )
        high_risk_rows = current.merge_risk_rows(
            connection,
            [],
            scope="192.168.1.0/24",
            limit=100,
            risk_level=lambda score: (
                "CRITICAL" if score >= 85
                else "HIGH" if score >= 65
                else "MEDIUM" if score >= 35
                else "LOW" if score >= 15
                else "INFO"
            ),
        )
        high_risk = next(
            row
            for row in high_risk_rows
            if row["subject_key"] == accepted_high.asset_key
        )
        require(
            int(high_risk["score"]) >= 90,
            "independently accepted HIGH/CRITICAL risk was incorrectly capped",
        )
        require(
            int(high_risk["score"]) < 100,
            "DEGRADED evidence independently raised accepted high risk",
        )

        final = Snapshot(
            "accepted-2",
            "192.168.1.0/24",
            "192.168.1.0/24",
            "2026-07-17T17:00:00+00:00",
            {accepted_asset.asset_key: accepted_asset},
        )
        current.apply_snapshot(
            connection,
            final,
            decision("ACCEPTED", "d4", True),
        )
        removed = connection.execute(
            "SELECT 1 FROM telemetry_current_assets "
            "WHERE asset_key = ?",
            (removed_later.asset_key,),
        ).fetchone()
        require(
            removed is None,
            "coverage-proven ACCEPTED evidence did not apply absence",
        )
        lifecycle = connection.execute(
            "SELECT state, missing_count FROM asset_lifecycle "
            "WHERE asset_key = ?",
            (removed_later.asset_key,),
        ).fetchone()
        require(
            lifecycle is not None
            and lifecycle["state"] == "MISSING"
            and int(lifecycle["missing_count"]) == 1,
            "coverage-proven ACCEPTED replay did not rebuild lifecycle absence",
        )

        connection.close()

    print("[PASS] v0.45 telemetry effect boundaries and projection replay rules")


if __name__ == "__main__":
    main()
