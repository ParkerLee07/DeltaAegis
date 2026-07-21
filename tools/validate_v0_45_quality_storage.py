#!/usr/bin/env python3
"""Validate v0.45 quality decision storage, retention, and review rules."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sqlite3
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "deltaaegis_core" / "telemetry_quality.py"
POLICY = ROOT / "contracts" / "v0.45" / "telemetry-quality-policy.json"


def require(condition, message):
    if not condition:
        raise SystemExit(f"[FAIL] {message}")


def load_module():
    spec = importlib.util.spec_from_file_location(
        "deltaaegis_v045_quality_storage",
        MODULE,
    )
    if spec is None or spec.loader is None:
        raise SystemExit("[FAIL] could not load telemetry_quality module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def base_schema(connection):
    connection.executescript(
        """
        CREATE TABLE snapshots (
            scan_id TEXT PRIMARY KEY,
            quality_status TEXT NOT NULL,
            manifest_path TEXT NOT NULL DEFAULT '',
            is_accepted_baseline INTEGER NOT NULL DEFAULT 0
        );
        """
    )


def decision(quality, digest="a" * 64, state="DEGRADED"):
    return {
        "schema_version": quality.DECISION_SCHEMA_VERSION,
        "decision_id": f"decision-{digest[:8]}-{state.lower()}",
        "run_id": "run-1",
        "bundle_digest": digest,
        "manifest_path": "/tmp/run-1/manifest.json",
        "network_scope": "192.168.1.0/24",
        "scanner_version": "2.1.0",
        "automated_state": state,
        "current_state": state,
        "policy_version": quality.POLICY_VERSION,
        "reason_codes": ["partial_scan"],
        "reasons": [
            {
                "code": "partial_scan",
                "severity": "warning",
                "minimum_state": state,
                "overridable": True,
                "description": "fixture",
            }
        ],
        "allowed_effects": ["update_positive_observations"],
        "blocked_effects": ["apply_absence_mutations"],
        "effect_policy": {
            "update_positive_observations": "positive_observations_only",
            "apply_absence_mutations": "blocked",
        },
        "coverage_capabilities": {
            "negative_evidence_allowed": False,
        },
        "source_contract": {
            "netsniper_version": "2.1.0",
        },
        "retention_disposition": (
            "audit_metadata_only" if state == "REJECTED" else "trusted_store"
        ),
        "evaluated_at": "2026-07-17T14:00:00+00:00",
        "review_required": state in {"DEGRADED", "QUARANTINED"},
    }


def main():
    quality = load_module()
    with tempfile.TemporaryDirectory(prefix="deltaaegis-v045-storage-") as tmp:
        db = Path(tmp) / "test.db"
        connection = sqlite3.connect(db)
        connection.row_factory = sqlite3.Row
        base_schema(connection)
        before_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        require(
            before_tables == {"snapshots"},
            "v0.45 tables were not lazy before first feature use",
        )
        empty_summary = quality.quality_summary(connection)
        require(empty_summary["total"] == 0, "empty lazy ledger summary changed")
        after_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        require(
            {"telemetry_quality_decisions", "telemetry_quality_reviews"}
            <= after_tables,
            "first quality feature use did not initialize the lazy ledger",
        )

        stored = quality.persist_decision(
            connection,
            decision(quality),
            import_status="IMPORTED",
        )
        require(
            stored["automated_state"] == "DEGRADED",
            "automated state was not stored",
        )

        duplicate = quality.persist_decision(
            connection,
            decision(quality),
            import_status="IMPORTED",
        )
        require(
            duplicate["decision_id"] == stored["decision_id"],
            "same run and digest must be idempotent",
        )
        count = connection.execute(
            "SELECT COUNT(*) AS count FROM telemetry_quality_decisions"
        ).fetchone()["count"]
        require(count == 1, "idempotent decision duplicated a ledger row")

        conflict = quality.apply_run_id_conflict(
            connection,
            decision(quality, digest="b" * 64, state="ACCEPTED"),
            policy_path=POLICY,
        )
        require(
            conflict["automated_state"] == "REJECTED",
            "same run ID with different content must reject",
        )
        require(
            "run_id_hash_conflict" in conflict["reason_codes"],
            "run ID conflict reason is missing",
        )

        connection.execute(
            """
            INSERT INTO snapshots (
                scan_id, quality_status, manifest_path,
                is_accepted_baseline, bundle_digest
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                "run-legacy",
                "ACCEPTED",
                "/missing/legacy/manifest.json",
                1,
                "d" * 64,
            ),
        )
        legacy_candidate = decision(
            quality,
            digest="e" * 64,
            state="ACCEPTED",
        )
        legacy_candidate["run_id"] = "run-legacy"
        legacy_conflict = quality.apply_run_id_conflict(
            connection,
            legacy_candidate,
            policy_path=POLICY,
        )
        require(
            legacy_conflict["automated_state"] == "REJECTED",
            "pre-v0.45 snapshot run-ID collision did not fail closed",
        )
        require(
            "run_id_hash_conflict" in legacy_conflict["reason_codes"],
            "legacy run-ID conflict reason is missing",
        )

        connection.execute(
            """
            INSERT INTO snapshots (
                scan_id, quality_status, manifest_path,
                is_accepted_baseline, bundle_digest
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                "run-unverifiable",
                "ACCEPTED",
                "/missing/unverifiable/manifest.json",
                1,
                "",
            ),
        )
        unverifiable_candidate = decision(
            quality,
            digest="f" * 64,
            state="ACCEPTED",
        )
        unverifiable_candidate["run_id"] = "run-unverifiable"
        unverifiable_conflict = quality.apply_run_id_conflict(
            connection,
            unverifiable_candidate,
            policy_path=POLICY,
        )
        require(
            unverifiable_conflict["automated_state"] == "REJECTED",
            "unverifiable legacy run-ID reuse did not fail closed",
        )

        analyst = {
            "auth_type": "dashboard_session",
            "user_id": "u-analyst",
            "username": "analyst",
            "role": "ANALYST",
        }
        review = quality.record_review(
            connection,
            decision_id=stored["decision_id"],
            action="ANNOTATE",
            reason="Reviewed partial collector coverage.",
            actor=analyst,
        )
        require(
            review["resulting_state"] == "DEGRADED",
            "annotation must not mutate current state",
        )

        admin = {
            "auth_type": "dashboard_session",
            "user_id": "u-admin",
            "username": "admin",
            "role": "ADMIN",
        }
        overridden = quality.override_decision(
            connection,
            decision_id=stored["decision_id"],
            target_state="ACCEPTED",
            reason="Independent evidence confirmed collector coverage.",
            actor=admin,
            policy_path=POLICY,
        )
        require(
            overridden["decision"]["automated_state"] == "DEGRADED",
            "automated state must remain immutable after override",
        )
        require(
            overridden["decision"]["current_state"] == "ACCEPTED",
            "reviewed state was not updated",
        )
        contract = overridden["decision"]["decision_contract"]
        require(
            contract["review"]["status"] == "overridden",
            "public decision contract did not disclose override state",
        )
        require(
            contract["review"]["reviewer"] == "admin",
            "public decision contract did not disclose session reviewer",
        )
        require(
            set(contract) == set(quality.PUBLIC_DECISION_KEYS),
            "stored public decision contract has unexpected keys",
        )

        try:
            quality.override_decision(
                connection,
                decision_id=stored["decision_id"],
                target_state="QUARANTINED",
                reason="token actor",
                actor={
                    "auth_type": "api_token",
                    "username": "token",
                    "role": "ADMIN",
                },
                policy_path=POLICY,
            )
        except quality.TelemetryQualityError:
            pass
        else:
            raise SystemExit(
                "[FAIL] API token was allowed to perform quality override"
            )

        rejected = decision(quality, digest="c" * 64, state="REJECTED")
        rejected["run_id"] = "run-rejected"
        quality.persist_decision(connection, rejected, import_status="REJECTED")
        try:
            quality.override_decision(
                connection,
                decision_id=rejected["decision_id"],
                target_state="ACCEPTED",
                reason="not allowed",
                actor=admin,
                policy_path=POLICY,
            )
        except quality.TelemetryQualityError:
            pass
        else:
            raise SystemExit("[FAIL] REJECTED telemetry was overridable")

        connection.close()

    print("[PASS] v0.45 durable decision and review ledger")


if __name__ == "__main__":
    main()
