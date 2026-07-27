"""Versioned, deterministic, explainable detection results for DeltaAegis v1."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping


DETECTION_SCHEMA_VERSION = "deltaaegis-detection-result-v1"
DETECTION_REVIEW_SCHEMA_VERSION = "deltaaegis-detection-review-v1"
RULESET_ID = "deltaaegis-core-network-change"
RULESET_VERSION = "1.0.0"
REVIEW_ACTIONS = {"REVIEWED", "SUPPRESSED", "UNSUPPRESSED"}
RULE_ID_PATTERN = re.compile(r"DA-RULE-[0-9]{4}")


class DetectionError(ValueError):
    """Raised when detection or review evidence violates the v1 contract."""


RULES: dict[str, dict[str, str]] = {
    "ASSET_FIRST_OBSERVED": {
        "rule_id": "DA-RULE-0001",
        "title": "Asset first observed",
        "rationale": "A previously unseen asset entered the preserved scope evidence.",
    },
    "ASSET_REMOVED": {
        "rule_id": "DA-RULE-0002",
        "title": "Stable asset removed",
        "rationale": "A stable asset crossed the accepted absence threshold.",
    },
    "ASSET_REAPPEARED": {
        "rule_id": "DA-RULE-0003",
        "title": "Asset reappeared",
        "rationale": "A previously missing or removed asset returned.",
    },
    "MONITORED_SERVICE_OPENED": {
        "rule_id": "DA-RULE-0010",
        "title": "Monitored service opened",
        "rationale": "A monitored service is present in current evidence but absent from the baseline.",
    },
    "MONITORED_SERVICE_CLOSED": {
        "rule_id": "DA-RULE-0011",
        "title": "Monitored service closed",
        "rationale": "A monitored service present in the baseline is absent from complete current evidence.",
    },
    "NETSNIPER_FINDING_ADDED": {
        "rule_id": "DA-RULE-0020",
        "title": "Finding added",
        "rationale": "NetSniper supplied a new interpreted finding for the scoped asset.",
    },
    "NETSNIPER_FINDING_REMOVED": {
        "rule_id": "DA-RULE-0021",
        "title": "Finding removed",
        "rationale": "A prior finding is absent from complete current evidence.",
    },
    "DEVICE_CLASSIFICATION_CHANGED": {
        "rule_id": "DA-RULE-0030",
        "title": "Device classification changed",
        "rationale": "The evidence-backed device classification changed between preserved scans.",
    },
    "PROFILE_BASELINE_RESET": {
        "rule_id": "DA-RULE-0090",
        "title": "Profile baseline reset",
        "rationale": "The telemetry contract changed and established a new comparison baseline.",
    },
    "IDENTITY_BASELINE_RESET": {
        "rule_id": "DA-RULE-0091",
        "title": "Identity baseline reset",
        "rationale": "Identity coverage changed materially and established a new baseline.",
    },
    "SNAPSHOT_REVIEW_REQUIRED": {
        "rule_id": "DA-RULE-0092",
        "title": "Telemetry review required",
        "rationale": "Telemetry quality evidence requires operator review.",
    },
    "SNAPSHOT_PROFILE_CHANGED": {
        "rule_id": "DA-RULE-0093",
        "title": "Telemetry profile changed",
        "rationale": "The scan profile differs from its comparison baseline.",
    },
}


DETECTION_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS detection_results (
    result_id TEXT PRIMARY KEY,
    result_schema_version TEXT NOT NULL,
    ruleset_id TEXT NOT NULL,
    ruleset_version TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    event_type TEXT NOT NULL,
    sensor_id TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    source_scan_id TEXT NOT NULL,
    internal_scan_id TEXT NOT NULL,
    baseline_scan_id TEXT NOT NULL DEFAULT '',
    source_decision_id TEXT NOT NULL,
    source_bundle_digest TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    severity TEXT NOT NULL,
    result_state TEXT NOT NULL DEFAULT 'MATCHED',
    evidence_digest TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    explanation_json TEXT NOT NULL,
    evaluated_at TEXT NOT NULL,
    UNIQUE(scope_id, internal_scan_id, rule_id, rule_version,
           subject_key, evidence_digest),
    FOREIGN KEY(sensor_id) REFERENCES identity_sensors(sensor_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(scope_id) REFERENCES identity_scopes(scope_id)
        ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_detection_results_scope
    ON detection_results(scope_id, evaluated_at, result_id);
CREATE INDEX IF NOT EXISTS idx_detection_results_sensor
    ON detection_results(sensor_id, evaluated_at, result_id);
CREATE INDEX IF NOT EXISTS idx_detection_results_rule
    ON detection_results(rule_id, rule_version, evaluated_at);
CREATE INDEX IF NOT EXISTS idx_detection_results_scan
    ON detection_results(internal_scan_id, result_id);

CREATE TABLE IF NOT EXISTS detection_reviews (
    review_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    review_id TEXT NOT NULL UNIQUE,
    review_schema_version TEXT NOT NULL,
    result_id TEXT NOT NULL,
    action TEXT NOT NULL,
    prior_disposition TEXT NOT NULL,
    resulting_disposition TEXT NOT NULL,
    reason TEXT NOT NULL,
    actor_user_id TEXT,
    actor_username TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    actor_auth_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(result_id) REFERENCES detection_results(result_id)
        ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_detection_reviews_result
    ON detection_reviews(result_id, review_sequence);

CREATE TRIGGER IF NOT EXISTS detection_results_immutable_update
BEFORE UPDATE ON detection_results
BEGIN
    SELECT RAISE(ABORT, 'detection results are immutable');
END;

CREATE TRIGGER IF NOT EXISTS detection_results_immutable_delete
BEFORE DELETE ON detection_results
BEGIN
    SELECT RAISE(ABORT, 'detection results are immutable');
END;

CREATE TRIGGER IF NOT EXISTS detection_reviews_immutable_update
BEFORE UPDATE ON detection_reviews
BEGIN
    SELECT RAISE(ABORT, 'detection reviews are immutable');
END;

CREATE TRIGGER IF NOT EXISTS detection_reviews_immutable_delete
BEFORE DELETE ON detection_reviews
BEGIN
    SELECT RAISE(ABORT, 'detection reviews are immutable');
END;
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _execute_schema_sql(connection: sqlite3.Connection, script: str) -> None:
    statement = ""
    for line in str(script).splitlines(keepends=True):
        statement += line
        if not sqlite3.complete_statement(statement):
            continue
        sql = statement.strip()
        statement = ""
        if sql:
            connection.execute(sql)
    if statement.strip():
        raise DetectionError("incomplete detection schema SQL")


def apply_schema(connection: sqlite3.Connection) -> dict[str, Any]:
    _execute_schema_sql(connection, DETECTION_SCHEMA_SQL)
    return {
        "schema_version": DETECTION_SCHEMA_VERSION,
        "ruleset_id": RULESET_ID,
        "ruleset_version": RULESET_VERSION,
        "rule_count": len(RULES),
    }


def validate_schema(connection: sqlite3.Connection) -> None:
    tables = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type='table'"
        )
    }
    missing = {"detection_results", "detection_reviews"} - tables
    if missing:
        raise DetectionError(
            "detection schema is missing tables: " + ", ".join(sorted(missing))
        )
    triggers = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type='trigger'"
        )
    }
    required_triggers = {
        "detection_results_immutable_update",
        "detection_results_immutable_delete",
        "detection_reviews_immutable_update",
        "detection_reviews_immutable_delete",
    }
    if not required_triggers.issubset(triggers):
        raise DetectionError("detection immutability triggers are missing")
    review_columns = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(detection_reviews)")
    }
    if "review_sequence" not in review_columns:
        raise DetectionError("detection review ordering sequence is missing")
    for event_type, rule in RULES.items():
        if not RULE_ID_PATTERN.fullmatch(rule["rule_id"]):
            raise DetectionError(f"invalid rule identifier for {event_type}")


def _canonical_event(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "event_type": str(item.get("event_type") or "").strip().upper(),
        "severity": str(item.get("severity") or "INFO").strip().upper(),
        "subject_key": str(item.get("subject_key") or "").strip(),
        "previous_value": item.get("previous_value"),
        "current_value": item.get("current_value"),
        "summary": str(item.get("summary") or "").strip(),
    }


def result_for_event(
    event: Mapping[str, Any],
    *,
    identity: Mapping[str, Any],
    decision: Mapping[str, Any],
    baseline_scan_id: str | None,
) -> dict[str, Any] | None:
    canonical = _canonical_event(event)
    rule = RULES.get(canonical["event_type"])
    if rule is None:
        return None
    if not canonical["subject_key"] or not canonical["summary"]:
        raise DetectionError("detection event is missing subject or summary")
    evidence = {
        "sensor_id": str(identity["sensor_id"]),
        "scope_id": str(identity["scope_id"]),
        "network_scope": str(identity["network_scope"]),
        "source_scan_id": str(identity["source_scan_id"]),
        "internal_scan_id": str(identity["internal_scan_id"]),
        "baseline_scan_id": str(baseline_scan_id or ""),
        "source_decision_id": str(decision.get("decision_id") or ""),
        "source_bundle_digest": str(identity["bundle_digest"]),
        "quality_state": str(decision.get("current_state") or "").upper(),
        "event": canonical,
    }
    evidence_json = canonical_json(evidence)
    evidence_digest = hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
    result_material = "\0".join(
        (
            DETECTION_SCHEMA_VERSION,
            rule["rule_id"],
            RULESET_VERSION,
            str(identity["scope_id"]),
            str(identity["internal_scan_id"]),
            canonical["subject_key"],
            evidence_digest,
        )
    )
    result_id = "detection-" + hashlib.sha256(
        result_material.encode("utf-8")
    ).hexdigest()
    explanation = {
        "title": rule["title"],
        "rationale": rule["rationale"],
        "summary": canonical["summary"],
        "condition": canonical["event_type"],
        "observed": canonical["current_value"],
        "baseline": canonical["previous_value"],
        "severity_basis": canonical["severity"],
        "provenance": {
            "sensor_id": identity["sensor_id"],
            "scope_id": identity["scope_id"],
            "source_scan_id": identity["source_scan_id"],
            "bundle_digest": identity["bundle_digest"],
            "decision_id": decision.get("decision_id"),
        },
    }
    return {
        "result_id": result_id,
        "result_schema_version": DETECTION_SCHEMA_VERSION,
        "ruleset_id": RULESET_ID,
        "ruleset_version": RULESET_VERSION,
        "rule_id": rule["rule_id"],
        "rule_version": RULESET_VERSION,
        "event_type": canonical["event_type"],
        "sensor_id": identity["sensor_id"],
        "scope_id": identity["scope_id"],
        "source_scan_id": identity["source_scan_id"],
        "internal_scan_id": identity["internal_scan_id"],
        "baseline_scan_id": str(baseline_scan_id or ""),
        "source_decision_id": str(decision.get("decision_id") or ""),
        "source_bundle_digest": identity["bundle_digest"],
        "subject_key": canonical["subject_key"],
        "severity": canonical["severity"],
        "result_state": "MATCHED",
        "evidence_digest": evidence_digest,
        "evidence_json": evidence_json,
        "explanation_json": canonical_json(explanation),
        # Deterministic evidence time; never use replay wall-clock time.
        "evaluated_at": str(decision.get("evaluated_at") or ""),
    }


_RESULT_COLUMNS = (
    "result_id",
    "result_schema_version",
    "ruleset_id",
    "ruleset_version",
    "rule_id",
    "rule_version",
    "event_type",
    "sensor_id",
    "scope_id",
    "source_scan_id",
    "internal_scan_id",
    "baseline_scan_id",
    "source_decision_id",
    "source_bundle_digest",
    "subject_key",
    "severity",
    "result_state",
    "evidence_digest",
    "evidence_json",
    "explanation_json",
    "evaluated_at",
)


def persist_results(
    connection: sqlite3.Connection,
    events: Iterable[Mapping[str, Any]],
    *,
    identity: Mapping[str, Any],
    decision: Mapping[str, Any],
    baseline_scan_id: str | None,
) -> dict[str, Any]:
    generated = []
    for event in events:
        result = result_for_event(
            event,
            identity=identity,
            decision=decision,
            baseline_scan_id=baseline_scan_id,
        )
        if result is not None:
            generated.append(result)
    inserted = 0
    replayed = 0
    placeholders = ", ".join("?" for _ in _RESULT_COLUMNS)
    for result in generated:
        cursor = connection.execute(
            f"INSERT OR IGNORE INTO detection_results "
            f"({', '.join(_RESULT_COLUMNS)}) VALUES ({placeholders})",
            tuple(result[column] for column in _RESULT_COLUMNS),
        )
        if cursor.rowcount == 1:
            inserted += 1
            continue
        row = connection.execute(
            "SELECT * FROM detection_results WHERE result_id=?",
            (result["result_id"],),
        ).fetchone()
        if row is None or any(str(row[column]) != str(result[column]) for column in _RESULT_COLUMNS):
            raise DetectionError(
                f"detection result identity conflict: {result['result_id']}"
            )
        replayed += 1
    return {
        "evaluated": len(generated),
        "inserted": inserted,
        "replayed": replayed,
        "result_ids": [item["result_id"] for item in generated],
    }


def _decode_result(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    item = dict(row)
    for key in ("evidence_json", "explanation_json"):
        item[key.removesuffix("_json")] = json.loads(str(item.pop(key) or "{}"))
    latest = item.pop("latest_review", None)
    item["disposition"] = str(latest or "OPEN")
    return item


def result_by_id(connection: sqlite3.Connection, result_id: Any) -> dict[str, Any]:
    key = str(result_id or "").strip()
    row = connection.execute(
        """
        SELECT d.*, COALESCE((
            SELECT resulting_disposition FROM detection_reviews r
            WHERE r.result_id=d.result_id
            ORDER BY r.review_sequence DESC LIMIT 1
        ), 'OPEN') AS latest_review
        FROM detection_results d WHERE d.result_id=?
        """,
        (key,),
    ).fetchone()
    if row is None:
        raise DetectionError(f"detection result not found: {key}")
    item = _decode_result(row)
    reviews = connection.execute(
        "SELECT * FROM detection_reviews WHERE result_id=? "
        "ORDER BY review_sequence",
        (key,),
    ).fetchall()
    item["reviews"] = [dict(review) for review in reviews]
    return item


def list_results(
    connection: sqlite3.Connection,
    *,
    sensor_id: str | None = None,
    scope_id: str | None = None,
    disposition: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if sensor_id:
        clauses.append("d.sensor_id=?")
        params.append(str(sensor_id).strip().lower())
    if scope_id:
        clauses.append("d.scope_id=?")
        params.append(str(scope_id).strip().lower())
    normalized_disposition = str(disposition or "").strip().upper()
    disposition_sql = (
        "COALESCE((SELECT resulting_disposition FROM detection_reviews r "
        "WHERE r.result_id=d.result_id ORDER BY r.review_sequence DESC "
        "LIMIT 1), 'OPEN')"
    )
    if normalized_disposition:
        clauses.append(f"{disposition_sql}=?")
        params.append(normalized_disposition)
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    params.extend((max(1, min(int(limit), 1000)), max(0, int(offset))))
    rows = connection.execute(
        f"""
        SELECT d.*, {disposition_sql} AS latest_review
        FROM detection_results d
        {where}
        ORDER BY d.evaluated_at DESC, d.result_id DESC
        LIMIT ? OFFSET ?
        """,
        tuple(params),
    ).fetchall()
    return [_decode_result(row) for row in rows]


def review_result(
    connection: sqlite3.Connection,
    *,
    result_id: Any,
    action: Any,
    reason: Any,
    actor: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(actor, Mapping) or not str(
        actor.get("user_id") or actor.get("token_id") or actor.get("session_id") or ""
    ).strip():
        raise DetectionError("detection review requires an authenticated actor")
    key = str(result_id or "").strip()
    normalized_action = str(action or "").strip().upper()
    if normalized_action not in REVIEW_ACTIONS:
        raise DetectionError(
            "detection review action must be REVIEWED, SUPPRESSED, or UNSUPPRESSED"
        )
    normalized_reason = str(reason or "").strip()
    if not normalized_reason or len(normalized_reason) > 2000:
        raise DetectionError("detection review reason must contain 1-2000 characters")
    current = result_by_id(connection, key)
    prior = str(current["disposition"])
    resulting = {
        "REVIEWED": "REVIEWED",
        "SUPPRESSED": "SUPPRESSED",
        "UNSUPPRESSED": "OPEN",
    }[normalized_action]
    if normalized_action == "UNSUPPRESSED" and prior != "SUPPRESSED":
        raise DetectionError("only a suppressed result can be unsuppressed")
    now = utc_now()
    review_id = "dreview-" + uuid.uuid4().hex
    connection.execute(
        """
        INSERT INTO detection_reviews (
            review_id, review_schema_version, result_id, action,
            prior_disposition, resulting_disposition, reason,
            actor_user_id, actor_username, actor_role, actor_auth_type,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            review_id,
            DETECTION_REVIEW_SCHEMA_VERSION,
            key,
            normalized_action,
            prior,
            resulting,
            normalized_reason,
            actor.get("user_id"),
            str(actor.get("username") or actor.get("token_name") or "api-token"),
            str(actor.get("role") or ""),
            str(actor.get("auth_type") or ""),
            now,
        ),
    )
    return result_by_id(connection, key)


def rules_contract() -> dict[str, Any]:
    return {
        "schema_version": "deltaaegis-detection-rules-v1",
        "ruleset_id": RULESET_ID,
        "ruleset_version": RULESET_VERSION,
        "rules": [
            {
                "event_type": event_type,
                "rule_id": rule["rule_id"],
                "rule_version": RULESET_VERSION,
                "title": rule["title"],
                "rationale": rule["rationale"],
            }
            for event_type, rule in sorted(RULES.items())
        ],
    }


__all__ = (
    "DETECTION_REVIEW_SCHEMA_VERSION",
    "DETECTION_SCHEMA_SQL",
    "DETECTION_SCHEMA_VERSION",
    "DetectionError",
    "RULES",
    "RULESET_ID",
    "RULESET_VERSION",
    "apply_schema",
    "list_results",
    "persist_results",
    "result_by_id",
    "result_for_event",
    "review_result",
    "rules_contract",
    "validate_schema",
)
