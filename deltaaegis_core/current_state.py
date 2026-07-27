"""DeltaAegis v0.45 replayable current-state projection.

Immutable snapshot/observation rows remain the historical evidence ledger.  This
module owns the operational projection that combines ACCEPTED evidence with
positive-only DEGRADED evidence while preventing absence mutation by degraded
runs.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from typing import Any


REMOVAL_THRESHOLD = 3


def _numeric_ip_sort_key(value: Any) -> tuple[Any, ...]:
    raw = str(value or "").strip()
    try:
        parsed = ipaddress.ip_address(raw)
        return (0, parsed.version, int(parsed))
    except ValueError:
        return (1, 0, raw.casefold())


def _execute_schema_sql(connection: sqlite3.Connection, script: str) -> None:
    """Execute DDL without sqlite3.executescript's implicit transaction commit."""

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
        raise ValueError("incomplete current-state schema SQL")


PROJECTION_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS telemetry_current_assets (
    network_scope TEXT NOT NULL,
    asset_key TEXT NOT NULL,
    source_scan_id TEXT NOT NULL,
    source_decision_id TEXT NOT NULL,
    source_quality_state TEXT NOT NULL,
    accepted_evidence_seen INTEGER NOT NULL DEFAULT 0,
    accepted_score INTEGER,
    observed_at TEXT NOT NULL,
    identity_class TEXT NOT NULL DEFAULT 'IP_ONLY',
    identity_confidence TEXT,
    identity_source TEXT,
    ip_address TEXT NOT NULL DEFAULT '',
    mac_address TEXT,
    vendor TEXT,
    hostname TEXT,
    device_type TEXT,
    device_type_confidence INTEGER,
    classification_type TEXT,
    classification_primary_type TEXT,
    classification_confidence INTEGER,
    classification_confidence_label TEXT,
    classification_decision TEXT,
    classification_method TEXT,
    classification_json TEXT NOT NULL DEFAULT '{}',
    classification_evidence_json TEXT NOT NULL DEFAULT '[]',
    classification_contradictions_json TEXT NOT NULL DEFAULT '[]',
    classification_candidates_json TEXT NOT NULL DEFAULT '[]',
    classification_confidence_band TEXT,
    classification_calibrated_decision TEXT,
    classification_siem_action TEXT,
    classification_calibration_reason TEXT,
    classification_validation_state TEXT,
    classification_contradiction_count INTEGER,
    classification_validator_summary_json TEXT NOT NULL DEFAULT '{}',
    classification_validators_json TEXT NOT NULL DEFAULT '[]',
    severity TEXT,
    score INTEGER,
    PRIMARY KEY(network_scope, asset_key)
);

CREATE INDEX IF NOT EXISTS idx_telemetry_current_assets_scan
    ON telemetry_current_assets(source_scan_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_current_assets_ip
    ON telemetry_current_assets(network_scope, ip_address);

CREATE TABLE IF NOT EXISTS telemetry_current_services (
    network_scope TEXT NOT NULL,
    asset_key TEXT NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    state TEXT NOT NULL,
    service_name TEXT,
    product TEXT,
    version TEXT,
    source_scan_id TEXT NOT NULL,
    source_decision_id TEXT NOT NULL,
    source_quality_state TEXT NOT NULL,
    accepted_evidence_seen INTEGER NOT NULL DEFAULT 0,
    observed_at TEXT NOT NULL,
    PRIMARY KEY(network_scope, asset_key, protocol, port)
);

CREATE INDEX IF NOT EXISTS idx_telemetry_current_services_scan
    ON telemetry_current_services(source_scan_id);

CREATE TABLE IF NOT EXISTS telemetry_current_findings (
    network_scope TEXT NOT NULL,
    asset_key TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT -1,
    name TEXT,
    service TEXT,
    score INTEGER,
    evidence TEXT,
    source_scan_id TEXT NOT NULL,
    source_decision_id TEXT NOT NULL,
    source_quality_state TEXT NOT NULL,
    accepted_evidence_seen INTEGER NOT NULL DEFAULT 0,
    observed_at TEXT NOT NULL,
    PRIMARY KEY(network_scope, asset_key, finding_id, port)
);

CREATE INDEX IF NOT EXISTS idx_telemetry_current_findings_scan
    ON telemetry_current_findings(source_scan_id);
"""


CLASSIFICATION_FIELDS = (
    "device_type",
    "device_type_confidence",
    "classification_type",
    "classification_primary_type",
    "classification_confidence",
    "classification_confidence_label",
    "classification_decision",
    "classification_method",
    "classification_json",
    "classification_evidence_json",
    "classification_contradictions_json",
    "classification_candidates_json",
    "classification_confidence_band",
    "classification_calibrated_decision",
    "classification_siem_action",
    "classification_calibration_reason",
    "classification_validation_state",
    "classification_contradiction_count",
    "classification_validator_summary_json",
    "classification_validators_json",
    "severity",
    "score",
)


def ensure_schema(connection: sqlite3.Connection) -> None:
    _execute_schema_sql(connection, PROJECTION_SCHEMA_SQL)
    existing = {
        str(row[1])
        for row in connection.execute(
            "PRAGMA table_info(telemetry_current_assets)"
        ).fetchall()
    }
    if "accepted_score" not in existing:
        connection.execute(
            "ALTER TABLE telemetry_current_assets "
            "ADD COLUMN accepted_score INTEGER"
        )

def ensure_ready(connection: sqlite3.Connection) -> int:
    """Initialize v0.45 projection storage and seed legacy accepted state lazily."""

    ensure_schema(connection)
    return bootstrap_legacy_projection(connection)


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    try:
        decoded = json.loads(value or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _json_array(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    try:
        decoded = json.loads(value or "[]")
    except (TypeError, json.JSONDecodeError):
        return []
    return decoded if isinstance(decoded, list) else []


def _value(item: Any, name: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def _scope(snapshot: Any) -> str:
    value = _value(snapshot, "network_scope")
    if value:
        return str(value)
    return str(_value(snapshot, "target") or "")


def _asset_mapping(asset: Any) -> dict[str, Any]:
    item = {
        "asset_key": _value(asset, "asset_key"),
        "identity_class": _value(asset, "identity_class", "IP_ONLY"),
        "identity_confidence": _value(asset, "identity_confidence"),
        "identity_source": _value(asset, "identity_source"),
        "ip_address": _value(asset, "ip_address", ""),
        "mac_address": _value(asset, "mac_address"),
        "vendor": _value(asset, "vendor"),
        "hostname": _value(asset, "hostname"),
    }
    for name in CLASSIFICATION_FIELDS:
        item[name] = _value(asset, name)
    for name, default in (
        ("classification_json", "{}"),
        ("classification_evidence_json", "[]"),
        ("classification_contradictions_json", "[]"),
        ("classification_candidates_json", "[]"),
        ("classification_validator_summary_json", "{}"),
        ("classification_validators_json", "[]"),
    ):
        if item.get(name) is None:
            item[name] = default
    return item


def _decision_rank(value: Any) -> int:
    clean = str(value or "").strip().lower()
    return {
        "classified": 5,
        "confirmed": 5,
        "high_confidence": 5,
        "probable": 4,
        "possible": 3,
        "review": 2,
        "ambiguous": 2,
        "unknown": 1,
        "": 0,
    }.get(clean, 1)


def _validation_rank(value: Any) -> int:
    clean = str(value or "").strip().lower()
    return {
        "confirmed": 5,
        "validated": 5,
        "supported": 4,
        "consistent": 4,
        "not_applicable": 3,
        "unverified": 2,
        "review": 1,
        "contradicted": 0,
        "": 2,
    }.get(clean, 2)


def _operator_disposition(mapping: dict[str, Any]) -> str:
    classification = _json_object(mapping.get("classification_json"))
    context = _json_object(classification.get("deltaaegis_context"))
    disposition = context.get("operator_disposition")
    if isinstance(disposition, dict):
        disposition = (
            disposition.get("action")
            or disposition.get("disposition")
            or disposition.get("state")
        )
    return str(disposition or "").strip().lower()


def _semantic_fingerprint(mapping: dict[str, Any]) -> str:
    classification = _json_object(mapping.get("classification_json"))
    context = _json_object(classification.get("deltaaegis_context"))
    return str(
        context.get("semantic_fingerprint")
        or classification.get("semantic_fingerprint")
        or ""
    ).strip()


def _classification_tuple(mapping: dict[str, Any]) -> tuple[int, int, int, int, int]:
    evidence_count = len(_json_array(mapping.get("classification_evidence_json")))
    contradictions = mapping.get("classification_contradiction_count")
    try:
        contradiction_count = int(contradictions or 0)
    except (TypeError, ValueError):
        contradiction_count = len(
            _json_array(mapping.get("classification_contradictions_json"))
        )
    try:
        confidence = int(mapping.get("classification_confidence") or 0)
    except (TypeError, ValueError):
        confidence = 0
    return (
        _decision_rank(
            mapping.get("classification_calibrated_decision")
            or mapping.get("classification_decision")
        ),
        confidence,
        evidence_count,
        -contradiction_count,
        _validation_rank(mapping.get("classification_validation_state")),
    )


def degraded_classification_is_stronger(
    existing: dict[str, Any],
    candidate: dict[str, Any],
) -> bool:
    """Apply the approved strictly-stronger degraded classification rule."""

    disposition = _operator_disposition(candidate)
    if disposition in {
        "review_only",
        "display_only",
        "no_action",
        "hold",
        "manual_review",
    }:
        return False

    old_fingerprint = _semantic_fingerprint(existing)
    new_fingerprint = _semantic_fingerprint(candidate)
    if not new_fingerprint:
        return False
    if old_fingerprint and new_fingerprint == old_fingerprint:
        return False

    old_tuple = _classification_tuple(existing)
    new_tuple = _classification_tuple(candidate)
    return (
        new_tuple[0] > old_tuple[0]
        and new_tuple[1] > old_tuple[1]
        and new_tuple[2] >= old_tuple[2]
        and new_tuple[3] >= old_tuple[3]
        and new_tuple[4] >= old_tuple[4]
    )


def _current_asset(
    connection: sqlite3.Connection,
    scope: str,
    asset_key: str,
) -> dict[str, Any] | None:
    row = connection.execute(
        "SELECT * FROM telemetry_current_assets "
        "WHERE network_scope = ? AND asset_key = ?",
        (scope, asset_key),
    ).fetchone()
    return dict(row) if row is not None else None


def _preserve_classification(
    candidate: dict[str, Any],
    existing: dict[str, Any],
) -> dict[str, Any]:
    output = dict(candidate)
    for name in CLASSIFICATION_FIELDS:
        output[name] = existing.get(name)
    return output


def _upsert_lifecycle_positive(
    connection: sqlite3.Connection,
    *,
    scope: str,
    scan_id: str,
    observed_at: str,
    asset: dict[str, Any],
) -> None:
    row = connection.execute(
        "SELECT 1 FROM asset_lifecycle "
        "WHERE network_scope = ? AND asset_key = ?",
        (scope, asset["asset_key"]),
    ).fetchone()
    if row is None:
        connection.execute(
            """
            INSERT INTO asset_lifecycle (
                network_scope, asset_key, identity_class, state,
                missing_count, current_ip, mac_address, vendor, hostname,
                first_seen_scan_id, last_seen_scan_id, first_seen_at,
                last_seen_at, removed_at
            ) VALUES (?, ?, ?, 'ACTIVE', 0, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                scope,
                asset["asset_key"],
                asset.get("identity_class") or "IP_ONLY",
                asset.get("ip_address") or "",
                asset.get("mac_address"),
                asset.get("vendor"),
                asset.get("hostname"),
                scan_id,
                scan_id,
                observed_at,
                observed_at,
            ),
        )
    else:
        connection.execute(
            """
            UPDATE asset_lifecycle
            SET identity_class = ?,
                state = 'ACTIVE',
                missing_count = 0,
                current_ip = ?,
                mac_address = ?,
                vendor = ?,
                hostname = ?,
                last_seen_scan_id = ?,
                last_seen_at = ?,
                removed_at = NULL
            WHERE network_scope = ? AND asset_key = ?
            """,
            (
                asset.get("identity_class") or "IP_ONLY",
                asset.get("ip_address") or "",
                asset.get("mac_address"),
                asset.get("vendor"),
                asset.get("hostname"),
                scan_id,
                observed_at,
                scope,
                asset["asset_key"],
            ),
        )


def _apply_lifecycle_absence(
    connection: sqlite3.Connection,
    *,
    scope: str,
    current_keys: set[str],
    observed_at: str,
) -> None:
    """Rebuild accepted absence state without generating retroactive events."""

    rows = connection.execute(
        "SELECT * FROM asset_lifecycle WHERE network_scope = ?",
        (scope,),
    ).fetchall()
    for raw_row in rows:
        row = dict(raw_row)
        asset_key = str(row.get("asset_key") or "")
        if not asset_key or asset_key in current_keys:
            continue
        missing_count = int(row.get("missing_count") or 0) + 1
        identity_class = str(
            row.get("identity_class") or "IP_ONLY"
        ).upper()
        prior_state = str(row.get("state") or "ACTIVE").upper()
        removed_at = row.get("removed_at")
        if identity_class == "LOCAL_MAC":
            state = "EPHEMERAL_MISSING"
        elif identity_class == "GLOBAL_MAC":
            if prior_state == "REMOVED" or missing_count >= REMOVAL_THRESHOLD:
                state = "REMOVED"
                removed_at = removed_at or observed_at
            else:
                state = "MISSING"
        else:
            state = "MISSING"
        connection.execute(
            """
            UPDATE asset_lifecycle
            SET state = ?,
                missing_count = ?,
                removed_at = ?
            WHERE network_scope = ? AND asset_key = ?
            """,
            (
                state,
                missing_count,
                removed_at,
                scope,
                asset_key,
            ),
        )
def _upsert_asset(
    connection: sqlite3.Connection,
    *,
    scope: str,
    scan_id: str,
    decision_id: str,
    state: str,
    observed_at: str,
    asset: dict[str, Any],
    update_lifecycle: bool,
) -> None:
    existing = _current_asset(connection, scope, str(asset["asset_key"]))
    accepted_seen = state == "ACCEPTED"
    candidate = dict(asset)

    if existing:
        accepted_seen = accepted_seen or bool(
            existing.get("accepted_evidence_seen")
        )
        if state == "DEGRADED" and not degraded_classification_is_stronger(
            existing,
            candidate,
        ):
            candidate = _preserve_classification(candidate, existing)

    if state == "ACCEPTED":
        accepted_score = candidate.get("score")
    elif existing is not None:
        accepted_score = existing.get("accepted_score")
    else:
        accepted_score = None

    columns = [
        "network_scope",
        "asset_key",
        "source_scan_id",
        "source_decision_id",
        "source_quality_state",
        "accepted_evidence_seen",
        "accepted_score",
        "observed_at",
        "identity_class",
        "identity_confidence",
        "identity_source",
        "ip_address",
        "mac_address",
        "vendor",
        "hostname",
        *CLASSIFICATION_FIELDS,
    ]
    values = [
        scope,
        candidate["asset_key"],
        scan_id,
        decision_id,
        state,
        1 if accepted_seen else 0,
        accepted_score,
        observed_at,
        candidate.get("identity_class") or "IP_ONLY",
        candidate.get("identity_confidence"),
        candidate.get("identity_source"),
        candidate.get("ip_address") or "",
        candidate.get("mac_address"),
        candidate.get("vendor"),
        candidate.get("hostname"),
        *[candidate.get(name) for name in CLASSIFICATION_FIELDS],
    ]
    updates = ", ".join(
        f"{column}=excluded.{column}"
        for column in columns
        if column not in {"network_scope", "asset_key"}
    )
    placeholders = ", ".join("?" for _ in columns)
    connection.execute(
        f"""
        INSERT INTO telemetry_current_assets ({", ".join(columns)})
        VALUES ({placeholders})
        ON CONFLICT(network_scope, asset_key) DO UPDATE SET {updates}
        """,
        values,
    )
    if update_lifecycle:
        _upsert_lifecycle_positive(
            connection,
            scope=scope,
            scan_id=scan_id,
            observed_at=observed_at,
            asset=candidate,
        )


def _upsert_service(
    connection: sqlite3.Connection,
    *,
    scope: str,
    asset_key: str,
    service: Any,
    scan_id: str,
    decision_id: str,
    state: str,
    accepted_seen: bool,
    observed_at: str,
) -> None:
    connection.execute(
        """
        INSERT INTO telemetry_current_services (
            network_scope, asset_key, protocol, port, state,
            service_name, product, version, source_scan_id,
            source_decision_id, source_quality_state,
            accepted_evidence_seen, observed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(network_scope, asset_key, protocol, port) DO UPDATE SET
            state=excluded.state,
            service_name=excluded.service_name,
            product=excluded.product,
            version=excluded.version,
            source_scan_id=excluded.source_scan_id,
            source_decision_id=excluded.source_decision_id,
            source_quality_state=excluded.source_quality_state,
            accepted_evidence_seen=MAX(
                telemetry_current_services.accepted_evidence_seen,
                excluded.accepted_evidence_seen
            ),
            observed_at=excluded.observed_at
        """,
        (
            scope,
            asset_key,
            str(_value(service, "protocol") or "tcp"),
            int(_value(service, "port") or 0),
            str(_value(service, "state") or "open"),
            _value(service, "service_name"),
            _value(service, "product"),
            _value(service, "version"),
            scan_id,
            decision_id,
            state,
            1 if accepted_seen else 0,
            observed_at,
        ),
    )


def _upsert_finding(
    connection: sqlite3.Connection,
    *,
    scope: str,
    asset_key: str,
    finding: dict[str, Any],
    scan_id: str,
    decision_id: str,
    state: str,
    accepted_seen: bool,
    observed_at: str,
) -> None:
    finding_id = str(
        finding.get("finding_id")
        or finding.get("id")
        or "UNKNOWN"
    )
    try:
        port = int(finding.get("port", -1))
    except (TypeError, ValueError):
        port = -1
    connection.execute(
        """
        INSERT INTO telemetry_current_findings (
            network_scope, asset_key, finding_id, port, name,
            service, score, evidence, source_scan_id,
            source_decision_id, source_quality_state,
            accepted_evidence_seen, observed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(network_scope, asset_key, finding_id, port) DO UPDATE SET
            name=excluded.name,
            service=excluded.service,
            score=excluded.score,
            evidence=excluded.evidence,
            source_scan_id=excluded.source_scan_id,
            source_decision_id=excluded.source_decision_id,
            source_quality_state=excluded.source_quality_state,
            accepted_evidence_seen=MAX(
                telemetry_current_findings.accepted_evidence_seen,
                excluded.accepted_evidence_seen
            ),
            observed_at=excluded.observed_at
        """,
        (
            scope,
            asset_key,
            finding_id,
            port,
            finding.get("name"),
            finding.get("service"),
            finding.get("score"),
            finding.get("evidence"),
            scan_id,
            decision_id,
            state,
            1 if accepted_seen else 0,
            observed_at,
        ),
    )


def snapshot_is_historical(
    connection: sqlite3.Connection,
    *,
    scope: str,
    created_at: str,
    scan_id: str,
) -> bool:
    """Return true when a newer imported snapshot already owns the scope."""

    row = connection.execute(
        """
        SELECT s.created_at, s.scan_id
        FROM snapshots s
        LEFT JOIN telemetry_quality_decisions q
          ON q.decision_id = s.quality_decision_id
        WHERE s.network_scope = ?
          AND (
                (s.quality_decision_id IS NULL AND s.quality_status = 'ACCEPTED')
                OR
                (
                    s.quality_decision_id IS NOT NULL
                    AND q.current_state IN ('ACCEPTED', 'DEGRADED')
                    AND q.import_status IN ('IMPORTED', 'ALREADY_IMPORTED')
                )
          )
        ORDER BY s.created_at DESC, s.imported_at DESC, s.scan_id DESC
        LIMIT 1
        """,
        (scope,),
    ).fetchone()
    if row is None:
        return False
    existing = (str(row["created_at"] or ""), str(row["scan_id"] or ""))
    incoming = (str(created_at or ""), str(scan_id or ""))
    return incoming < existing


def apply_snapshot(
    connection: sqlite3.Connection,
    snapshot: Any,
    decision: dict[str, Any],
    *,
    update_lifecycle: bool = True,
) -> dict[str, int]:
    """Apply ACCEPTED or positive-only DEGRADED evidence to the projection."""

    ensure_schema(connection)
    state = str(decision.get("current_state") or "").upper()
    if state not in {"ACCEPTED", "DEGRADED"}:
        return {"assets": 0, "services": 0, "findings": 0, "deleted": 0}

    scope = _scope(snapshot)
    scan_id = str(_value(snapshot, "scan_id") or "")
    observed_at = str(_value(snapshot, "created_at") or "")
    decision_id = str(decision.get("decision_id") or "")
    assets_value = _value(snapshot, "assets", {})
    assets = (
        list(assets_value.values())
        if isinstance(assets_value, dict)
        else list(assets_value or [])
    )
    current_keys = {
        str(_value(asset, "asset_key") or "")
        for asset in assets
        if _value(asset, "asset_key")
    }
    deleted = 0

    negative_allowed = bool(
        _json_object(decision.get("coverage_capabilities")).get(
            "negative_evidence_allowed"
        )
    )
    if state == "ACCEPTED" and negative_allowed:
        if update_lifecycle:
            _apply_lifecycle_absence(
                connection,
                scope=scope,
                current_keys=current_keys,
                observed_at=observed_at,
            )
        existing = {
            str(row["asset_key"])
            for row in connection.execute(
                "SELECT asset_key FROM telemetry_current_assets "
                "WHERE network_scope = ?",
                (scope,),
            ).fetchall()
        }
        missing = existing - current_keys
        for asset_key in sorted(missing):
            connection.execute(
                "DELETE FROM telemetry_current_findings "
                "WHERE network_scope = ? AND asset_key = ?",
                (scope, asset_key),
            )
            connection.execute(
                "DELETE FROM telemetry_current_services "
                "WHERE network_scope = ? AND asset_key = ?",
                (scope, asset_key),
            )
            connection.execute(
                "DELETE FROM telemetry_current_assets "
                "WHERE network_scope = ? AND asset_key = ?",
                (scope, asset_key),
            )
            deleted += 1

    service_count = 0
    finding_count = 0
    for raw_asset in assets:
        asset = _asset_mapping(raw_asset)
        asset_key = str(asset.get("asset_key") or "")
        if not asset_key:
            continue
        _upsert_asset(
            connection,
            scope=scope,
            scan_id=scan_id,
            decision_id=decision_id,
            state=state,
            observed_at=observed_at,
            asset=asset,
            update_lifecycle=update_lifecycle,
        )
        current = _current_asset(connection, scope, asset_key) or {}
        accepted_seen = bool(current.get("accepted_evidence_seen"))

        services = list(_value(raw_asset, "services", []) or [])
        if state == "ACCEPTED" and negative_allowed:
            observed_pairs = {
                (
                    str(_value(service, "protocol") or "tcp"),
                    int(_value(service, "port") or 0),
                )
                for service in services
            }
            rows = connection.execute(
                "SELECT protocol, port FROM telemetry_current_services "
                "WHERE network_scope = ? AND asset_key = ?",
                (scope, asset_key),
            ).fetchall()
            for row in rows:
                pair = (str(row["protocol"]), int(row["port"]))
                if pair not in observed_pairs:
                    connection.execute(
                        "DELETE FROM telemetry_current_services "
                        "WHERE network_scope = ? AND asset_key = ? "
                        "AND protocol = ? AND port = ?",
                        (scope, asset_key, pair[0], pair[1]),
                    )

        for service in services:
            _upsert_service(
                connection,
                scope=scope,
                asset_key=asset_key,
                service=service,
                scan_id=scan_id,
                decision_id=decision_id,
                state=state,
                accepted_seen=(state == "ACCEPTED"),
                observed_at=observed_at,
            )
            service_count += 1

        findings = [
            item
            for item in list(_value(raw_asset, "findings", []) or [])
            if isinstance(item, dict)
        ]
        if state == "ACCEPTED" and negative_allowed:
            observed_findings = {
                (
                    str(
                        item.get("finding_id")
                        or item.get("id")
                        or "UNKNOWN"
                    ),
                    int(item.get("port", -1) or -1),
                )
                for item in findings
            }
            rows = connection.execute(
                "SELECT finding_id, port FROM telemetry_current_findings "
                "WHERE network_scope = ? AND asset_key = ?",
                (scope, asset_key),
            ).fetchall()
            for row in rows:
                pair = (str(row["finding_id"]), int(row["port"]))
                if pair not in observed_findings:
                    connection.execute(
                        "DELETE FROM telemetry_current_findings "
                        "WHERE network_scope = ? AND asset_key = ? "
                        "AND finding_id = ? AND port = ?",
                        (scope, asset_key, pair[0], pair[1]),
                    )

        for finding in findings:
            _upsert_finding(
                connection,
                scope=scope,
                asset_key=asset_key,
                finding=finding,
                scan_id=scan_id,
                decision_id=decision_id,
                state=state,
                accepted_seen=(state == "ACCEPTED"),
                observed_at=observed_at,
            )
            finding_count += 1

    return {
        "assets": len(current_keys),
        "services": service_count,
        "findings": finding_count,
        "deleted": deleted,
    }


def _db_asset_rows(
    connection: sqlite3.Connection,
    scan_id: str,
) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    for row in connection.execute(
        "SELECT * FROM asset_observations WHERE scan_id = ?",
        (scan_id,),
    ).fetchall():
        item = dict(row)
        item["services"] = [
            dict(service)
            for service in connection.execute(
                "SELECT * FROM service_observations "
                "WHERE scan_id = ? AND asset_key = ?",
                (scan_id, row["asset_key"]),
            ).fetchall()
        ]
        item["findings"] = [
            dict(finding)
            for finding in connection.execute(
                "SELECT * FROM finding_observations "
                "WHERE scan_id = ? AND asset_key = ?",
                (scan_id, row["asset_key"]),
            ).fetchall()
        ]
        assets.append(item)
    return assets


def apply_scan_from_db(
    connection: sqlite3.Connection,
    *,
    scan_id: str,
    decision: dict[str, Any],
    update_lifecycle: bool = True,
) -> dict[str, int]:
    snapshot_row = connection.execute(
        "SELECT * FROM snapshots WHERE scan_id = ?",
        (scan_id,),
    ).fetchone()
    if snapshot_row is None:
        return {"assets": 0, "services": 0, "findings": 0, "deleted": 0}
    snapshot = dict(snapshot_row)
    snapshot["assets"] = {
        item["asset_key"]: item
        for item in _db_asset_rows(connection, scan_id)
    }
    return apply_snapshot(
        connection,
        snapshot,
        decision,
        update_lifecycle=update_lifecycle,
    )


def replay_scope(
    connection: sqlite3.Connection,
    scope: str,
) -> dict[str, int]:
    """Rebuild projection and lifecycle state from the legacy seed plus v0.45 ledger."""

    ensure_schema(connection)
    connection.execute(
        "DELETE FROM telemetry_current_findings WHERE network_scope = ?",
        (scope,),
    )
    connection.execute(
        "DELETE FROM telemetry_current_services WHERE network_scope = ?",
        (scope,),
    )
    connection.execute(
        "DELETE FROM telemetry_current_assets WHERE network_scope = ?",
        (scope,),
    )
    connection.execute(
        "DELETE FROM asset_lifecycle WHERE network_scope = ?",
        (scope,),
    )

    totals = {"assets": 0, "services": 0, "findings": 0, "deleted": 0}
    legacy = connection.execute(
        """
        SELECT *
        FROM snapshots
        WHERE network_scope = ?
          AND quality_status = 'ACCEPTED'
          AND quality_decision_id IS NULL
        ORDER BY created_at DESC, imported_at DESC, scan_id DESC
        LIMIT 1
        """,
        (scope,),
    ).fetchone()
    if legacy is not None:
        legacy_scan_id = str(legacy["scan_id"])
        seed = apply_scan_from_db(
            connection,
            scan_id=legacy_scan_id,
            decision={
                "decision_id": f"legacy:{legacy_scan_id}",
                "current_state": "ACCEPTED",
                "coverage_capabilities": {
                    "negative_evidence_allowed": True,
                },
            },
            update_lifecycle=True,
        )
        for key, value in seed.items():
            totals[key] += int(value)

    decisions = connection.execute(
        """
        SELECT q.*, s.scan_id AS snapshot_scan_id,
               s.created_at AS snapshot_created_at,
               s.imported_at AS snapshot_imported_at
        FROM telemetry_quality_decisions q
        JOIN snapshots s ON s.quality_decision_id = q.decision_id
        WHERE q.network_scope = ?
          AND q.current_state IN ('ACCEPTED', 'DEGRADED')
          AND q.import_status IN ('IMPORTED', 'ALREADY_IMPORTED')
        ORDER BY s.created_at, s.imported_at, s.scan_id, q.decision_id
        """,
        (scope,),
    ).fetchall()
    for row in decisions:
        decision = dict(row)
        decision["coverage_capabilities"] = _json_object(
            decision.get("coverage_json")
        )
        result = apply_scan_from_db(
            connection,
            scan_id=str(decision["snapshot_scan_id"]),
            decision=decision,
            update_lifecycle=True,
        )
        for key, value in result.items():
            totals[key] += int(value)
    return totals


def bootstrap_legacy_projection(connection: sqlite3.Connection) -> int:
    ensure_schema(connection)
    existing = connection.execute(
        "SELECT COUNT(*) AS count FROM telemetry_current_assets"
    ).fetchone()
    if existing is not None and int(existing["count"] or 0) > 0:
        return 0
    try:
        scopes = connection.execute(
            "SELECT DISTINCT network_scope FROM snapshots "
            "WHERE quality_status = 'ACCEPTED' "
            "AND network_scope IS NOT NULL AND network_scope != ''"
        ).fetchall()
    except sqlite3.Error:
        return 0
    count = 0
    for scope_row in scopes:
        scope = str(scope_row["network_scope"])
        snapshot = connection.execute(
            """
            SELECT *
            FROM snapshots
            WHERE network_scope = ? AND quality_status = 'ACCEPTED'
            ORDER BY created_at DESC, imported_at DESC
            LIMIT 1
            """,
            (scope,),
        ).fetchone()
        if snapshot is None:
            continue
        scan_id = str(snapshot["scan_id"])
        decision = {
            "decision_id": f"legacy:{scan_id}",
            "current_state": "ACCEPTED",
            "coverage_capabilities": {
                "negative_evidence_allowed": True,
            },
        }
        result = apply_scan_from_db(
            connection,
            scan_id=scan_id,
            decision=decision,
            update_lifecycle=False,
        )
        count += int(result["assets"])
    return count


def current_assets(
    connection: sqlite3.Connection,
    *,
    scope: str | None = None,
    limit: int = 10000,
) -> list[dict[str, Any]]:
    ensure_ready(connection)
    ensure_schema(connection)
    requested_limit = max(1, min(int(limit), 10000))
    params: list[Any] = []
    where = ""
    if scope:
        where = " WHERE network_scope = ?"
        params.append(scope)
    rows = connection.execute(
        "SELECT * FROM telemetry_current_assets"
        + where
        + " ORDER BY network_scope, asset_key LIMIT ?",
        (*params, 10000),
    ).fetchall()
    output = [dict(row) for row in rows]
    output.sort(
        key=lambda item: (
            str(item.get("network_scope") or ""),
            _numeric_ip_sort_key(item.get("ip_address")),
            str(item.get("asset_key") or ""),
        )
    )
    return output[:requested_limit]


def merge_asset_rows(
    connection: sqlite3.Connection,
    rows: list[dict[str, Any]],
    *,
    scope: str | None = None,
    state: str | None = None,
    identity: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    projected = current_assets(
        connection,
        scope=scope,
        limit=10000,
    )
    by_key = {
        (str(item.get("network_scope") or ""), str(item.get("asset_key") or "")): item
        for item in rows or []
    }
    for item in projected:
        key = (str(item["network_scope"]), str(item["asset_key"]))
        existing = by_key.get(key, {})
        merged = dict(existing)
        merged.update(
            {
                "network_scope": item["network_scope"],
                "asset_key": item["asset_key"],
                "state": existing.get("state") or "ACTIVE",
                "current_ip": item["ip_address"],
                "ip_address": item["ip_address"],
                "mac_address": item["mac_address"],
                "vendor": item["vendor"],
                "hostname": item["hostname"],
                "identity_class": item["identity_class"],
                "identity_confidence": item["identity_confidence"],
                "identity_source": item["identity_source"],
                "device_type": item["device_type"],
                "classification_type": item["classification_type"],
                "classification_primary_type": item[
                    "classification_primary_type"
                ],
                "classification_confidence": item[
                    "classification_confidence"
                ],
                "classification_decision": item[
                    "classification_decision"
                ],
                "classification_confidence_band": item[
                    "classification_confidence_band"
                ],
                "classification_calibrated_decision": item[
                    "classification_calibrated_decision"
                ],
                "classification_siem_action": item[
                    "classification_siem_action"
                ],
                "classification_contradiction_count": item[
                    "classification_contradiction_count"
                ],
                "source_quality_state": item["source_quality_state"],
                "source_scan_id": item["source_scan_id"],
                "quality_decision_id": item["source_decision_id"],
                "accepted_evidence_seen": bool(
                    item["accepted_evidence_seen"]
                ),
                "last_seen_at": item["observed_at"],
            }
        )
        by_key[key] = merged

    output = list(by_key.values())
    if state:
        clean_state = str(state).strip().upper()
        output = [
            item
            for item in output
            if str(item.get("state") or "").upper() == clean_state
        ]
    if identity:
        clean_identity = str(identity).strip().upper()
        output = [
            item
            for item in output
            if str(item.get("identity_class") or "").upper()
            == clean_identity
        ]
    output.sort(
        key=lambda item: (
            str(item.get("network_scope") or ""),
            str(item.get("state") or ""),
            _numeric_ip_sort_key(
                item.get("current_ip") or item.get("ip_address")
            ),
            str(item.get("asset_key") or ""),
        )
    )
    return output[:limit] if limit is not None else output


def augment_asset_detail(
    connection: sqlite3.Connection,
    payload: dict[str, Any],
) -> dict[str, Any]:
    ensure_ready(connection)
    if not isinstance(payload, dict):
        return payload
    asset_key = str(
        payload.get("asset_key")
        or payload.get("identifier")
        or ""
    )
    scope = str(payload.get("network_scope") or payload.get("scope") or "")
    row = None
    if asset_key and scope:
        row = connection.execute(
            "SELECT * FROM telemetry_current_assets "
            "WHERE network_scope = ? AND asset_key = ?",
            (scope, asset_key),
        ).fetchone()
    elif asset_key:
        row = connection.execute(
            "SELECT * FROM telemetry_current_assets "
            "WHERE asset_key = ? ORDER BY observed_at DESC LIMIT 1",
            (asset_key,),
        ).fetchone()
    output = dict(payload)
    if row is not None:
        item = dict(row)
        projected_scope = str(item["network_scope"])
        projected_key = str(item["asset_key"])
        services = [
            dict(service)
            for service in connection.execute(
                "SELECT protocol, port, state, service_name, product, "
                "version, source_scan_id, source_quality_state, observed_at "
                "FROM telemetry_current_services "
                "WHERE network_scope = ? AND asset_key = ? "
                "ORDER BY protocol, port",
                (projected_scope, projected_key),
            ).fetchall()
        ]
        findings = [
            dict(finding)
            for finding in connection.execute(
                "SELECT finding_id, name, service, port, score, evidence, "
                "source_scan_id, source_quality_state, observed_at "
                "FROM telemetry_current_findings "
                "WHERE network_scope = ? AND asset_key = ? "
                "ORDER BY score DESC, finding_id, port",
                (projected_scope, projected_key),
            ).fetchall()
        ]
        output["telemetry_quality"] = {
            "decision_id": item["source_decision_id"],
            "state": item["source_quality_state"],
            "source_scan_id": item["source_scan_id"],
            "accepted_evidence_seen": bool(
                item["accepted_evidence_seen"]
            ),
            "observed_at": item["observed_at"],
        }
        output["telemetry_projection"] = {
            "asset": item,
            "services": services,
            "findings": findings,
        }
    return output


def current_state_summary(
    connection: sqlite3.Connection,
    *,
    scope: str | None = None,
) -> dict[str, Any]:
    ensure_ready(connection)
    params: tuple[Any, ...] = ()
    where = ""
    if scope:
        where = " WHERE network_scope = ?"
        params = (scope,)
    row = connection.execute(
        "SELECT COUNT(*) AS assets, "
        "SUM(CASE WHEN source_quality_state = 'DEGRADED' THEN 1 ELSE 0 END) "
        "AS degraded_assets, "
        "SUM(CASE WHEN accepted_evidence_seen = 1 THEN 1 ELSE 0 END) "
        "AS accepted_backed_assets "
        "FROM telemetry_current_assets" + where,
        params,
    ).fetchone()
    service_row = connection.execute(
        "SELECT COUNT(*) AS count FROM telemetry_current_services" + where,
        params,
    ).fetchone()
    finding_row = connection.execute(
        "SELECT COUNT(*) AS count FROM telemetry_current_findings" + where,
        params,
    ).fetchone()
    return {
        "assets": int(row["assets"] or 0) if row else 0,
        "degraded_assets": int(row["degraded_assets"] or 0) if row else 0,
        "accepted_backed_assets": int(
            row["accepted_backed_assets"] or 0
        ) if row else 0,
        "services": int(service_row["count"] or 0) if service_row else 0,
        "findings": int(finding_row["count"] or 0) if finding_row else 0,
    }


def _projection_risk_support(
    connection: sqlite3.Connection,
    *,
    scope: str,
    asset_key: str,
) -> dict[str, Any]:
    asset = connection.execute(
        """
        SELECT score, accepted_score, source_quality_state,
               accepted_evidence_seen
        FROM telemetry_current_assets
        WHERE network_scope = ? AND asset_key = ?
        """,
        (scope, asset_key),
    ).fetchone()
    if asset is None:
        return {
            "total_score": 0,
            "accepted_score": 0,
            "service_count": 0,
            "finding_count": 0,
            "has_degraded_only_support": False,
        }

    def integer(value: Any) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    service_row = connection.execute(
        """
        SELECT
            COUNT(*) AS total_count,
            SUM(CASE WHEN accepted_evidence_seen = 1 THEN 1 ELSE 0 END)
                AS accepted_count
        FROM telemetry_current_services
        WHERE network_scope = ? AND asset_key = ?
        """,
        (scope, asset_key),
    ).fetchone()
    finding_row = connection.execute(
        """
        SELECT
            COUNT(*) AS total_count,
            SUM(CASE WHEN accepted_evidence_seen = 1 THEN 1 ELSE 0 END)
                AS accepted_count,
            MAX(COALESCE(score, 0)) AS max_score,
            MAX(
                CASE WHEN accepted_evidence_seen = 1
                     THEN COALESCE(score, 0)
                     ELSE NULL
                END
            ) AS accepted_max_score
        FROM telemetry_current_findings
        WHERE network_scope = ? AND asset_key = ?
        """,
        (scope, asset_key),
    ).fetchone()

    total_services = integer(service_row["total_count"]) if service_row else 0
    accepted_services = (
        integer(service_row["accepted_count"]) if service_row else 0
    )
    total_findings = integer(finding_row["total_count"]) if finding_row else 0
    accepted_findings = (
        integer(finding_row["accepted_count"]) if finding_row else 0
    )
    max_finding = integer(finding_row["max_score"]) if finding_row else 0
    accepted_max_finding = (
        integer(finding_row["accepted_max_score"]) if finding_row else 0
    )

    current_asset_score = integer(asset["score"])
    accepted_asset_score = integer(asset["accepted_score"])
    total_score = (
        current_asset_score
        + min(20, total_services * 2)
        + min(30, max_finding)
    )
    accepted_score = (
        accepted_asset_score
        + min(20, accepted_services * 2)
        + min(30, accepted_max_finding)
    )
    total_score = max(total_score, accepted_score)

    has_degraded_only_support = (
        str(asset["source_quality_state"] or "").upper() == "DEGRADED"
        or total_services > accepted_services
        or total_findings > accepted_findings
    )

    return {
        "total_score": max(0, min(100, total_score)),
        "accepted_score": max(0, min(100, accepted_score)),
        "service_count": total_services,
        "finding_count": total_findings,
        "has_degraded_only_support": has_degraded_only_support,
    }


def risk_ceiling_for_asset(
    connection: sqlite3.Connection,
    *,
    scope: str,
    asset_key: str,
) -> int | None:
    """Return the approved ceiling for degraded-only risk contribution."""

    support = _projection_risk_support(
        connection,
        scope=scope,
        asset_key=asset_key,
    )
    return 64 if support["has_degraded_only_support"] else None


def merge_risk_rows(
    connection: sqlite3.Connection,
    rows: list[dict[str, Any]],
    *,
    scope: str | None,
    limit: int,
    risk_level,
) -> list[dict[str, Any]]:
    output = [dict(item) for item in rows or []]
    by_key = {
        (
            str(item.get("network_scope") or scope or ""),
            str(item.get("subject_key") or item.get("asset_key") or ""),
        ): item
        for item in output
    }
    projected = current_assets(connection, scope=scope, limit=10000)
    for asset in projected:
        asset_key = str(asset["asset_key"])
        support = _projection_risk_support(
            connection,
            scope=str(asset["network_scope"]),
            asset_key=asset_key,
        )
        row_key = (str(asset["network_scope"]), asset_key)
        existing = by_key.get(row_key)
        if existing is not None:
            existing_score = max(0, min(100, int(existing.get("score") or 0)))
            projected_score = int(support["total_score"])
            accepted_score = int(support["accepted_score"])
            if support["has_degraded_only_support"]:
                projected_score = max(
                    accepted_score,
                    min(projected_score, 64),
                )
                existing["degraded_positive_evidence_present"] = True
                existing["degraded_contribution_ceiling"] = 64
                reasons = list(existing.get("reasons") or [])
                note = (
                    "DEGRADED positive evidence is visible, but it does not "
                    "independently raise accepted-derived risk above MEDIUM."
                )
                if note not in reasons:
                    reasons.append(note)
                existing["reasons"] = reasons
            existing["score"] = max(existing_score, projected_score)
            existing["level"] = risk_level(existing["score"])
            existing["accepted_supported_score"] = max(
                int(existing.get("accepted_supported_score") or 0),
                accepted_score,
            )
            existing["network_scope"] = str(asset["network_scope"])
            continue

        ceiling = (
            64 if support["has_degraded_only_support"] else None
        )
        total_score = int(support["total_score"])
        accepted_score = int(support["accepted_score"])
        if ceiling is None:
            score = total_score
        else:
            # Accepted evidence may independently retain HIGH or CRITICAL risk.
            # Any incremental support that exists only in DEGRADED telemetry is
            # constrained to the approved MEDIUM ceiling.
            score = max(accepted_score, min(total_score, ceiling))
        score = max(0, min(100, score))

        record = {
            "subject_key": asset_key,
            "asset_key": asset_key,
            "network_scope": asset["network_scope"],
            "ip_address": asset["ip_address"],
            "mac_address": asset["mac_address"],
            "hostname": asset["hostname"],
            "vendor": asset["vendor"],
            "device_type": asset["device_type"],
            "classification": asset["classification_primary_type"],
            "classification_decision": asset[
                "classification_calibrated_decision"
            ]
            or asset["classification_decision"],
            "classification_confidence": int(
                asset["classification_confidence"] or 0
            ),
            "identity_confidence": asset["identity_confidence"],
            "score": score,
            "level": risk_level(score),
            "open_alerts": 0,
            "current_finding_count": int(support["finding_count"]),
            "reasons": [
                "Current positive observation is sourced from "
                f"{asset['source_quality_state']} telemetry."
            ],
            "recommended_actions": [
                "Review the telemetry-quality decision before treating "
                "absence or classification uncertainty as authoritative."
            ],
            "source_quality_state": asset["source_quality_state"],
            "quality_decision_id": asset["source_decision_id"],
            "quality_risk_ceiling": ceiling,
            "accepted_supported_score": accepted_score,
            "degraded_positive_evidence_present": bool(
                support["has_degraded_only_support"]
            ),
        }
        if ceiling is not None:
            record["reasons"].append(
                "DEGRADED-only risk contribution is capped at MEDIUM (64)."
            )
        output.append(record)
        by_key[row_key] = record

    output.sort(
        key=lambda item: (
            -int(item.get("score") or 0),
            str(item.get("network_scope") or ""),
            str(item.get("subject_key") or ""),
        )
    )
    return output[: max(1, int(limit))]


__all__ = [
    "apply_scan_from_db",
    "apply_snapshot",
    "augment_asset_detail",
    "bootstrap_legacy_projection",
    "current_assets",
    "current_state_summary",
    "degraded_classification_is_stronger",
    "ensure_schema",
    "ensure_ready",
    "merge_asset_rows",
    "merge_risk_rows",
    "replay_scope",
    "risk_ceiling_for_asset",
    "snapshot_is_historical",
]
