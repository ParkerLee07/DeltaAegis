"""Durable sensor, scope, and evidence identity for DeltaAegis v1.

The v0.42-v0.45 compatibility model used a CIDR as the observation-domain
key.  v1 keeps that value as an attribute while assigning every sensor and
scope an immutable identifier.  Legacy rows are attributed to one explicit
local sensor; ambiguous legacy records are assigned to an explicit unassigned
scope instead of being guessed into an observed network.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping


IDENTITY_SCHEMA_VERSION = "deltaaegis-identity-v1"
DEFAULT_SENSOR_ID = "sensor-legacy-local"
DEFAULT_SENSOR_NAME = "Legacy local sensor"
DEFAULT_TRUST_DOMAIN = "local"
UNASSIGNED_SCOPE_ID = "scope-legacy-unassigned"
SENSOR_ID_PATTERN = re.compile(r"sensor-[a-z0-9][a-z0-9._-]{2,63}")
SCOPE_ID_PATTERN = re.compile(r"scope-[a-z0-9][a-z0-9._-]{2,63}")
SOURCE_SCAN_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


class IdentityError(ValueError):
    """Raised when evidence cannot be bound to an authorized identity."""


IDENTITY_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS identity_sensors (
    sensor_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    trust_domain TEXT NOT NULL,
    sensor_kind TEXT NOT NULL DEFAULT 'MANAGED',
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_identity_sensors_status
    ON identity_sensors(status, display_name);

CREATE TABLE IF NOT EXISTS identity_scopes (
    scope_id TEXT PRIMARY KEY,
    sensor_id TEXT NOT NULL,
    network_scope TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(sensor_id, network_scope),
    FOREIGN KEY(sensor_id) REFERENCES identity_sensors(sensor_id)
        ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_identity_scopes_sensor
    ON identity_scopes(sensor_id, status, network_scope);
CREATE INDEX IF NOT EXISTS idx_identity_scopes_network
    ON identity_scopes(network_scope, sensor_id);

CREATE TABLE IF NOT EXISTS identity_evidence_receipts (
    receipt_id TEXT PRIMARY KEY,
    sensor_id TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    source_scan_id TEXT NOT NULL,
    internal_scan_id TEXT NOT NULL UNIQUE,
    bundle_digest TEXT NOT NULL,
    decision_id TEXT NOT NULL DEFAULT '',
    import_status TEXT NOT NULL,
    received_at TEXT NOT NULL,
    imported_at TEXT,
    UNIQUE(sensor_id, source_scan_id),
    FOREIGN KEY(sensor_id) REFERENCES identity_sensors(sensor_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(scope_id) REFERENCES identity_scopes(scope_id)
        ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_identity_receipts_scope
    ON identity_evidence_receipts(scope_id, received_at);
CREATE INDEX IF NOT EXISTS idx_identity_receipts_digest
    ON identity_evidence_receipts(bundle_digest);

CREATE TABLE IF NOT EXISTS identity_scope_heads (
    scope_id TEXT PRIMARY KEY,
    source_scan_id TEXT NOT NULL,
    internal_scan_id TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    quality_state TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(scope_id) REFERENCES identity_scopes(scope_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS identity_current_assets (
    scope_id TEXT NOT NULL,
    sensor_id TEXT NOT NULL,
    asset_key TEXT NOT NULL,
    source_scan_id TEXT NOT NULL,
    internal_scan_id TEXT NOT NULL,
    source_decision_id TEXT NOT NULL,
    source_quality_state TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    presence_state TEXT NOT NULL DEFAULT 'ACTIVE',
    missing_count INTEGER NOT NULL DEFAULT 0,
    identity_class TEXT NOT NULL DEFAULT 'IP_ONLY',
    ip_address TEXT NOT NULL DEFAULT '',
    mac_address TEXT,
    hostname TEXT,
    vendor TEXT,
    accepted_score INTEGER,
    record_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY(scope_id, asset_key),
    FOREIGN KEY(scope_id) REFERENCES identity_scopes(scope_id)
        ON DELETE CASCADE,
    FOREIGN KEY(sensor_id) REFERENCES identity_sensors(sensor_id)
        ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_identity_assets_sensor
    ON identity_current_assets(sensor_id, scope_id, asset_key);
CREATE INDEX IF NOT EXISTS idx_identity_assets_ip
    ON identity_current_assets(scope_id, ip_address);

CREATE TABLE IF NOT EXISTS identity_current_services (
    scope_id TEXT NOT NULL,
    sensor_id TEXT NOT NULL,
    asset_key TEXT NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    state TEXT NOT NULL,
    service_name TEXT,
    product TEXT,
    version TEXT,
    source_scan_id TEXT NOT NULL,
    internal_scan_id TEXT NOT NULL,
    source_decision_id TEXT NOT NULL,
    source_quality_state TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY(scope_id, asset_key, protocol, port),
    FOREIGN KEY(scope_id, asset_key)
        REFERENCES identity_current_assets(scope_id, asset_key)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS identity_current_findings (
    scope_id TEXT NOT NULL,
    sensor_id TEXT NOT NULL,
    asset_key TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT -1,
    name TEXT,
    service TEXT,
    score INTEGER,
    evidence TEXT,
    source_scan_id TEXT NOT NULL,
    internal_scan_id TEXT NOT NULL,
    source_decision_id TEXT NOT NULL,
    source_quality_state TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY(scope_id, asset_key, finding_id, port),
    FOREIGN KEY(scope_id, asset_key)
        REFERENCES identity_current_assets(scope_id, asset_key)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS identity_site_memberships (
    scope_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(scope_id) REFERENCES identity_scopes(scope_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(site_id) REFERENCES logical_sites(site_id)
        ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_identity_site_memberships_site
    ON identity_site_memberships(site_id, scope_id);
"""


IDENTITY_COLUMNS: dict[str, tuple[tuple[str, str], ...]] = {
    "snapshots": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
        ("source_scan_id", "source_scan_id TEXT NOT NULL DEFAULT ''"),
    ),
    "asset_observations": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "service_observations": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "finding_observations": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "delta_events": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "asset_lifecycle": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "alerts": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "asset_annotations": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "asset_annotation_history": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "asset_investigations": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "asset_investigation_history": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "scan_jobs": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "scan_schedules": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "scan_schedule_deletions": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "trueaegis_jobs": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "logical_site_memberships": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "validation_runs": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "validation_observations": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "validation_correlations": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "netsniper_intelligence_hosts": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "netsniper_intelligence_summaries": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "telemetry_quality_decisions": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
        ("source_run_id", "source_run_id TEXT NOT NULL DEFAULT ''"),
    ),
    "telemetry_quality_reviews": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "telemetry_current_assets": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "telemetry_current_services": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
    "telemetry_current_findings": (
        ("sensor_id", "sensor_id TEXT NOT NULL DEFAULT ''"),
        ("scope_id", "scope_id TEXT NOT NULL DEFAULT ''"),
    ),
}


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
        raise IdentityError("incomplete identity schema SQL")


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type='table'"
        )
    }


def _ensure_column(
    connection: sqlite3.Connection,
    table: str,
    column: str,
    ddl: str,
) -> None:
    if table not in _tables(connection):
        return
    columns = {
        str(row[1])
        for row in connection.execute(f'PRAGMA table_info("{table}")')
    }
    if column not in columns:
        connection.execute(f'ALTER TABLE "{table}" ADD COLUMN {ddl}')


def canonical_sensor_id(value: Any) -> str:
    sensor_id = str(value or "").strip().lower()
    if not SENSOR_ID_PATTERN.fullmatch(sensor_id):
        raise IdentityError(
            "sensor_id must match sensor-[a-z0-9][a-z0-9._-]{2,63}"
        )
    return sensor_id


def canonical_scope_id(value: Any) -> str:
    scope_id = str(value or "").strip().lower()
    if not SCOPE_ID_PATTERN.fullmatch(scope_id):
        raise IdentityError(
            "scope_id must match scope-[a-z0-9][a-z0-9._-]{2,63}"
        )
    return scope_id


def canonical_network_scope(
    value: Any,
    *,
    allow_unassigned: bool = False,
    require_rfc1918: bool = False,
) -> str:
    raw = str(value or "").strip()
    if not raw and allow_unassigned:
        return ""
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise IdentityError(f"invalid network scope: {raw!r}") from exc
    if require_rfc1918 and (
        network.version != 4
        or not any(network.subnet_of(parent) for parent in RFC1918_NETWORKS)
    ):
        raise IdentityError("network scope must be an RFC1918 IPv4 CIDR")
    return str(network)


def scope_id_for(sensor_id: Any, network_scope: Any) -> str:
    sensor = canonical_sensor_id(sensor_id)
    scope = canonical_network_scope(
        network_scope,
        require_rfc1918=(sensor != DEFAULT_SENSOR_ID),
    )
    digest = hashlib.sha256(f"{sensor}\0{scope}".encode("utf-8")).hexdigest()
    return f"scope-{digest[:32]}"


def internal_scan_id(sensor_id: Any, source_scan_id: Any) -> str:
    sensor = canonical_sensor_id(sensor_id)
    source = str(source_scan_id or "").strip()
    if not SOURCE_SCAN_ID_PATTERN.fullmatch(source):
        raise IdentityError("source scan ID is missing or malformed")
    if sensor == DEFAULT_SENSOR_ID:
        return source
    digest = hashlib.sha256(f"{sensor}\0{source}".encode("utf-8")).hexdigest()
    return f"scan-{digest[:40]}"


def _row_dict(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    return dict(row)


def ensure_default_identity(connection: sqlite3.Connection) -> None:
    now = utc_now()
    connection.execute(
        """
        INSERT INTO identity_sensors (
            sensor_id, display_name, trust_domain, sensor_kind, status,
            metadata_json, created_at, updated_at
        ) VALUES (?, ?, ?, 'LEGACY', 'ACTIVE', '{}', ?, ?)
        ON CONFLICT(sensor_id) DO NOTHING
        """,
        (DEFAULT_SENSOR_ID, DEFAULT_SENSOR_NAME, DEFAULT_TRUST_DOMAIN, now, now),
    )
    connection.execute(
        """
        INSERT INTO identity_scopes (
            scope_id, sensor_id, network_scope, display_name, status,
            metadata_json, created_at, updated_at
        ) VALUES (?, ?, '', 'Legacy records without attributable scope',
                  'UNASSIGNED', '{}', ?, ?)
        ON CONFLICT(scope_id) DO NOTHING
        """,
        (UNASSIGNED_SCOPE_ID, DEFAULT_SENSOR_ID, now, now),
    )


def ensure_scope(
    connection: sqlite3.Connection,
    *,
    sensor_id: Any,
    network_scope: Any,
    display_name: str = "",
    allow_default_create: bool = False,
) -> dict[str, Any]:
    sensor = canonical_sensor_id(sensor_id)
    scope = canonical_network_scope(
        network_scope,
        require_rfc1918=(sensor != DEFAULT_SENSOR_ID),
    )
    sensor_row = connection.execute(
        "SELECT * FROM identity_sensors WHERE sensor_id = ?",
        (sensor,),
    ).fetchone()
    if sensor_row is None:
        raise IdentityError(f"sensor is not enrolled: {sensor}")
    if str(sensor_row["status"]).upper() != "ACTIVE":
        raise IdentityError(f"sensor is not active: {sensor}")
    expected_scope_id = scope_id_for(sensor, scope)
    row = connection.execute(
        "SELECT * FROM identity_scopes WHERE sensor_id = ? AND network_scope = ?",
        (sensor, scope),
    ).fetchone()
    if row is None:
        if sensor != DEFAULT_SENSOR_ID and not allow_default_create:
            raise IdentityError(
                f"scope is not enrolled for sensor {sensor}: {scope}"
            )
        now = utc_now()
        connection.execute(
            """
            INSERT INTO identity_scopes (
                scope_id, sensor_id, network_scope, display_name, status,
                metadata_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'ACTIVE', '{}', ?, ?)
            """,
            (
                expected_scope_id,
                sensor,
                scope,
                str(display_name or scope).strip()[:120],
                now,
                now,
            ),
        )
        row = connection.execute(
            "SELECT * FROM identity_scopes WHERE scope_id = ?",
            (expected_scope_id,),
        ).fetchone()
    if row is None or str(row["status"]).upper() != "ACTIVE":
        raise IdentityError(f"scope is not active: {expected_scope_id}")
    if str(row["scope_id"]) != expected_scope_id:
        raise IdentityError("scope identity does not match its deterministic CIDR binding")
    return _row_dict(row)


def register_sensor(
    connection: sqlite3.Connection,
    *,
    display_name: Any,
    trust_domain: Any = DEFAULT_TRUST_DOMAIN,
    sensor_id: Any = None,
    network_scopes: Iterable[Any] = (),
    metadata: Mapping[str, Any] | None = None,
    actor: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(actor, Mapping) or not str(
        actor.get("user_id") or actor.get("token_id") or actor.get("session_id") or ""
    ).strip():
        raise IdentityError("sensor enrollment requires an authenticated actor")
    name = str(display_name or "").strip()
    if not name or len(name) > 120:
        raise IdentityError("sensor display_name must contain 1-120 characters")
    trust = str(trust_domain or "").strip().lower()
    if not trust or len(trust) > 96 or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", trust):
        raise IdentityError("trust_domain is malformed")
    sensor = (
        canonical_sensor_id(sensor_id)
        if sensor_id
        else f"sensor-{uuid.uuid4().hex[:24]}"
    )
    if sensor == DEFAULT_SENSOR_ID:
        raise IdentityError("the legacy local sensor cannot be re-enrolled")
    normalized_scopes = sorted(
        {
            canonical_network_scope(item, require_rfc1918=True)
            for item in network_scopes
        }
    )
    if not normalized_scopes:
        raise IdentityError("sensor enrollment requires at least one network scope")
    if len(normalized_scopes) > 256:
        raise IdentityError("sensor enrollment exceeds 256 network scopes")
    now = utc_now()
    connection.execute(
        """
        INSERT INTO identity_sensors (
            sensor_id, display_name, trust_domain, sensor_kind, status,
            metadata_json, created_at, updated_at
        ) VALUES (?, ?, ?, 'MANAGED', 'ACTIVE', ?, ?, ?)
        """,
        (sensor, name, trust, canonical_json(dict(metadata or {})), now, now),
    )
    for network_scope in normalized_scopes:
        ensure_scope(
            connection,
            sensor_id=sensor,
            network_scope=network_scope,
            allow_default_create=True,
        )
    return sensor_detail(connection, sensor)


def sensor_detail(connection: sqlite3.Connection, sensor_id: Any) -> dict[str, Any]:
    sensor = canonical_sensor_id(sensor_id)
    row = connection.execute(
        "SELECT * FROM identity_sensors WHERE sensor_id = ?", (sensor,)
    ).fetchone()
    if row is None:
        raise IdentityError(f"sensor not found: {sensor}")
    item = _row_dict(row)
    item["metadata"] = json.loads(str(item.pop("metadata_json") or "{}"))
    item["scopes"] = list_scopes(connection, sensor_id=sensor)
    return item


def list_sensors(
    connection: sqlite3.Connection,
    *,
    include_revoked: bool = False,
) -> list[dict[str, Any]]:
    where = "" if include_revoked else "WHERE status != 'REVOKED'"
    rows = connection.execute(
        f"SELECT * FROM identity_sensors {where} ORDER BY display_name, sensor_id"
    ).fetchall()
    output = []
    for row in rows:
        item = _row_dict(row)
        item["metadata"] = json.loads(str(item.pop("metadata_json") or "{}"))
        item["scope_count"] = int(
            connection.execute(
                "SELECT COUNT(*) FROM identity_scopes WHERE sensor_id = ?",
                (item["sensor_id"],),
            ).fetchone()[0]
        )
        output.append(item)
    return output


def list_scopes(
    connection: sqlite3.Connection,
    *,
    sensor_id: Any = None,
    include_unassigned: bool = False,
) -> list[dict[str, Any]]:
    clauses = []
    params: list[Any] = []
    if sensor_id:
        clauses.append("s.sensor_id = ?")
        params.append(canonical_sensor_id(sensor_id))
    if not include_unassigned:
        clauses.append("s.status != 'UNASSIGNED'")
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    rows = connection.execute(
        f"""
        SELECT s.*, n.display_name AS sensor_name,
               n.trust_domain AS trust_domain,
               m.site_id AS site_id,
               l.name AS site_name
        FROM identity_scopes s
        JOIN identity_sensors n ON n.sensor_id = s.sensor_id
        LEFT JOIN identity_site_memberships m ON m.scope_id = s.scope_id
        LEFT JOIN logical_sites l ON l.site_id = m.site_id
        {where}
        ORDER BY n.display_name, s.network_scope, s.scope_id
        """,
        tuple(params),
    ).fetchall()
    output = []
    for row in rows:
        item = _row_dict(row)
        item["metadata"] = json.loads(str(item.pop("metadata_json") or "{}"))
        output.append(item)
    return output


def assign_scope_to_site(
    connection: sqlite3.Connection,
    *,
    scope_id: Any,
    site_id: Any,
    actor: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(actor, Mapping) or not str(
        actor.get("user_id") or actor.get("token_id") or actor.get("session_id") or ""
    ).strip():
        raise IdentityError("scope assignment requires an authenticated actor")
    scope = canonical_scope_id(scope_id)
    site = str(site_id or "").strip()
    scope_row = connection.execute(
        "SELECT * FROM identity_scopes WHERE scope_id=? AND status='ACTIVE'",
        (scope,),
    ).fetchone()
    if scope_row is None:
        raise IdentityError(f"active scope not found: {scope}")
    site_row = connection.execute(
        "SELECT site_id, status FROM logical_sites WHERE site_id=?",
        (site,),
    ).fetchone()
    if site_row is None or str(site_row["status"]) != "ACTIVE":
        raise IdentityError(f"active logical site not found: {site}")
    existing = connection.execute(
        "SELECT site_id FROM identity_site_memberships WHERE scope_id=?",
        (scope,),
    ).fetchone()
    if existing is not None and str(existing["site_id"]) != site:
        raise IdentityError(
            f"scope {scope} is already assigned to logical site {existing['site_id']}"
        )
    now = utc_now()
    connection.execute(
        """
        INSERT INTO identity_site_memberships (
            scope_id, site_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?)
        ON CONFLICT(scope_id) DO UPDATE SET updated_at=excluded.updated_at
        """,
        (scope, site, now, now),
    )
    return {
        "scope_id": scope,
        "sensor_id": str(scope_row["sensor_id"]),
        "network_scope": str(scope_row["network_scope"]),
        "site_id": site,
        "updated_at": now,
    }


def remove_scope_from_site(
    connection: sqlite3.Connection,
    *,
    scope_id: Any,
    site_id: Any,
    actor: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(actor, Mapping) or not str(
        actor.get("user_id") or actor.get("token_id") or actor.get("session_id") or ""
    ).strip():
        raise IdentityError("scope removal requires an authenticated actor")
    scope = canonical_scope_id(scope_id)
    site = str(site_id or "").strip()
    cursor = connection.execute(
        "DELETE FROM identity_site_memberships WHERE scope_id=? AND site_id=?",
        (scope, site),
    )
    if cursor.rowcount != 1:
        raise IdentityError(f"scope membership not found: {scope} -> {site}")
    return {"scope_id": scope, "site_id": site, "removed": True}


def identity_for_evidence(
    connection: sqlite3.Connection,
    *,
    sensor_id: Any,
    network_scope: Any,
    source_scan_id: Any,
    bundle_digest: Any,
) -> dict[str, Any]:
    sensor = canonical_sensor_id(sensor_id or DEFAULT_SENSOR_ID)
    if not str(network_scope or "").strip():
        if sensor != DEFAULT_SENSOR_ID:
            raise IdentityError(
                "non-default sensor evidence must declare an enrolled network scope"
            )
        row = connection.execute(
            "SELECT * FROM identity_scopes WHERE scope_id=?",
            (UNASSIGNED_SCOPE_ID,),
        ).fetchone()
        if row is None:
            raise IdentityError("legacy unassigned scope is missing")
        scope = _row_dict(row)
    else:
        scope = ensure_scope(
            connection,
            sensor_id=sensor,
            network_scope=network_scope,
            allow_default_create=(sensor == DEFAULT_SENSOR_ID),
        )
    source = str(source_scan_id or "").strip()
    internal = internal_scan_id(sensor, source)
    digest = str(bundle_digest or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise IdentityError("evidence bundle digest is missing or malformed")
    existing = connection.execute(
        """
        SELECT * FROM identity_evidence_receipts
        WHERE sensor_id = ? AND source_scan_id = ?
        """,
        (sensor, source),
    ).fetchone()
    if existing is not None and str(existing["bundle_digest"]) != digest:
        raise IdentityError(
            "sensor source_scan_id is already bound to different evidence"
        )
    return {
        "schema_version": IDENTITY_SCHEMA_VERSION,
        "sensor_id": sensor,
        "scope_id": str(scope["scope_id"]),
        "network_scope": str(scope["network_scope"]),
        "source_scan_id": source,
        "internal_scan_id": internal,
        "bundle_digest": digest,
        "duplicate": existing is not None,
        "existing_receipt": _row_dict(existing) if existing is not None else None,
    }


def bind_decision_identity(
    decision: Mapping[str, Any], identity: Mapping[str, Any]
) -> dict[str, Any]:
    item = dict(decision)
    item["source_run_id"] = str(identity["source_scan_id"])
    item["run_id"] = str(identity["internal_scan_id"])
    item["sensor_id"] = str(identity["sensor_id"])
    item["scope_id"] = str(identity["scope_id"])
    item["network_scope"] = str(identity["network_scope"])
    material = "|".join(
        (
            item["run_id"],
            str(item.get("bundle_digest") or ""),
            str(item.get("policy_version") or ""),
            str(item.get("schema_version") or ""),
        )
    )
    item["decision_id"] = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return item


def link_decision(
    connection: sqlite3.Connection,
    *,
    decision_id: str,
    identity: Mapping[str, Any],
) -> None:
    connection.execute(
        """
        UPDATE telemetry_quality_decisions
        SET sensor_id = ?, scope_id = ?, source_run_id = ?
        WHERE decision_id = ?
        """,
        (
            identity["sensor_id"],
            identity["scope_id"],
            identity["source_scan_id"],
            decision_id,
        ),
    )


def link_snapshot(
    connection: sqlite3.Connection,
    *,
    scan_id: str,
    identity: Mapping[str, Any],
) -> None:
    params = (
        identity["sensor_id"],
        identity["scope_id"],
        identity["source_scan_id"],
        scan_id,
    )
    connection.execute(
        "UPDATE snapshots SET sensor_id=?, scope_id=?, source_scan_id=? "
        "WHERE scan_id=?",
        params,
    )
    for table in (
        "asset_observations",
        "service_observations",
        "finding_observations",
        "netsniper_intelligence_hosts",
        "netsniper_intelligence_summaries",
    ):
        if table in _tables(connection):
            connection.execute(
                f"UPDATE {table} SET sensor_id=?, scope_id=? WHERE scan_id=?",
                (identity["sensor_id"], identity["scope_id"], scan_id),
            )


def record_evidence_receipt(
    connection: sqlite3.Connection,
    *,
    identity: Mapping[str, Any],
    decision_id: str,
    import_status: str,
    imported_at: str | None = None,
) -> dict[str, Any]:
    material = (
        f"{identity['sensor_id']}\0{identity['source_scan_id']}\0"
        f"{identity['bundle_digest']}"
    )
    receipt_id = "receipt-" + hashlib.sha256(material.encode("utf-8")).hexdigest()
    now = utc_now()
    connection.execute(
        """
        INSERT INTO identity_evidence_receipts (
            receipt_id, sensor_id, scope_id, source_scan_id,
            internal_scan_id, bundle_digest, decision_id, import_status,
            received_at, imported_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(sensor_id, source_scan_id) DO UPDATE SET
            decision_id=CASE
                WHEN identity_evidence_receipts.bundle_digest=excluded.bundle_digest
                THEN excluded.decision_id
                ELSE identity_evidence_receipts.decision_id
            END,
            import_status=CASE
                WHEN identity_evidence_receipts.bundle_digest=excluded.bundle_digest
                THEN excluded.import_status
                ELSE identity_evidence_receipts.import_status
            END,
            imported_at=CASE
                WHEN identity_evidence_receipts.bundle_digest=excluded.bundle_digest
                THEN COALESCE(excluded.imported_at,
                              identity_evidence_receipts.imported_at)
                ELSE identity_evidence_receipts.imported_at
            END
        """,
        (
            receipt_id,
            identity["sensor_id"],
            identity["scope_id"],
            identity["source_scan_id"],
            identity["internal_scan_id"],
            identity["bundle_digest"],
            str(decision_id or ""),
            str(import_status),
            now,
            imported_at,
        ),
    )
    row = connection.execute(
        "SELECT * FROM identity_evidence_receipts WHERE sensor_id=? AND source_scan_id=?",
        (identity["sensor_id"], identity["source_scan_id"]),
    ).fetchone()
    if row is None or str(row["bundle_digest"]) != identity["bundle_digest"]:
        raise IdentityError("evidence receipt conflict")
    return _row_dict(row)


def _value(item: Any, name: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(name, default)
    return getattr(item, name, default)


def _asset_record(asset: Any) -> dict[str, Any]:
    if hasattr(asset, "__dict__"):
        item = dict(vars(asset))
    elif isinstance(asset, Mapping):
        item = dict(asset)
    else:
        item = {"asset_key": _value(asset, "asset_key")}
    item.pop("services", None)
    item.pop("findings", None)
    return item


def _is_historical(
    connection: sqlite3.Connection,
    *,
    scope_id: str,
    observed_at: str,
    internal_scan_id_value: str,
) -> bool:
    row = connection.execute(
        "SELECT observed_at, internal_scan_id FROM identity_scope_heads WHERE scope_id=?",
        (scope_id,),
    ).fetchone()
    if row is None:
        return False
    return (str(observed_at), str(internal_scan_id_value)) < (
        str(row["observed_at"]),
        str(row["internal_scan_id"]),
    )


def apply_snapshot_projection(
    connection: sqlite3.Connection,
    *,
    snapshot: Any,
    decision: Mapping[str, Any],
    identity: Mapping[str, Any],
) -> dict[str, Any]:
    state = str(decision.get("current_state") or "REJECTED").upper()
    scope_id = str(identity["scope_id"])
    sensor_id = str(identity["sensor_id"])
    source_scan = str(identity["source_scan_id"])
    internal_scan = str(identity["internal_scan_id"])
    observed_at = str(_value(snapshot, "created_at") or utc_now())
    if state not in {"ACCEPTED", "DEGRADED"}:
        return {"applied": False, "reason": f"quality_{state.lower()}"}
    if _is_historical(
        connection,
        scope_id=scope_id,
        observed_at=observed_at,
        internal_scan_id_value=internal_scan,
    ):
        return {"applied": False, "reason": "historical"}

    assets = _value(snapshot, "assets", {}) or {}
    current_keys = {str(key) for key in assets}
    if state == "ACCEPTED":
        rows = connection.execute(
            "SELECT asset_key, identity_class, missing_count, presence_state "
            "FROM identity_current_assets WHERE scope_id=?",
            (scope_id,),
        ).fetchall()
        for row in rows:
            key = str(row["asset_key"])
            if key in current_keys:
                continue
            missing = int(row["missing_count"] or 0) + 1
            identity_class = str(row["identity_class"] or "IP_ONLY").upper()
            if identity_class == "LOCAL_MAC":
                presence = "EPHEMERAL_MISSING"
            elif identity_class == "GLOBAL_MAC" and missing >= 3:
                presence = "REMOVED"
            else:
                presence = "MISSING"
            connection.execute(
                "UPDATE identity_current_assets SET presence_state=?, missing_count=? "
                "WHERE scope_id=? AND asset_key=?",
                (presence, missing, scope_id, key),
            )

    for asset_key, asset in assets.items():
        key = str(asset_key)
        record = _asset_record(asset)
        score = _value(asset, "score")
        existing = connection.execute(
            "SELECT accepted_score FROM identity_current_assets "
            "WHERE scope_id=? AND asset_key=?",
            (scope_id, key),
        ).fetchone()
        accepted_score = (
            score
            if state == "ACCEPTED"
            else (existing["accepted_score"] if existing is not None else None)
        )
        if state == "DEGRADED" and accepted_score is not None and score is not None:
            try:
                record["score"] = min(int(score), int(accepted_score))
            except (TypeError, ValueError):
                record["score"] = accepted_score
        connection.execute(
            """
            INSERT INTO identity_current_assets (
                scope_id, sensor_id, asset_key, source_scan_id,
                internal_scan_id, source_decision_id, source_quality_state,
                observed_at, presence_state, missing_count, identity_class,
                ip_address, mac_address, hostname, vendor, accepted_score,
                record_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 0, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scope_id, asset_key) DO UPDATE SET
                sensor_id=excluded.sensor_id,
                source_scan_id=excluded.source_scan_id,
                internal_scan_id=excluded.internal_scan_id,
                source_decision_id=excluded.source_decision_id,
                source_quality_state=excluded.source_quality_state,
                observed_at=excluded.observed_at,
                presence_state='ACTIVE',
                missing_count=0,
                identity_class=excluded.identity_class,
                ip_address=excluded.ip_address,
                mac_address=excluded.mac_address,
                hostname=excluded.hostname,
                vendor=excluded.vendor,
                accepted_score=COALESCE(excluded.accepted_score,
                                        identity_current_assets.accepted_score),
                record_json=excluded.record_json
            """,
            (
                scope_id,
                sensor_id,
                key,
                source_scan,
                internal_scan,
                str(decision.get("decision_id") or ""),
                state,
                observed_at,
                str(_value(asset, "identity_class") or "IP_ONLY"),
                str(_value(asset, "ip_address") or ""),
                _value(asset, "mac_address"),
                _value(asset, "hostname"),
                _value(asset, "vendor"),
                accepted_score,
                canonical_json(record),
            ),
        )
        if state == "ACCEPTED":
            connection.execute(
                "DELETE FROM identity_current_services WHERE scope_id=? AND asset_key=?",
                (scope_id, key),
            )
            connection.execute(
                "DELETE FROM identity_current_findings WHERE scope_id=? AND asset_key=?",
                (scope_id, key),
            )
        for service in _value(asset, "services", []) or []:
            service_state = str(_value(service, "state") or "open")
            if state == "DEGRADED" and service_state.lower() != "open":
                continue
            connection.execute(
                """
                INSERT INTO identity_current_services (
                    scope_id, sensor_id, asset_key, protocol, port, state,
                    service_name, product, version, source_scan_id,
                    internal_scan_id, source_decision_id,
                    source_quality_state, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scope_id, asset_key, protocol, port) DO UPDATE SET
                    state=excluded.state,
                    service_name=excluded.service_name,
                    product=excluded.product,
                    version=excluded.version,
                    source_scan_id=excluded.source_scan_id,
                    internal_scan_id=excluded.internal_scan_id,
                    source_decision_id=excluded.source_decision_id,
                    source_quality_state=excluded.source_quality_state,
                    observed_at=excluded.observed_at
                """,
                (
                    scope_id,
                    sensor_id,
                    key,
                    str(_value(service, "protocol") or "tcp"),
                    int(_value(service, "port") or 0),
                    service_state,
                    _value(service, "service_name"),
                    _value(service, "product"),
                    _value(service, "version"),
                    source_scan,
                    internal_scan,
                    str(decision.get("decision_id") or ""),
                    state,
                    observed_at,
                ),
            )
        for finding in _value(asset, "findings", []) or []:
            finding_id = str(
                _value(finding, "finding_id")
                or _value(finding, "id")
                or "UNKNOWN"
            )
            try:
                port = int(_value(finding, "port", -1))
            except (TypeError, ValueError):
                port = -1
            connection.execute(
                """
                INSERT INTO identity_current_findings (
                    scope_id, sensor_id, asset_key, finding_id, port, name,
                    service, score, evidence, source_scan_id,
                    internal_scan_id, source_decision_id,
                    source_quality_state, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scope_id, asset_key, finding_id, port) DO UPDATE SET
                    name=excluded.name,
                    service=excluded.service,
                    score=excluded.score,
                    evidence=excluded.evidence,
                    source_scan_id=excluded.source_scan_id,
                    internal_scan_id=excluded.internal_scan_id,
                    source_decision_id=excluded.source_decision_id,
                    source_quality_state=excluded.source_quality_state,
                    observed_at=excluded.observed_at
                """,
                (
                    scope_id,
                    sensor_id,
                    key,
                    finding_id,
                    port,
                    _value(finding, "name"),
                    _value(finding, "service"),
                    _value(finding, "score"),
                    _value(finding, "evidence"),
                    source_scan,
                    internal_scan,
                    str(decision.get("decision_id") or ""),
                    state,
                    observed_at,
                ),
            )

    connection.execute(
        """
        INSERT INTO identity_scope_heads (
            scope_id, source_scan_id, internal_scan_id, decision_id,
            quality_state, observed_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(scope_id) DO UPDATE SET
            source_scan_id=excluded.source_scan_id,
            internal_scan_id=excluded.internal_scan_id,
            decision_id=excluded.decision_id,
            quality_state=excluded.quality_state,
            observed_at=excluded.observed_at,
            updated_at=excluded.updated_at
        """,
        (
            scope_id,
            source_scan,
            internal_scan,
            str(decision.get("decision_id") or ""),
            state,
            observed_at,
            utc_now(),
        ),
    )
    return {"applied": True, "assets": len(assets), "scope_id": scope_id}


def list_assets(
    connection: sqlite3.Connection,
    *,
    sensor_id: Any = None,
    scope_id: Any = None,
    limit: int = 200,
    offset: int = 0,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if sensor_id:
        clauses.append("a.sensor_id = ?")
        params.append(canonical_sensor_id(sensor_id))
    if scope_id:
        clauses.append("a.scope_id = ?")
        params.append(canonical_scope_id(scope_id))
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    params.extend((max(1, min(int(limit), 1000)), max(0, int(offset))))
    rows = connection.execute(
        f"""
        SELECT a.*, s.network_scope, s.display_name AS scope_name,
               n.display_name AS sensor_name
        FROM identity_current_assets a
        JOIN identity_scopes s ON s.scope_id = a.scope_id
        JOIN identity_sensors n ON n.sensor_id = a.sensor_id
        {where}
        ORDER BY a.sensor_id, a.scope_id, a.asset_key
        LIMIT ? OFFSET ?
        """,
        tuple(params),
    ).fetchall()
    output = []
    for row in rows:
        item = _row_dict(row)
        record = json.loads(str(item.pop("record_json") or "{}"))
        record.update(item)
        output.append(record)
    return output


def asset_detail(
    connection: sqlite3.Connection,
    *,
    asset_key: Any,
    scope_id: Any,
) -> dict[str, Any]:
    key = str(asset_key or "").strip()
    scope = canonical_scope_id(scope_id)
    rows = list_assets(connection, scope_id=scope, limit=1000)
    item = next((row for row in rows if str(row.get("asset_key")) == key), None)
    if item is None:
        raise IdentityError(f"asset not found in scope {scope}: {key}")
    services = connection.execute(
        "SELECT * FROM identity_current_services "
        "WHERE scope_id=? AND asset_key=? ORDER BY protocol, port",
        (scope, key),
    ).fetchall()
    findings = connection.execute(
        "SELECT * FROM identity_current_findings "
        "WHERE scope_id=? AND asset_key=? ORDER BY finding_id, port",
        (scope, key),
    ).fetchall()
    item["services"] = [dict(row) for row in services]
    item["findings"] = [dict(row) for row in findings]
    return item


def _scope_for_network(connection: sqlite3.Connection, network_scope: str) -> str:
    if not str(network_scope or "").strip():
        return UNASSIGNED_SCOPE_ID
    try:
        scope = canonical_network_scope(network_scope)
    except IdentityError:
        # Supported legacy databases can contain old synthetic or anomalous
        # scope strings. Preserve those rows under an explicit unassigned
        # identity rather than trusting the value or blocking the upgrade.
        return UNASSIGNED_SCOPE_ID
    ensure_scope(
        connection,
        sensor_id=DEFAULT_SENSOR_ID,
        network_scope=scope,
        allow_default_create=True,
    )
    return scope_id_for(DEFAULT_SENSOR_ID, scope)


def _backfill_direct_scope_table(
    connection: sqlite3.Connection,
    table: str,
    *,
    network_column: str = "network_scope",
) -> int:
    if table not in _tables(connection):
        return 0
    rows = connection.execute(
        f"SELECT rowid AS _identity_rowid, {network_column} FROM {table} "
        "WHERE sensor_id='' OR scope_id=''"
    ).fetchall()
    for row in rows:
        scope_id = _scope_for_network(connection, str(row[network_column] or ""))
        connection.execute(
            f"UPDATE {table} SET sensor_id=?, scope_id=? WHERE rowid=?",
            (DEFAULT_SENSOR_ID, scope_id, row["_identity_rowid"]),
        )
    return len(rows)


def _backfill_scan_children(connection: sqlite3.Connection) -> None:
    for table in (
        "asset_observations",
        "service_observations",
        "finding_observations",
        "delta_events",
        "netsniper_intelligence_hosts",
        "netsniper_intelligence_summaries",
    ):
        if table not in _tables(connection):
            continue
        connection.execute(
            f"""
            UPDATE {table}
            SET sensor_id=COALESCE((
                    SELECT sensor_id FROM snapshots s
                    WHERE s.scan_id={table}.scan_id
                ), ?),
                scope_id=COALESCE((
                    SELECT scope_id FROM snapshots s
                    WHERE s.scan_id={table}.scan_id
                ), ?)
            WHERE sensor_id='' OR scope_id=''
            """,
            (DEFAULT_SENSOR_ID, UNASSIGNED_SCOPE_ID),
        )


def _backfill_legacy_projection(connection: sqlite3.Connection) -> int:
    if "telemetry_current_assets" not in _tables(connection):
        return 0
    rows = connection.execute(
        "SELECT * FROM telemetry_current_assets"
    ).fetchall()
    for row in rows:
        item = _row_dict(row)
        scope_id = _scope_for_network(connection, item.get("network_scope", ""))
        source_scan = str(item.get("source_scan_id") or "legacy-projection")
        record = {
            key: value
            for key, value in item.items()
            if key not in {"sensor_id", "scope_id"}
        }
        connection.execute(
            """
            INSERT INTO identity_current_assets (
                scope_id, sensor_id, asset_key, source_scan_id,
                internal_scan_id, source_decision_id, source_quality_state,
                observed_at, presence_state, missing_count, identity_class,
                ip_address, mac_address, hostname, vendor, accepted_score,
                record_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 0, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scope_id, asset_key) DO NOTHING
            """,
            (
                scope_id,
                DEFAULT_SENSOR_ID,
                item["asset_key"],
                source_scan,
                source_scan,
                str(item.get("source_decision_id") or "legacy"),
                str(item.get("source_quality_state") or "ACCEPTED"),
                str(item.get("observed_at") or utc_now()),
                str(item.get("identity_class") or "IP_ONLY"),
                str(item.get("ip_address") or ""),
                item.get("mac_address"),
                item.get("hostname"),
                item.get("vendor"),
                item.get("accepted_score"),
                canonical_json(record),
            ),
        )
    for source_table, target_table, key_columns in (
        (
            "telemetry_current_services",
            "identity_current_services",
            ("protocol", "port"),
        ),
        (
            "telemetry_current_findings",
            "identity_current_findings",
            ("finding_id", "port"),
        ),
    ):
        if source_table not in _tables(connection):
            continue
        for row in connection.execute(f"SELECT * FROM {source_table}"):
            item = _row_dict(row)
            scope_id = _scope_for_network(
                connection, str(item.get("network_scope") or "")
            )
            parent = connection.execute(
                "SELECT 1 FROM identity_current_assets WHERE scope_id=? AND asset_key=?",
                (scope_id, item["asset_key"]),
            ).fetchone()
            if parent is None:
                continue
            common = (
                scope_id,
                DEFAULT_SENSOR_ID,
                item["asset_key"],
            )
            if target_table == "identity_current_services":
                connection.execute(
                    """
                    INSERT OR IGNORE INTO identity_current_services (
                        scope_id, sensor_id, asset_key, protocol, port, state,
                        service_name, product, version, source_scan_id,
                        internal_scan_id, source_decision_id,
                        source_quality_state, observed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    common
                    + (
                        item["protocol"], item["port"], item["state"],
                        item.get("service_name"), item.get("product"),
                        item.get("version"), item["source_scan_id"],
                        item["source_scan_id"], item["source_decision_id"],
                        item["source_quality_state"], item["observed_at"],
                    ),
                )
            else:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO identity_current_findings (
                        scope_id, sensor_id, asset_key, finding_id, port, name,
                        service, score, evidence, source_scan_id,
                        internal_scan_id, source_decision_id,
                        source_quality_state, observed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    common
                    + (
                        item["finding_id"], item["port"], item.get("name"),
                        item.get("service"), item.get("score"),
                        item.get("evidence"), item["source_scan_id"],
                        item["source_scan_id"], item["source_decision_id"],
                        item["source_quality_state"], item["observed_at"],
                    ),
                )
    return len(rows)


def apply_schema(connection: sqlite3.Connection) -> dict[str, Any]:
    _execute_schema_sql(connection, IDENTITY_SCHEMA_SQL)
    for table, columns in IDENTITY_COLUMNS.items():
        for column, ddl in columns:
            _ensure_column(connection, table, column, ddl)
    ensure_default_identity(connection)

    backfilled = 0
    for table in (
        "snapshots",
        "asset_lifecycle",
        "asset_investigations",
        "asset_investigation_history",
        "scan_jobs",
        "scan_schedules",
        "scan_schedule_deletions",
        "trueaegis_jobs",
        "logical_site_memberships",
        "validation_correlations",
        "telemetry_quality_decisions",
        "telemetry_current_assets",
        "telemetry_current_services",
        "telemetry_current_findings",
    ):
        backfilled += _backfill_direct_scope_table(connection, table)

    connection.execute(
        "UPDATE snapshots SET source_scan_id=scan_id WHERE source_scan_id=''"
    )
    _backfill_scan_children(connection)

    for table in ("asset_annotations", "asset_annotation_history"):
        if table in _tables(connection):
            connection.execute(
                f"UPDATE {table} SET sensor_id=?, scope_id=? "
                "WHERE sensor_id='' OR scope_id=''",
                (DEFAULT_SENSOR_ID, UNASSIGNED_SCOPE_ID),
            )

    if "telemetry_quality_reviews" in _tables(connection):
        connection.execute(
            """
            UPDATE telemetry_quality_reviews
            SET sensor_id=COALESCE((
                    SELECT sensor_id FROM telemetry_quality_decisions q
                    WHERE q.decision_id=telemetry_quality_reviews.decision_id
                ), ?),
                scope_id=COALESCE((
                    SELECT scope_id FROM telemetry_quality_decisions q
                    WHERE q.decision_id=telemetry_quality_reviews.decision_id
                ), ?)
            WHERE sensor_id='' OR scope_id=''
            """,
            (DEFAULT_SENSOR_ID, UNASSIGNED_SCOPE_ID),
        )
    if "telemetry_quality_decisions" in _tables(connection):
        connection.execute(
            "UPDATE telemetry_quality_decisions SET source_run_id=run_id "
            "WHERE source_run_id=''"
        )
    if "validation_runs" in _tables(connection):
        for row in connection.execute(
            "SELECT rowid AS _identity_rowid, validation_run_id FROM validation_runs "
            "WHERE sensor_id='' OR scope_id=''"
        ):
            scopes = connection.execute(
                "SELECT DISTINCT scope_id FROM validation_correlations "
                "WHERE validation_run_id=? AND scope_id!=''",
                (row["validation_run_id"],),
            ).fetchall()
            scope_id = str(scopes[0][0]) if len(scopes) == 1 else UNASSIGNED_SCOPE_ID
            connection.execute(
                "UPDATE validation_runs SET sensor_id=?, scope_id=? WHERE rowid=?",
                (DEFAULT_SENSOR_ID, scope_id, row["_identity_rowid"]),
            )
        if "validation_observations" in _tables(connection):
            connection.execute(
                """
                UPDATE validation_observations
                SET sensor_id=COALESCE((
                        SELECT sensor_id FROM validation_runs r
                        WHERE r.validation_run_id=validation_observations.validation_run_id
                    ), ?),
                    scope_id=COALESCE((
                        SELECT scope_id FROM validation_runs r
                        WHERE r.validation_run_id=validation_observations.validation_run_id
                    ), ?)
                WHERE sensor_id='' OR scope_id=''
                """,
                (DEFAULT_SENSOR_ID, UNASSIGNED_SCOPE_ID),
            )
    if "alerts" in _tables(connection):
        connection.execute(
            """
            UPDATE alerts
            SET sensor_id=COALESCE((
                    SELECT sensor_id FROM delta_events e
                    WHERE e.event_id=alerts.first_event_id
                ), ?),
                scope_id=COALESCE((
                    SELECT scope_id FROM delta_events e
                    WHERE e.event_id=alerts.first_event_id
                ), ?)
            WHERE sensor_id='' OR scope_id=''
            """,
            (DEFAULT_SENSOR_ID, UNASSIGNED_SCOPE_ID),
        )
    if "logical_site_memberships" in _tables(connection):
        connection.execute(
            """
            INSERT OR IGNORE INTO identity_site_memberships (
                scope_id, site_id, created_at, updated_at
            )
            SELECT scope_id, site_id, created_at, updated_at
            FROM logical_site_memberships WHERE scope_id!=''
            """
        )
    projected = _backfill_legacy_projection(connection)

    for row in connection.execute(
        "SELECT scan_id, source_scan_id, sensor_id, scope_id, bundle_digest, "
        "quality_decision_id, imported_at FROM snapshots"
    ):
        source = str(row["source_scan_id"] or row["scan_id"])
        digest = str(row["bundle_digest"] or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            digest = hashlib.sha256(
                f"legacy-unverified\0{row['scan_id']}".encode("utf-8")
            ).hexdigest()
        record_evidence_receipt(
            connection,
            identity={
                "sensor_id": row["sensor_id"] or DEFAULT_SENSOR_ID,
                "scope_id": row["scope_id"] or UNASSIGNED_SCOPE_ID,
                "source_scan_id": source,
                "internal_scan_id": row["scan_id"],
                "bundle_digest": digest,
            },
            decision_id=str(row["quality_decision_id"] or ""),
            import_status="MIGRATED",
            imported_at=str(row["imported_at"] or utc_now()),
        )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_jobs_sensor_status "
        "ON scan_jobs(sensor_id, status, created_at)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_snapshots_scope_created "
        "ON snapshots(scope_id, created_at, scan_id)"
    )
    return {
        "schema_version": IDENTITY_SCHEMA_VERSION,
        "legacy_rows_backfilled": backfilled,
        "legacy_assets_projected": projected,
    }


def validate_schema(connection: sqlite3.Connection) -> None:
    required = {
        "identity_sensors",
        "identity_scopes",
        "identity_evidence_receipts",
        "identity_scope_heads",
        "identity_current_assets",
        "identity_current_services",
        "identity_current_findings",
        "identity_site_memberships",
    }
    missing = sorted(required - _tables(connection))
    if missing:
        raise IdentityError("identity schema is missing tables: " + ", ".join(missing))
    if connection.execute(
        "SELECT 1 FROM identity_sensors WHERE sensor_id=? AND status='ACTIVE'",
        (DEFAULT_SENSOR_ID,),
    ).fetchone() is None:
        raise IdentityError("legacy local sensor is missing or inactive")
    for table, columns in IDENTITY_COLUMNS.items():
        if table not in _tables(connection):
            continue
        existing = {
            str(row[1])
            for row in connection.execute(f'PRAGMA table_info("{table}")')
        }
        missing_columns = [name for name, _ in columns if name not in existing]
        if missing_columns:
            raise IdentityError(
                f"{table} is missing identity columns: {', '.join(missing_columns)}"
            )
    orphan_count = int(
        connection.execute(
            """
            SELECT COUNT(*) FROM snapshots s
            LEFT JOIN identity_scopes i ON i.scope_id=s.scope_id
            WHERE s.sensor_id='' OR s.scope_id='' OR i.scope_id IS NULL
            """
        ).fetchone()[0]
    )
    if orphan_count:
        raise IdentityError(f"{orphan_count} snapshots lack durable scope identity")


__all__ = (
    "DEFAULT_SENSOR_ID",
    "IDENTITY_COLUMNS",
    "IDENTITY_SCHEMA_SQL",
    "IDENTITY_SCHEMA_VERSION",
    "IdentityError",
    "UNASSIGNED_SCOPE_ID",
    "apply_schema",
    "apply_snapshot_projection",
    "assign_scope_to_site",
    "asset_detail",
    "bind_decision_identity",
    "canonical_network_scope",
    "canonical_scope_id",
    "canonical_sensor_id",
    "ensure_default_identity",
    "ensure_scope",
    "identity_for_evidence",
    "internal_scan_id",
    "link_decision",
    "link_snapshot",
    "list_assets",
    "list_scopes",
    "list_sensors",
    "record_evidence_receipt",
    "remove_scope_from_site",
    "register_sensor",
    "scope_id_for",
    "sensor_detail",
    "validate_schema",
)
