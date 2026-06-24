#!/usr/bin/env python3
"""DeltaAegis v0.22.0: Operator Triage Intelligence, Evidence Timeline Intelligence, Workflow Filters and Operator Views, Investigation Workflow Actions, Executive SIEM Dashboard Refresh, Investigation Command Center, MAC-port behavior correlation, NetSniper scan orchestration, current-state SIEM dashboard, classification storage, calibrated risk policy, reporting, and dashboard console.

Consumes finalized NetSniper run bundles, preserves snapshot evidence, tracks
stable and ephemeral identities separately, applies a three-scan removal
threshold, and maintains operator-facing alert state without discarding the
append-only delta-event history.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Iterable

DEFAULT_DB = Path.home() / "DeltaAegis" / "data" / "deltaaegis.db"
DEFAULT_RUNS = Path.home() / "NetSniper" / "runs"
DEFAULT_NETSNIPER = Path.home() / "NetSniper" / "netsniper.sh"
DEFAULT_SCAN_LOGS = Path.home() / "DeltaAegis" / "scan-logs"
DEFAULT_EVENTS = Path.home() / "DeltaAegis" / "events" / "events.jsonl"
DEFAULT_REPORTS = Path.home() / "DeltaAegis" / "reports"
DELTAAEGIS_V0_14_COMPATIBILITY_NOTE = "DeltaAegis v0.14.0 — NetSniper Scan Orchestration compatibility retained."
DELTAAEGIS_V0_15_COMPATIBILITY_NOTE = "DeltaAegis v0.15.0 — MAC-Port Behavior Correlation compatibility retained."
DELTAAEGIS_V0_16_COMPATIBILITY_NOTE = "DeltaAegis v0.16.0 — Investigation Command Center compatibility retained."
QUALITY_RATIO_THRESHOLD = 0.50
IDENTITY_COVERAGE_THRESHOLD = 0.50
IDENTITY_DROP_REVIEW_THRESHOLD = 0.25
REMOVAL_THRESHOLD = 3
MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
SCAN_JOB_STATUSES = {"QUEUED", "RUNNING", "COMPLETED", "FAILED"}

ACCESS_ROLES = ("ADMIN", "ANALYST", "VIEWER")
ACCESS_ROLE_RANKS = {
    "VIEWER": 10,
    "ANALYST": 20,
    "ADMIN": 30,
}
ACCESS_PASSWORD_ALGORITHM = "pbkdf2_sha256"
ACCESS_PASSWORD_ITERATIONS = 260000
ACCESS_API_TOKEN_PREFIX = "da"

ACCESS_SESSION_COOKIE_NAME = "deltaaegis_session"
ACCESS_SESSION_TTL_SECONDS = 8 * 60 * 60



class DeltaAegisError(RuntimeError):
    pass


@dataclass(frozen=True)
class Service:
    protocol: str
    port: int
    state: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None

    @property
    def key(self) -> tuple[str, int]:
        return self.protocol, self.port


@dataclass
class IdentityEvidence:
    mac_address: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    source: str = "IP_ONLY"


@dataclass
class AssetObservation:
    asset_key: str
    identity_class: str
    identity_confidence: str
    identity_source: str
    ip_address: str
    mac_address: str | None
    vendor: str | None
    hostname: str | None
    device_type: str | None
    severity: str | None
    score: int | None
    services: list[Service]
    findings: list[dict[str, Any]]

    # NetSniper v1.4 intelligence fields.
    # These default values preserve compatibility with older tests and older bundles.
    device_type_confidence: int | None = None
    classification_type: str | None = None
    classification_primary_type: str | None = None
    classification_confidence: int | None = None
    classification_confidence_label: str | None = None
    classification_decision: str | None = None
    classification_method: str | None = None
    classification_json: str = "{}"
    classification_evidence_json: str = "[]"
    classification_contradictions_json: str = "[]"
    classification_candidates_json: str = "[]"

    # NetSniper v1.6 SIEM-facing classification calibration fields.
    classification_confidence_band: str | None = None
    classification_calibrated_decision: str | None = None
    classification_siem_action: str | None = None
    classification_calibration_reason: str | None = None
    classification_validation_state: str | None = None
    classification_contradiction_count: int | None = None
    classification_validator_summary_json: str = "{}"
    classification_validators_json: str = "[]"


@dataclass
class Snapshot:
    scan_id: str
    manifest_path: str
    manifest_schema_version: str
    target: str
    scanner_version: str
    scan_profile: str
    profile_fingerprint: str
    monitored_ports: tuple[int, ...]
    protocols: tuple[str, ...]
    created_at: str
    scan_started_at: str | None
    scan_completed_at: str | None
    neighbors_captured_at: str | None
    discovery_interface: str | None
    nmap_version: str | None
    bundle_status: str
    xml_exit_status: str
    hosts_up: int
    hosts_down: int
    hosts_total: int
    assets: dict[str, AssetObservation]

    @property
    def mac_backed_assets(self) -> int:
        return sum(1 for asset in self.assets.values() if asset.asset_key.startswith("mac:"))

    @property
    def identity_coverage(self) -> float:
        return self.mac_backed_assets / len(self.assets) if self.assets else 0.0


SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS snapshots (
    scan_id TEXT PRIMARY KEY,
    manifest_path TEXT NOT NULL,
    target TEXT NOT NULL,
    network_scope TEXT NOT NULL DEFAULT '',
    scanner_version TEXT NOT NULL,
    scan_profile TEXT NOT NULL,
    created_at TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    bundle_status TEXT NOT NULL,
    quality_status TEXT NOT NULL,
    quality_reason TEXT NOT NULL,
    xml_exit_status TEXT NOT NULL,
    hosts_up INTEGER NOT NULL,
    hosts_down INTEGER NOT NULL,
    hosts_total INTEGER NOT NULL,
    mac_backed_assets INTEGER NOT NULL,
    identity_coverage REAL NOT NULL,
    is_accepted_baseline INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS asset_observations (
    scan_id TEXT NOT NULL,
    asset_key TEXT NOT NULL,
    identity_confidence TEXT NOT NULL,
    identity_source TEXT NOT NULL,
    ip_address TEXT NOT NULL,
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
    PRIMARY KEY (scan_id, asset_key),
    FOREIGN KEY (scan_id) REFERENCES snapshots(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_asset_observations_ip
    ON asset_observations(scan_id, ip_address);

CREATE TABLE IF NOT EXISTS service_observations (
    scan_id TEXT NOT NULL,
    asset_key TEXT NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    state TEXT NOT NULL,
    service_name TEXT,
    product TEXT,
    version TEXT,
    PRIMARY KEY (scan_id, asset_key, protocol, port),
    FOREIGN KEY (scan_id, asset_key)
        REFERENCES asset_observations(scan_id, asset_key) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS finding_observations (
    scan_id TEXT NOT NULL,
    asset_key TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    name TEXT,
    service TEXT,
    port INTEGER,
    score INTEGER,
    evidence TEXT,
    PRIMARY KEY (scan_id, asset_key, finding_id, port),
    FOREIGN KEY (scan_id, asset_key)
        REFERENCES asset_observations(scan_id, asset_key) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS delta_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    baseline_scan_id TEXT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    previous_value TEXT,
    current_value TEXT,
    summary TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES snapshots(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS asset_lifecycle (
    network_scope TEXT NOT NULL DEFAULT '',
    asset_key TEXT NOT NULL,
    identity_class TEXT NOT NULL,
    state TEXT NOT NULL,
    missing_count INTEGER NOT NULL DEFAULT 0,
    current_ip TEXT NOT NULL,
    mac_address TEXT,
    vendor TEXT,
    hostname TEXT,
    first_seen_scan_id TEXT NOT NULL,
    last_seen_scan_id TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    removed_at TEXT,
    PRIMARY KEY (network_scope, asset_key)
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    status TEXT NOT NULL,
    summary TEXT NOT NULL,
    opened_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    resolved_at TEXT,
    first_event_id INTEGER,
    last_event_id INTEGER
);

CREATE TABLE IF NOT EXISTS alert_notes (
    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_alert_notes_alert_id ON alert_notes(alert_id);



CREATE TABLE IF NOT EXISTS asset_annotations (
    asset_key TEXT PRIMARY KEY,
    owner TEXT,
    role TEXT,
    criticality TEXT,
    notes TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_annotation_history (
    annotation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_key TEXT NOT NULL,
    owner TEXT,
    role TEXT,
    criticality TEXT,
    notes TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_asset_annotation_history_asset_key
ON asset_annotation_history(asset_key);

CREATE TABLE IF NOT EXISTS asset_investigations (
    network_scope TEXT NOT NULL DEFAULT '',
    asset_key TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (network_scope, asset_key)
);

CREATE TABLE IF NOT EXISTS asset_investigation_history (
    investigation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_scope TEXT NOT NULL DEFAULT '',
    asset_key TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_asset_investigation_history_asset
ON asset_investigation_history(network_scope, asset_key);


CREATE TABLE IF NOT EXISTS investigation_ticket_state (
    ticket_key TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'OPEN',
    analyst TEXT,
    note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT,
    suppressed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_investigation_ticket_state_status
    ON investigation_ticket_state(status);

CREATE INDEX IF NOT EXISTS idx_investigation_ticket_state_updated_at
    ON investigation_ticket_state(updated_at);


CREATE TABLE IF NOT EXISTS investigation_ticket_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_key TEXT NOT NULL,
    previous_status TEXT,
    new_status TEXT NOT NULL,
    analyst TEXT,
    note TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_investigation_ticket_history_ticket_key
    ON investigation_ticket_history(ticket_key);

CREATE INDEX IF NOT EXISTS idx_investigation_ticket_history_created_at
    ON investigation_ticket_history(created_at);

CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    network_scope TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    netsniper_path TEXT NOT NULL DEFAULT '',
    runs_dir TEXT NOT NULL DEFAULT '',
    bundle_path TEXT,
    exit_code INTEGER,
    auto_ingest INTEGER NOT NULL DEFAULT 0,
    stdout_log TEXT,
    stderr_log TEXT,
    status_json TEXT NOT NULL DEFAULT '{}',
    message TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_created_at
    ON scan_jobs(created_at);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_status
    ON scan_jobs(status);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_scope
    ON scan_jobs(network_scope);

"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()






def ensure_netsniper_intelligence_host_schema(connection: sqlite3.Connection) -> None:
    connection.execute("""
        CREATE TABLE IF NOT EXISTS netsniper_intelligence_hosts (
            scan_id TEXT NOT NULL,
            host_id TEXT NOT NULL,
            ip TEXT,
            mac TEXT,
            hostname TEXT,
            device_type TEXT,
            device_type_confidence INTEGER NOT NULL DEFAULT 0,
            severity TEXT,
            score INTEGER NOT NULL DEFAULT 0,
            primary_type TEXT,
            category TEXT,
            confidence INTEGER NOT NULL DEFAULT 0,
            confidence_band TEXT,
            decision TEXT,
            siem_action TEXT,
            evidence_count INTEGER NOT NULL DEFAULT 0,
            contradiction_count INTEGER NOT NULL DEFAULT 0,
            secondary_candidate_count INTEGER NOT NULL DEFAULT 0,
            explanation TEXT,
            observed_summary_json TEXT NOT NULL DEFAULT '{}',
            observed_json TEXT NOT NULL DEFAULT '{}',
            evidence_json TEXT NOT NULL DEFAULT '[]',
            contradictions_json TEXT NOT NULL DEFAULT '[]',
            secondary_candidates_json TEXT NOT NULL DEFAULT '[]',
            findings_json TEXT NOT NULL DEFAULT '[]',
            raw_host_json TEXT NOT NULL DEFAULT '{}',
            imported_at TEXT NOT NULL,
            PRIMARY KEY (scan_id, host_id)
        )
    """)

def ensure_netsniper_intelligence_schema(connection: sqlite3.Connection) -> None:
    connection.execute("""
        CREATE TABLE IF NOT EXISTS netsniper_intelligence_summaries (
            scan_id TEXT PRIMARY KEY,
            manifest_path TEXT NOT NULL,
            analysis_enriched_json TEXT,
            classification_quality_json TEXT,
            classification_quality_markdown TEXT,
            host_count INTEGER NOT NULL DEFAULT 0,
            classified_count INTEGER NOT NULL DEFAULT 0,
            possible_or_review_count INTEGER NOT NULL DEFAULT 0,
            unknown_count INTEGER NOT NULL DEFAULT 0,
            contradiction_host_count INTEGER NOT NULL DEFAULT 0,
            false_confidence_candidate_count INTEGER NOT NULL DEFAULT 0,
            unknown_with_exposed_services_count INTEGER NOT NULL DEFAULT 0,
            decision_counts_json TEXT NOT NULL DEFAULT '{}',
            siem_action_counts_json TEXT NOT NULL DEFAULT '{}',
            confidence_band_counts_json TEXT NOT NULL DEFAULT '{}',
            top_device_types_json TEXT NOT NULL DEFAULT '{}',
            review_queue_json TEXT NOT NULL DEFAULT '[]',
            contradiction_review_json TEXT NOT NULL DEFAULT '[]',
            false_confidence_candidates_json TEXT NOT NULL DEFAULT '[]',
            unknown_with_exposed_services_json TEXT NOT NULL DEFAULT '[]',
            sample_explanations_json TEXT NOT NULL DEFAULT '{}',
            imported_at TEXT NOT NULL
        )
    """)

def ensure_column(connection: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def backfill_snapshot_network_scopes(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        """
        SELECT scan_id, target, network_scope
        FROM snapshots
        WHERE network_scope IS NULL OR network_scope = ''
        """
    ).fetchall()

    for row in rows:
        try:
            scope = canonical_network_scope(row["target"])
        except ValueError:
            scope = str(row["target"] or "").strip()

        connection.execute(
            "UPDATE snapshots SET network_scope = ? WHERE scan_id = ?",
            (scope, row["scan_id"]),
        )


def ensure_scoped_asset_lifecycle_schema(connection: sqlite3.Connection) -> None:
    columns = [row[1] for row in connection.execute("PRAGMA table_info(asset_lifecycle)")]
    pk_columns = [
        row[1]
        for row in connection.execute("PRAGMA table_info(asset_lifecycle)")
        if int(row[5]) > 0
    ]

    if "network_scope" in columns and set(pk_columns) == {"network_scope", "asset_key"}:
        return

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_lifecycle_scoped_migration (
            network_scope TEXT NOT NULL DEFAULT '',
            asset_key TEXT NOT NULL,
            identity_class TEXT NOT NULL,
            state TEXT NOT NULL,
            missing_count INTEGER NOT NULL DEFAULT 0,
            current_ip TEXT NOT NULL,
            mac_address TEXT,
            vendor TEXT,
            hostname TEXT,
            first_seen_scan_id TEXT NOT NULL,
            last_seen_scan_id TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            removed_at TEXT,
            PRIMARY KEY (network_scope, asset_key)
        )
        """
    )

    has_network_scope = "network_scope" in columns
    scope_expr = "COALESCE(s.network_scope, '')"

    if has_network_scope:
        scope_expr = "COALESCE(al.network_scope, s.network_scope, '')"

    connection.execute(
        f"""
        INSERT OR IGNORE INTO asset_lifecycle_scoped_migration (
            network_scope,
            asset_key,
            identity_class,
            state,
            missing_count,
            current_ip,
            mac_address,
            vendor,
            hostname,
            first_seen_scan_id,
            last_seen_scan_id,
            first_seen_at,
            last_seen_at,
            removed_at
        )
        SELECT
            {scope_expr},
            al.asset_key,
            al.identity_class,
            al.state,
            al.missing_count,
            al.current_ip,
            al.mac_address,
            al.vendor,
            al.hostname,
            al.first_seen_scan_id,
            al.last_seen_scan_id,
            al.first_seen_at,
            al.last_seen_at,
            al.removed_at
        FROM asset_lifecycle al
        LEFT JOIN snapshots s ON s.scan_id = al.last_seen_scan_id
        """
    )

    connection.execute("DROP TABLE asset_lifecycle")
    connection.execute("ALTER TABLE asset_lifecycle_scoped_migration RENAME TO asset_lifecycle")


def ensure_enterprise_access_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS access_users ("
        "user_id TEXT PRIMARY KEY,"
        "username TEXT NOT NULL UNIQUE,"
        "display_name TEXT,"
        "role TEXT NOT NULL DEFAULT 'VIEWER',"
        "password_hash TEXT NOT NULL DEFAULT '',"
        "is_active INTEGER NOT NULL DEFAULT 1,"
        "created_at TEXT NOT NULL,"
        "updated_at TEXT NOT NULL,"
        "last_login_at TEXT,"
        "CHECK (role IN ('ADMIN', 'ANALYST', 'VIEWER'))"
        ")"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_users_username "
        "ON access_users(username)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_users_role "
        "ON access_users(role)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS access_api_tokens ("
        "token_id TEXT PRIMARY KEY,"
        "user_id TEXT NOT NULL,"
        "token_name TEXT NOT NULL,"
        "token_hash TEXT NOT NULL UNIQUE,"
        "token_prefix TEXT NOT NULL,"
        "role TEXT NOT NULL DEFAULT 'VIEWER',"
        "is_active INTEGER NOT NULL DEFAULT 1,"
        "created_at TEXT NOT NULL,"
        "updated_at TEXT NOT NULL,"
        "last_used_at TEXT,"
        "expires_at TEXT,"
        "FOREIGN KEY (user_id) REFERENCES access_users(user_id) ON DELETE CASCADE,"
        "CHECK (role IN ('ADMIN', 'ANALYST', 'VIEWER'))"
        ")"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_api_tokens_user_id "
        "ON access_api_tokens(user_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_api_tokens_prefix "
        "ON access_api_tokens(token_prefix)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS access_audit_log ("
        "audit_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "actor_user_id TEXT,"
        "actor_username TEXT,"
        "actor_role TEXT,"
        "action TEXT NOT NULL,"
        "target_type TEXT,"
        "target_key TEXT,"
        "source_ip TEXT,"
        "user_agent TEXT,"
        "detail_json TEXT NOT NULL DEFAULT '{}',"
        "created_at TEXT NOT NULL,"
        "FOREIGN KEY (actor_user_id) REFERENCES access_users(user_id) ON DELETE SET NULL"
        ")"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_audit_log_created_at "
        "ON access_audit_log(created_at)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_audit_log_action "
        "ON access_audit_log(action)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_audit_log_actor_user_id "
        "ON access_audit_log(actor_user_id)"
    )


def normalize_access_role(value: str | None, default: str = "VIEWER") -> str:
    role = str(value or default or "VIEWER").strip().upper().replace("-", "_").replace(" ", "_")

    if role not in ACCESS_ROLE_RANKS:
        raise DeltaAegisError(f"unsupported access role: {value!r}")

    return role


def access_role_allows(role: str | None, required_role: str | None) -> bool:
    actual = normalize_access_role(role)
    required = normalize_access_role(required_role)

    return ACCESS_ROLE_RANKS[actual] >= ACCESS_ROLE_RANKS[required]


def normalize_access_username(username: str) -> str:
    value = str(username or "").strip().lower()

    if not value:
        raise DeltaAegisError("username is required")

    if not re.fullmatch(r"[a-z0-9_.@-]{3,64}", value):
        raise DeltaAegisError(
            "username must be 3-64 characters using letters, numbers, dot, underscore, at-sign, or dash"
        )

    return value


def hash_access_password(password: str, salt: str | None = None, iterations: int = ACCESS_PASSWORD_ITERATIONS) -> str:
    if not password:
        raise DeltaAegisError("password is required")

    if iterations < 100000:
        raise DeltaAegisError("password hash iteration count is too low")

    salt_value = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        str(password).encode("utf-8"),
        salt_value.encode("utf-8"),
        iterations,
    ).hex()

    return f"{ACCESS_PASSWORD_ALGORITHM}${iterations}${salt_value}${digest}"


def verify_access_password(password: str, password_hash: str | None) -> bool:
    if not password or not password_hash:
        return False

    try:
        algorithm, iterations_text, salt, expected_digest = str(password_hash).split("$", 3)
        iterations = int(iterations_text)
    except (TypeError, ValueError):
        return False

    if algorithm != ACCESS_PASSWORD_ALGORITHM:
        return False

    candidate = hash_access_password(password, salt=salt, iterations=iterations)
    candidate_digest = candidate.rsplit("$", 1)[-1]

    return hmac.compare_digest(candidate_digest, expected_digest)


def hash_access_api_token(token: str) -> str:
    if not token:
        raise DeltaAegisError("API token is required")

    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


def generate_access_api_token() -> str:
    return f"{ACCESS_API_TOKEN_PREFIX}_{secrets.token_urlsafe(32)}"


def create_access_user(
    connection: sqlite3.Connection,
    username: str,
    role: str = "VIEWER",
    password: str | None = None,
    display_name: str | None = None,
    is_active: bool = True,
) -> dict[str, Any]:
    ensure_enterprise_access_schema(connection)

    normalized_username = normalize_access_username(username)
    normalized_role = normalize_access_role(role)
    now = utc_now()
    user_id = str(uuid.uuid4())
    password_hash = hash_access_password(password) if password else ""

    connection.execute(
        "INSERT INTO access_users ("
        "user_id, username, display_name, role, password_hash, is_active, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            user_id,
            normalized_username,
            display_name,
            normalized_role,
            password_hash,
            1 if is_active else 0,
            now,
            now,
        ),
    )

    return {
        "user_id": user_id,
        "username": normalized_username,
        "display_name": display_name,
        "role": normalized_role,
        "is_active": bool(is_active),
        "created_at": now,
        "updated_at": now,
    }


def access_user_by_username(connection: sqlite3.Connection, username: str) -> dict[str, Any] | None:
    ensure_enterprise_access_schema(connection)

    normalized_username = normalize_access_username(username)
    row = connection.execute(
        "SELECT user_id, username, display_name, role, password_hash, is_active, "
        "created_at, updated_at, last_login_at "
        "FROM access_users WHERE username = ?",
        (normalized_username,),
    ).fetchone()

    if not row:
        return None

    return dict(row)


def list_access_users(connection: sqlite3.Connection, include_inactive: bool = False) -> list[dict[str, Any]]:
    ensure_enterprise_access_schema(connection)

    where = "" if include_inactive else "WHERE is_active = 1"
    rows = connection.execute(
        "SELECT user_id, username, display_name, role, is_active, created_at, updated_at, last_login_at "
        f"FROM access_users {where} ORDER BY username"
    ).fetchall()

    return [dict(row) for row in rows]


def create_access_api_token(
    connection: sqlite3.Connection,
    user_id: str,
    token_name: str,
    role: str | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    ensure_enterprise_access_schema(connection)

    user = connection.execute(
        "SELECT user_id, username, role, is_active FROM access_users WHERE user_id = ?",
        (user_id,),
    ).fetchone()

    if not user:
        raise DeltaAegisError(f"access user not found: {user_id}")

    if not int(user["is_active"] or 0):
        raise DeltaAegisError(f"access user is inactive: {user['username']}")

    token_value = generate_access_api_token()
    token_hash = hash_access_api_token(token_value)
    token_id = str(uuid.uuid4())
    now = utc_now()
    token_role = normalize_access_role(role or user["role"])
    token_prefix = token_value[:12]
    clean_token_name = str(token_name or "DeltaAegis API Token").strip() or "DeltaAegis API Token"

    connection.execute(
        "INSERT INTO access_api_tokens ("
        "token_id, user_id, token_name, token_hash, token_prefix, role, "
        "is_active, created_at, updated_at, expires_at"
        ") VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
        (
            token_id,
            user_id,
            clean_token_name,
            token_hash,
            token_prefix,
            token_role,
            now,
            now,
            expires_at,
        ),
    )

    return {
        "token_id": token_id,
        "user_id": user_id,
        "username": user["username"],
        "token_name": clean_token_name,
        "token": token_value,
        "token_prefix": token_prefix,
        "role": token_role,
        "created_at": now,
        "expires_at": expires_at,
    }


def record_access_audit_event(
    connection: sqlite3.Connection,
    action: str,
    actor: dict[str, Any] | None = None,
    target_type: str | None = None,
    target_key: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
    details: dict[str, Any] | None = None,
) -> int:
    ensure_enterprise_access_schema(connection)

    actor = actor or {}
    now = utc_now()
    cursor = connection.execute(
        "INSERT INTO access_audit_log ("
        "actor_user_id, actor_username, actor_role, action, target_type, target_key, "
        "source_ip, user_agent, detail_json, created_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            actor.get("user_id"),
            actor.get("username"),
            actor.get("role"),
            str(action or "").strip().upper() or "UNKNOWN",
            target_type,
            target_key,
            source_ip,
            user_agent,
            json.dumps(details or {}, sort_keys=True),
            now,
        ),
    )

    return int(cursor.lastrowid)


def ensure_dashboard_session_schema(connection: sqlite3.Connection) -> None:
    ensure_enterprise_access_schema(connection)

    connection.execute(
        "CREATE TABLE IF NOT EXISTS access_sessions ("
        "session_id TEXT PRIMARY KEY, "
        "user_id TEXT NOT NULL, "
        "session_token_hash TEXT NOT NULL UNIQUE, "
        "role TEXT NOT NULL, "
        "is_active INTEGER NOT NULL DEFAULT 1, "
        "created_at TEXT NOT NULL, "
        "last_seen_at TEXT, "
        "expires_at TEXT NOT NULL, "
        "source_ip TEXT, "
        "user_agent TEXT, "
        "ended_at TEXT, "
        "end_reason TEXT, "
        "FOREIGN KEY(user_id) REFERENCES access_users(user_id)"
        ")"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_sessions_user_id "
        "ON access_sessions(user_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_sessions_token_hash "
        "ON access_sessions(session_token_hash)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_sessions_expires_at "
        "ON access_sessions(expires_at)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_sessions_active "
        "ON access_sessions(is_active)"
    )


def generate_dashboard_session_token() -> str:
    return "ds_" + secrets.token_urlsafe(32)


def hash_dashboard_session_token(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def dashboard_session_expiry(ttl_seconds: int = ACCESS_SESSION_TTL_SECONDS) -> str:
    ttl = max(300, int(ttl_seconds or ACCESS_SESSION_TTL_SECONDS))
    return (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat()


def dashboard_user_login(
    connection: sqlite3.Connection,
    username: str,
    password: str,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> dict[str, Any] | None:
    ensure_dashboard_session_schema(connection)

    normalized_username = normalize_access_username(username)
    user = access_user_by_username(connection, normalized_username)

    if not user or not int(user.get("is_active") or 0):
        record_access_audit_event(
            connection,
            action="LOGIN_FAILED",
            actor={
                "username": normalized_username or str(username or "").strip(),
                "role": None,
            },
            target_type="access_user",
            target_key=normalized_username or str(username or "").strip(),
            source_ip=source_ip,
            user_agent=user_agent,
            details={"reason": "unknown_or_inactive_user"},
        )
        connection.commit()
        return None

    if not verify_access_password(password, user.get("password_hash") or ""):
        record_access_audit_event(
            connection,
            action="LOGIN_FAILED",
            actor={
                "user_id": user.get("user_id"),
                "username": user.get("username"),
                "role": user.get("role"),
            },
            target_type="access_user",
            target_key=user.get("username"),
            source_ip=source_ip,
            user_agent=user_agent,
            details={"reason": "invalid_password"},
        )
        connection.commit()
        return None

    return create_dashboard_session(
        connection,
        user,
        source_ip=source_ip,
        user_agent=user_agent,
    )


def create_dashboard_session(
    connection: sqlite3.Connection,
    user: dict[str, Any],
    source_ip: str | None = None,
    user_agent: str | None = None,
    ttl_seconds: int = ACCESS_SESSION_TTL_SECONDS,
) -> dict[str, Any]:
    ensure_dashboard_session_schema(connection)

    session_id = str(uuid.uuid4())
    session_token = generate_dashboard_session_token()
    session_hash = hash_dashboard_session_token(session_token)
    now = utc_now()
    expires_at = dashboard_session_expiry(ttl_seconds)

    role = normalize_access_role(user.get("role") or "VIEWER")

    connection.execute(
        "INSERT INTO access_sessions ("
        "session_id, user_id, session_token_hash, role, is_active, "
        "created_at, last_seen_at, expires_at, source_ip, user_agent"
        ") VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)",
        (
            session_id,
            user.get("user_id"),
            session_hash,
            role,
            now,
            now,
            expires_at,
            source_ip,
            user_agent,
        ),
    )

    actor = {
        "user_id": user.get("user_id"),
        "username": user.get("username"),
        "role": role,
    }

    record_access_audit_event(
        connection,
        action="LOGIN_SUCCESS",
        actor=actor,
        target_type="access_session",
        target_key=session_id,
        source_ip=source_ip,
        user_agent=user_agent,
        details={
            "session_id": session_id,
            "expires_at": expires_at,
            "role": role,
        },
    )
    connection.commit()

    return {
        "session_id": session_id,
        "session_token": session_token,
        "session_token_hash": session_hash,
        "user_id": user.get("user_id"),
        "username": user.get("username"),
        "display_name": user.get("display_name"),
        "role": role,
        "expires_at": expires_at,
    }


def session_is_expired(expires_at: str | None) -> bool:
    if not expires_at:
        return True

    try:
        expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
    except ValueError:
        return True

    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)

    return expiry <= datetime.now(timezone.utc)


def authenticate_dashboard_session(
    connection: sqlite3.Connection,
    session_token: str,
    required_role: str = "VIEWER",
    update_last_seen: bool = True,
) -> dict[str, Any] | None:
    ensure_dashboard_session_schema(connection)

    token = str(session_token or "").strip()

    if not token:
        return None

    session_hash = hash_dashboard_session_token(token)

    row = connection.execute(
        "SELECT "
        "s.session_id, "
        "s.user_id, "
        "s.role AS session_role, "
        "s.is_active AS session_active, "
        "s.created_at AS session_created_at, "
        "s.last_seen_at, "
        "s.expires_at, "
        "u.username, "
        "u.display_name, "
        "u.role AS user_role, "
        "u.is_active AS user_active "
        "FROM access_sessions s "
        "JOIN access_users u ON u.user_id = s.user_id "
        "WHERE s.session_token_hash = ?",
        (session_hash,),
    ).fetchone()

    if not row:
        return None

    actor = {
        "auth_type": "dashboard_session",
        "session_id": row["session_id"],
        "user_id": row["user_id"],
        "username": row["username"],
        "display_name": row["display_name"],
        "role": normalize_access_role(row["session_role"] or row["user_role"] or "VIEWER"),
        "expires_at": row["expires_at"],
    }

    if not int(row["session_active"] or 0) or not int(row["user_active"] or 0):
        return None

    if session_is_expired(row["expires_at"]):
        expire_dashboard_session(
            connection,
            token,
            actor=actor,
            reason="expired",
            commit=True,
        )
        return None

    if not access_role_allows(actor["role"], required_role):
        return None

    if update_last_seen:
        now = utc_now()
        connection.execute(
            "UPDATE access_sessions "
            "SET last_seen_at = ? "
            "WHERE session_id = ?",
            (now, row["session_id"]),
        )
        connection.commit()
        actor["last_seen_at"] = now

    return actor


def expire_dashboard_session(
    connection: sqlite3.Connection,
    session_token: str,
    actor: dict[str, Any] | None = None,
    reason: str = "logout",
    commit: bool = True,
) -> bool:
    ensure_dashboard_session_schema(connection)

    token = str(session_token or "").strip()

    if not token:
        return False

    session_hash = hash_dashboard_session_token(token)
    now = utc_now()

    row = connection.execute(
        "SELECT session_id, user_id, role "
        "FROM access_sessions "
        "WHERE session_token_hash = ?",
        (session_hash,),
    ).fetchone()

    if not row:
        return False

    connection.execute(
        "UPDATE access_sessions "
        "SET is_active = 0, ended_at = ?, end_reason = ? "
        "WHERE session_id = ?",
        (now, str(reason or "logout"), row["session_id"]),
    )

    record_access_audit_event(
        connection,
        action="LOGOUT" if str(reason or "").lower() == "logout" else "SESSION_EXPIRED",
        actor=actor,
        target_type="access_session",
        target_key=row["session_id"],
        details={"reason": reason},
    )

    if commit:
        connection.commit()

    return True

def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA_SQL)
    ensure_column(connection, "snapshots", "manifest_schema_version", "manifest_schema_version TEXT NOT NULL DEFAULT 'netsniper-run-v1'")
    ensure_column(connection, "snapshots", "profile_fingerprint", "profile_fingerprint TEXT NOT NULL DEFAULT ''")
    ensure_column(connection, "snapshots", "monitored_ports_json", "monitored_ports_json TEXT NOT NULL DEFAULT '[]'")
    ensure_column(connection, "snapshots", "protocols_json", "protocols_json TEXT NOT NULL DEFAULT '[]'")
    ensure_column(connection, "snapshots", "discovery_interface", "discovery_interface TEXT")
    ensure_column(connection, "snapshots", "nmap_version", "nmap_version TEXT")
    ensure_column(connection, "snapshots", "scan_started_at", "scan_started_at TEXT")
    ensure_column(connection, "snapshots", "scan_completed_at", "scan_completed_at TEXT")
    ensure_column(connection, "snapshots", "neighbors_captured_at", "neighbors_captured_at TEXT")
    ensure_column(connection, "snapshots", "network_scope", "network_scope TEXT NOT NULL DEFAULT ''")
    ensure_column(connection, "asset_observations", "identity_class", "identity_class TEXT NOT NULL DEFAULT 'IP_ONLY'")

    # NetSniper v1.4 classification intelligence columns.
    ensure_column(connection, "asset_observations", "device_type_confidence", "device_type_confidence INTEGER")
    ensure_column(connection, "asset_observations", "classification_type", "classification_type TEXT")
    ensure_column(connection, "asset_observations", "classification_primary_type", "classification_primary_type TEXT")
    ensure_column(connection, "asset_observations", "classification_confidence", "classification_confidence INTEGER")
    ensure_column(connection, "asset_observations", "classification_confidence_label", "classification_confidence_label TEXT")
    ensure_column(connection, "asset_observations", "classification_decision", "classification_decision TEXT")
    ensure_column(connection, "asset_observations", "classification_method", "classification_method TEXT")
    ensure_column(connection, "asset_observations", "classification_json", "classification_json TEXT NOT NULL DEFAULT '{}'")
    ensure_column(connection, "asset_observations", "classification_evidence_json", "classification_evidence_json TEXT NOT NULL DEFAULT '[]'")
    ensure_column(connection, "asset_observations", "classification_contradictions_json", "classification_contradictions_json TEXT NOT NULL DEFAULT '[]'")
    ensure_column(connection, "asset_observations", "classification_candidates_json", "classification_candidates_json TEXT NOT NULL DEFAULT '[]'")

    # NetSniper v1.6 SIEM-facing classification calibration columns.
    ensure_column(connection, "asset_observations", "classification_confidence_band", "classification_confidence_band TEXT")
    ensure_column(connection, "asset_observations", "classification_calibrated_decision", "classification_calibrated_decision TEXT")
    ensure_column(connection, "asset_observations", "classification_siem_action", "classification_siem_action TEXT")
    ensure_column(connection, "asset_observations", "classification_calibration_reason", "classification_calibration_reason TEXT")
    ensure_column(connection, "asset_observations", "classification_validation_state", "classification_validation_state TEXT")
    ensure_column(connection, "asset_observations", "classification_contradiction_count", "classification_contradiction_count INTEGER")
    ensure_column(connection, "asset_observations", "classification_validator_summary_json", "classification_validator_summary_json TEXT NOT NULL DEFAULT '{}'")
    ensure_column(connection, "asset_observations", "classification_validators_json", "classification_validators_json TEXT NOT NULL DEFAULT '[]'")

    backfill_snapshot_network_scopes(connection)
    ensure_scoped_asset_lifecycle_schema(connection)
    ensure_enterprise_access_schema(connection)
    ensure_dashboard_session_schema(connection)
    connection.commit()
    return connection


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DeltaAegisError(f"could not read JSON {path}: {exc}") from exc


def require_file(bundle_dir: Path, manifest: dict[str, Any], key: str) -> Path:
    filename = manifest.get("files", {}).get(key)
    if not isinstance(filename, str) or not filename:
        raise DeltaAegisError(f"manifest missing files.{key}")
    path = bundle_dir / filename
    if not path.is_file():
        raise DeltaAegisError(f"required bundle file is missing: {path}")
    return path


def optional_file(bundle_dir: Path, manifest: dict[str, Any], key: str) -> Path | None:
    filename = manifest.get("files", {}).get(key)
    if not isinstance(filename, str) or not filename:
        return None
    path = bundle_dir / filename
    return path if path.is_file() else None


def analysis_by_ip(path: Path) -> dict[str, dict[str, Any]]:
    raw = load_json(path)
    if not isinstance(raw, list):
        raise DeltaAegisError(f"analysis JSON must be a list: {path}")
    return {item["host"]: item for item in raw if isinstance(item, dict) and isinstance(item.get("host"), str)}


def safe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def canonical_network_scope(target: str) -> str:
    return str(ipaddress.ip_network(str(target).strip(), strict=False))


def optional_network_scope(value: str | None) -> str | None:
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    return canonical_network_scope(value)


def snapshot_network_scope(snapshot_or_target) -> str:
    target = getattr(snapshot_or_target, "target", snapshot_or_target)
    return canonical_network_scope(str(target))


def parse_target_network(target: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise DeltaAegisError(f"manifest target is not a valid CIDR or IP address: {target!r}") from exc


def is_usable_target_address(raw_ip: str, target_network: ipaddress._BaseNetwork) -> bool:
    try:
        address = ipaddress.ip_address(raw_ip)
    except ValueError:
        return False
    if address.version != target_network.version or address not in target_network:
        return False
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        return False
    if isinstance(target_network, ipaddress.IPv4Network) and target_network.prefixlen <= 30:
        if address in {target_network.network_address, target_network.broadcast_address}:
            return False
    return True


def normalize_mac(raw_mac: str | None) -> str | None:
    if not raw_mac:
        return None
    normalized = raw_mac.strip().lower().replace("-", ":")
    return normalized if MAC_RE.fullmatch(normalized) else None


def classify_identity(mac_address: str | None) -> str:
    if not mac_address:
        return "IP_ONLY"
    first_octet = int(mac_address.split(":", 1)[0], 16)
    return "LOCAL_MAC" if first_octet & 0x02 else "GLOBAL_MAC"


def parse_discovery_xml(path: Path, target_network: ipaddress._BaseNetwork) -> dict[str, IdentityEvidence]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise DeltaAegisError(f"could not parse discovery XML {path}: {exc}") from exc
    result: dict[str, IdentityEvidence] = {}
    for host in root.findall("./host"):
        status = host.find("./status")
        if status is None or status.attrib.get("state") != "up":
            continue
        ipv4 = None
        mac = None
        vendor = None
        for address in host.findall("./address"):
            if address.attrib.get("addrtype") == "ipv4":
                ipv4 = address.attrib.get("addr")
            elif address.attrib.get("addrtype") == "mac":
                mac = normalize_mac(address.attrib.get("addr"))
                vendor = address.attrib.get("vendor")
        if not ipv4 or not is_usable_target_address(ipv4, target_network):
            continue
        hostname_node = host.find("./hostnames/hostname")
        hostname = hostname_node.attrib.get("name") if hostname_node is not None else None
        result[ipv4] = IdentityEvidence(mac, vendor, hostname, "DISCOVERY_XML" if mac else "IP_ONLY")
    return result


def parse_neighbors(path: Path | None, target_network: ipaddress._BaseNetwork) -> dict[str, str]:
    if path is None:
        return {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise DeltaAegisError(f"could not read neighbor telemetry {path}: {exc}") from exc
    result: dict[str, str] = {}
    for line in lines:
        fields = line.split()
        if len(fields) < 5 or "lladdr" not in fields:
            continue
        ip = fields[0]
        if not is_usable_target_address(ip, target_network):
            continue
        try:
            mac = normalize_mac(fields[fields.index("lladdr") + 1])
        except (ValueError, IndexError):
            continue
        if mac:
            result[ip] = mac
    return result


def identity_rank(source: str) -> int:
    return {"IP_ONLY": 0, "NEIGHBOR_TABLE": 1, "SERVICE_XML": 2, "DISCOVERY_XML": 3}.get(source, 0)


def parse_service_xml(path: Path, analysis: dict[str, dict[str, Any]], target_network: ipaddress._BaseNetwork, discovery: dict[str, IdentityEvidence], neighbors: dict[str, str]) -> tuple[str, int, int, int, dict[str, AssetObservation]]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise DeltaAegisError(f"could not parse XML {path}: {exc}") from exc
    finished = root.find("./runstats/finished")
    hosts_summary = root.find("./runstats/hosts")
    if finished is None or hosts_summary is None:
        raise DeltaAegisError("Nmap XML is missing runstats metadata")
    exit_status = finished.attrib.get("exit", "unknown")
    hosts_up = int(hosts_summary.attrib.get("up", "0"))
    hosts_down = int(hosts_summary.attrib.get("down", "0"))
    hosts_total = int(hosts_summary.attrib.get("total", "0"))
    preliminary: list[AssetObservation] = []
    for host in root.findall("./host"):
        status = host.find("./status")
        if status is None or status.attrib.get("state") != "up":
            continue
        ipv4 = None
        service_xml_mac = None
        service_xml_vendor = None
        for address in host.findall("./address"):
            if address.attrib.get("addrtype") == "ipv4":
                ipv4 = address.attrib.get("addr")
            elif address.attrib.get("addrtype") == "mac":
                service_xml_mac = normalize_mac(address.attrib.get("addr"))
                service_xml_vendor = address.attrib.get("vendor")
        if not ipv4 or not is_usable_target_address(ipv4, target_network):
            continue
        evidence = discovery.get(ipv4, IdentityEvidence())
        candidates = [
            (evidence.mac_address, evidence.vendor, evidence.source),
            (service_xml_mac, service_xml_vendor, "SERVICE_XML"),
            (neighbors.get(ipv4), None, "NEIGHBOR_TABLE"),
        ]
        candidates = [item for item in candidates if item[0]]
        mac, vendor, source = max(candidates, key=lambda item: identity_rank(item[2])) if candidates else (None, evidence.vendor, "IP_ONLY")
        hostname_node = host.find("./hostnames/hostname")
        hostname = hostname_node.attrib.get("name") if hostname_node is not None else evidence.hostname
        services: list[Service] = []
        for port_node in host.findall("./ports/port"):
            state_node = port_node.find("./state")
            state = state_node.attrib.get("state", "unknown") if state_node is not None else "unknown"
            if state != "open":
                continue
            service_node = port_node.find("./service")
            services.append(Service(
                protocol=port_node.attrib.get("protocol", "unknown").lower(),
                port=int(port_node.attrib["portid"]),
                state=state,
                service_name=service_node.attrib.get("name") if service_node is not None else None,
                product=service_node.attrib.get("product") if service_node is not None else None,
                version=service_node.attrib.get("version") if service_node is not None else None,
            ))
        interpretation = analysis.get(ipv4, {})
        findings = interpretation.get("findings", [])
        if not isinstance(findings, list):
            findings = []

        classification = interpretation.get("classification", {})
        if not isinstance(classification, dict):
            classification = {}

        classification_evidence = classification.get("evidence", [])
        if not isinstance(classification_evidence, list):
            classification_evidence = []

        classification_contradictions = classification.get("contradictions", [])
        if not isinstance(classification_contradictions, list):
            classification_contradictions = []

        classification_candidates = classification.get("candidates", classification.get("secondary_candidates", []))
        if not isinstance(classification_candidates, list):
            classification_candidates = []

        classification_validators = classification.get("validators", [])
        if not isinstance(classification_validators, list):
            classification_validators = []

        classification_validator_summary = classification.get("validator_summary", {})
        if not isinstance(classification_validator_summary, dict):
            classification_validator_summary = {}

        classification_contradiction_count = safe_int(classification.get("contradiction_count"))
        if classification_contradiction_count is None:
            classification_contradiction_count = len(classification_contradictions)

        confidence = "HIGH" if source in {"DISCOVERY_XML", "SERVICE_XML"} else "MEDIUM" if source == "NEIGHBOR_TABLE" else "LOW"

        preliminary.append(
            AssetObservation(
                "",
                classify_identity(mac),
                confidence,
                source,
                ipv4,
                mac,
                vendor,
                hostname,
                interpretation.get("device_type"),
                interpretation.get("severity"),
                safe_int(interpretation.get("score")),
                sorted(services, key=lambda item: item.key),
                [item for item in findings if isinstance(item, dict)],
                device_type_confidence=safe_int(interpretation.get("device_type_confidence")),
                classification_type=classification.get("type"),
                classification_primary_type=classification.get("primary_type", classification.get("type")),
                classification_confidence=safe_int(classification.get("confidence")),
                classification_confidence_label=classification.get("confidence_label"),
                classification_decision=classification.get("decision"),
                classification_method=classification.get("method"),
                classification_json=json.dumps(classification, sort_keys=True),
                classification_evidence_json=json.dumps(classification_evidence, sort_keys=True),
                classification_contradictions_json=json.dumps(classification_contradictions, sort_keys=True),
                classification_candidates_json=json.dumps(classification_candidates, sort_keys=True),
                classification_confidence_band=classification.get("confidence_band"),
                classification_calibrated_decision=classification.get("calibrated_decision"),
                classification_siem_action=classification.get("siem_action"),
                classification_calibration_reason=classification.get("calibration_reason"),
                classification_validation_state=classification.get("validation_state"),
                classification_contradiction_count=classification_contradiction_count,
                classification_validator_summary_json=json.dumps(classification_validator_summary, sort_keys=True),
                classification_validators_json=json.dumps(classification_validators, sort_keys=True),
            )
        )
    service_ips = {asset.ip_address for asset in preliminary}

    for ipv4 in sorted(analysis):
        if ipv4 in service_ips:
            continue

        if not is_usable_target_address(ipv4, target_network):
            continue

        interpretation = analysis.get(ipv4, {})
        if not isinstance(interpretation, dict):
            interpretation = {}

        evidence = discovery.get(ipv4, IdentityEvidence())

        candidates = [
            (evidence.mac_address, evidence.vendor, evidence.source),
            (neighbors.get(ipv4), None, "NEIGHBOR_TABLE"),
        ]
        candidates = [item for item in candidates if item[0]]

        mac, vendor, source = (
            max(candidates, key=lambda item: identity_rank(item[2]))
            if candidates
            else (None, evidence.vendor, "IP_ONLY")
        )

        classification = interpretation.get("classification", {})
        if not isinstance(classification, dict):
            classification = {}

        if not classification:
            classification = {
                "schema_version": "netsniper-classification-v1",
                "type": "Unknown / Ambiguous",
                "primary_type": "Unknown / Ambiguous",
                "confidence": 0,
                "confidence_label": "unknown",
                "confidence_band": "unknown",
                "calibrated_decision": "unknown",
                "siem_action": "no_action",
                "calibration_reason": (
                    "Host was present in the NetSniper inventory but did not have "
                    "monitored service evidence."
                ),
                "validation_state": "not_applicable",
                "contradiction_count": 0,
                "decision": "unknown",
                "method": "deltaaegis_full_inventory_preservation",
                "evidence": [],
                "validators": [],
                "validator_summary": {
                    "total": 0,
                    "confirmed": 0,
                    "inconclusive": 0,
                    "refuted": 0,
                    "not_applicable": 0,
                    "error": 0,
                    "names": [],
                },
                "contradictions": [],
                "candidates": [],
                "secondary_candidates": [],
            }

        findings = interpretation.get("findings", [])
        if not isinstance(findings, list):
            findings = []

        classification_evidence = classification.get("evidence", [])
        if not isinstance(classification_evidence, list):
            classification_evidence = []

        classification_contradictions = classification.get("contradictions", [])
        if not isinstance(classification_contradictions, list):
            classification_contradictions = []

        classification_candidates = classification.get(
            "candidates",
            classification.get("secondary_candidates", []),
        )
        if not isinstance(classification_candidates, list):
            classification_candidates = []

        classification_validators = classification.get("validators", [])
        if not isinstance(classification_validators, list):
            classification_validators = []

        classification_validator_summary = classification.get("validator_summary", {})
        if not isinstance(classification_validator_summary, dict):
            classification_validator_summary = {}

        classification_contradiction_count = safe_int(
            classification.get("contradiction_count")
        )
        if classification_contradiction_count is None:
            classification_contradiction_count = len(classification_contradictions)

        confidence = (
            "HIGH"
            if source in {"DISCOVERY_XML", "SERVICE_XML"}
            else "MEDIUM"
            if source == "NEIGHBOR_TABLE"
            else "LOW"
        )

        preliminary.append(
            AssetObservation(
                "",
                classify_identity(mac),
                confidence,
                source,
                ipv4,
                mac,
                vendor,
                evidence.hostname,
                interpretation.get("device_type") or "Unknown",
                interpretation.get("severity") or "INFO",
                safe_int(interpretation.get("score")) or 0,
                [],
                [item for item in findings if isinstance(item, dict)],
                device_type_confidence=safe_int(
                    interpretation.get("device_type_confidence")
                ) or 0,
                classification_type=classification.get("type")
                or classification.get("primary_type")
                or "Unknown / Ambiguous",
                classification_primary_type=classification.get(
                    "primary_type",
                    classification.get("type", "Unknown / Ambiguous"),
                ),
                classification_confidence=safe_int(classification.get("confidence")) or 0,
                classification_confidence_label=classification.get(
                    "confidence_label",
                    "unknown",
                ),
                classification_decision=classification.get("decision", "unknown"),
                classification_method=classification.get(
                    "method",
                    "deltaaegis_full_inventory_preservation",
                ),
                classification_json=json.dumps(classification, sort_keys=True),
                classification_evidence_json=json.dumps(
                    classification_evidence,
                    sort_keys=True,
                ),
                classification_contradictions_json=json.dumps(
                    classification_contradictions,
                    sort_keys=True,
                ),
                classification_candidates_json=json.dumps(
                    classification_candidates,
                    sort_keys=True,
                ),
                classification_confidence_band=classification.get(
                    "confidence_band",
                    "unknown",
                ),
                classification_calibrated_decision=classification.get(
                    "calibrated_decision",
                    classification.get("decision", "unknown"),
                ),
                classification_siem_action=classification.get("siem_action", "no_action"),
                classification_calibration_reason=classification.get(
                    "calibration_reason",
                ),
                classification_validation_state=classification.get(
                    "validation_state",
                    "not_applicable",
                ),
                classification_contradiction_count=classification_contradiction_count,
                classification_validator_summary_json=json.dumps(
                    classification_validator_summary,
                    sort_keys=True,
                ),
                classification_validators_json=json.dumps(
                    classification_validators,
                    sort_keys=True,
                ),
            )
        )

    mac_counts = Counter(asset.mac_address for asset in preliminary if asset.mac_address)
    assets: dict[str, AssetObservation] = {}
    for asset in preliminary:
        if asset.mac_address and mac_counts[asset.mac_address] == 1:
            asset.asset_key = f"mac:{asset.mac_address}"
        else:
            asset.asset_key = f"ip:{asset.ip_address}"
            asset.identity_class = "IP_ONLY"
            if asset.mac_address and mac_counts[asset.mac_address] > 1:
                asset.identity_confidence = "LOW"
                asset.identity_source = "DUPLICATE_MAC_FALLBACK"
        assets[asset.asset_key] = asset
    return exit_status, hosts_up, hosts_down, hosts_total, assets


def legacy_profile_fingerprint(scan_profile: str, target: str) -> str:
    return "legacy:" + hashlib.sha256(f"{scan_profile}|{target}".encode()).hexdigest()


def load_snapshot(manifest_path: Path) -> Snapshot:
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict):
        raise DeltaAegisError(f"manifest must contain an object: {manifest_path}")
    schema = str(manifest.get("schema_version", ""))
    if schema not in {"netsniper-run-v1", "netsniper-run-v2"}:
        raise DeltaAegisError(f"unsupported manifest schema: {schema!r}")
    if manifest.get("status") != "COMPLETE":
        raise DeltaAegisError(f"bundle is not finalized: {manifest_path}")
    bundle_dir = manifest_path.parent
    services_xml = require_file(bundle_dir, manifest, "services_xml")
    discovery_xml = require_file(bundle_dir, manifest, "discovery_xml")
    analysis_json = require_file(bundle_dir, manifest, "analysis_json")
    target = str(manifest["target"])
    target_network = parse_target_network(target)
    analysis = analysis_by_ip(analysis_json)
    discovery = parse_discovery_xml(discovery_xml, target_network)
    neighbors = parse_neighbors(optional_file(bundle_dir, manifest, "neighbors"), target_network)
    exit_status, hosts_up, hosts_down, hosts_total, assets = parse_service_xml(services_xml, analysis, target_network, discovery, neighbors)

    # NetSniper v1.8 preserves discovery-only hosts in analysis.json.
    # Treat the merged asset inventory as the current live inventory so
    # service-less-but-discovered hosts remain visible in DeltaAegis.
    counts = manifest.get("counts", {}) if isinstance(manifest.get("counts"), dict) else {}
    discovered_hosts = safe_int(counts.get("discovered_hosts"))
    inventory_hosts = max(len(assets), discovered_hosts or 0)

    if inventory_hosts > hosts_up:
        hosts_up = inventory_hosts

    if hosts_total < hosts_up:
        hosts_total = hosts_up

    scan_profile = str(manifest.get("scan_profile", "UNKNOWN"))
    profile = manifest.get("profile", {}) if isinstance(manifest.get("profile"), dict) else {}
    monitored_ports = tuple(sorted(int(port) for port in profile.get("monitored_ports", []) if isinstance(port, int) or str(port).isdigit()))
    protocols = tuple(sorted(str(item).lower() for item in profile.get("protocols", []) if isinstance(item, str)))
    fingerprint = str(profile.get("fingerprint") or manifest.get("profile_fingerprint") or legacy_profile_fingerprint(scan_profile, target))
    timestamps = manifest.get("timestamps", {}) if isinstance(manifest.get("timestamps"), dict) else {}
    telemetry = manifest.get("telemetry", {}) if isinstance(manifest.get("telemetry"), dict) else {}
    return Snapshot(
        scan_id=str(manifest["scan_id"]), manifest_path=str(manifest_path), manifest_schema_version=schema,
        target=target, scanner_version=str(manifest.get("scanner_version", "unknown")), scan_profile=scan_profile,
        profile_fingerprint=fingerprint, monitored_ports=monitored_ports, protocols=protocols,
        created_at=str(manifest.get("created_at") or timestamps.get("archived_at") or utc_now()),
        scan_started_at=timestamps.get("service_started_at"), scan_completed_at=timestamps.get("service_completed_at"),
        neighbors_captured_at=timestamps.get("neighbors_captured_at"), discovery_interface=telemetry.get("discovery_interface"),
        nmap_version=telemetry.get("nmap_version"), bundle_status=str(manifest.get("status", "UNKNOWN")),
        xml_exit_status=exit_status, hosts_up=hosts_up, hosts_down=hosts_down, hosts_total=hosts_total, assets=assets,
    )



def manifest_file_path(manifest_path: Path, manifest: dict[str, Any], key: str) -> Path | None:
    files = manifest.get("files", {})
    if not isinstance(files, dict):
        return None

    value = files.get(key)
    if not value:
        return None

    candidate = Path(str(value))
    if not candidate.is_absolute():
        candidate = manifest_path.parent / candidate

    return candidate


def load_json_file(path: Path | None, default: Any = None) -> Any:
    if path is None or not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def store_netsniper_intelligence_summary(
    connection: sqlite3.Connection,
    snapshot: Snapshot,
    manifest_path: Path,
    manifest: dict[str, Any],
) -> None:
    ensure_netsniper_intelligence_schema(connection)
    analysis_enriched_path = manifest_file_path(manifest_path, manifest, "analysis_enriched_json")
    quality_json_path = manifest_file_path(manifest_path, manifest, "classification_quality_json")
    quality_md_path = manifest_file_path(manifest_path, manifest, "classification_quality_markdown")

    quality = load_json_file(quality_json_path, {})
    if not isinstance(quality, dict):
        quality = {}

    connection.execute(
        """
        INSERT INTO netsniper_intelligence_summaries (
            scan_id,
            manifest_path,
            analysis_enriched_json,
            classification_quality_json,
            classification_quality_markdown,
            host_count,
            classified_count,
            possible_or_review_count,
            unknown_count,
            contradiction_host_count,
            false_confidence_candidate_count,
            unknown_with_exposed_services_count,
            decision_counts_json,
            siem_action_counts_json,
            confidence_band_counts_json,
            top_device_types_json,
            review_queue_json,
            contradiction_review_json,
            false_confidence_candidates_json,
            unknown_with_exposed_services_json,
            sample_explanations_json,
            imported_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(scan_id) DO UPDATE SET
            manifest_path=excluded.manifest_path,
            analysis_enriched_json=excluded.analysis_enriched_json,
            classification_quality_json=excluded.classification_quality_json,
            classification_quality_markdown=excluded.classification_quality_markdown,
            host_count=excluded.host_count,
            classified_count=excluded.classified_count,
            possible_or_review_count=excluded.possible_or_review_count,
            unknown_count=excluded.unknown_count,
            contradiction_host_count=excluded.contradiction_host_count,
            false_confidence_candidate_count=excluded.false_confidence_candidate_count,
            unknown_with_exposed_services_count=excluded.unknown_with_exposed_services_count,
            decision_counts_json=excluded.decision_counts_json,
            siem_action_counts_json=excluded.siem_action_counts_json,
            confidence_band_counts_json=excluded.confidence_band_counts_json,
            top_device_types_json=excluded.top_device_types_json,
            review_queue_json=excluded.review_queue_json,
            contradiction_review_json=excluded.contradiction_review_json,
            false_confidence_candidates_json=excluded.false_confidence_candidates_json,
            unknown_with_exposed_services_json=excluded.unknown_with_exposed_services_json,
            sample_explanations_json=excluded.sample_explanations_json,
            imported_at=excluded.imported_at
        """,
        (
            snapshot.scan_id,
            str(manifest_path),
            str(analysis_enriched_path) if analysis_enriched_path else None,
            str(quality_json_path) if quality_json_path else None,
            str(quality_md_path) if quality_md_path else None,
            safe_int(quality.get("host_count")) or 0,
            safe_int(quality.get("classified_count")) or 0,
            safe_int(quality.get("possible_or_review_count")) or 0,
            safe_int(quality.get("unknown_count")) or 0,
            safe_int(quality.get("contradiction_host_count")) or 0,
            safe_int(quality.get("false_confidence_candidate_count")) or 0,
            safe_int(quality.get("unknown_with_exposed_services_count")) or 0,
            json.dumps(quality.get("decision_counts") or {}, sort_keys=True),
            json.dumps(quality.get("siem_action_counts") or {}, sort_keys=True),
            json.dumps(quality.get("confidence_band_counts") or {}, sort_keys=True),
            json.dumps(quality.get("top_device_types") or {}, sort_keys=True),
            json.dumps(quality.get("review_queue_sample") or quality.get("review_queue") or [], sort_keys=True),
            json.dumps(quality.get("contradiction_review_sample") or quality.get("contradiction_review") or [], sort_keys=True),
            json.dumps(quality.get("false_confidence_candidates") or [], sort_keys=True),
            json.dumps(quality.get("unknown_with_exposed_services_sample") or [], sort_keys=True),
            json.dumps(quality.get("sample_explanations_by_type") or {}, sort_keys=True),
            utc_now(),
        ),
    )



def _classification_v1_7_for_host(host: dict[str, Any]) -> dict[str, Any]:
    classification = host.get("classification_v1_7")
    if isinstance(classification, dict):
        return classification

    classification = host.get("classification")
    if isinstance(classification, dict):
        return classification

    return {}


def _observed_v1_7_for_host(host: dict[str, Any]) -> dict[str, Any]:
    observed = host.get("classification_observed_v1_7")
    if isinstance(observed, dict):
        return observed
    return {}


def _list_len(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0


def store_netsniper_intelligence_hosts(
    connection: sqlite3.Connection,
    snapshot: Snapshot,
    manifest_path: Path,
    manifest: dict[str, Any],
) -> None:
    ensure_netsniper_intelligence_host_schema(connection)

    analysis_enriched_path = manifest_file_path(manifest_path, manifest, "analysis_enriched_json")
    enriched = load_json_file(analysis_enriched_path, {})

    if not isinstance(enriched, dict):
        return

    hosts = enriched.get("hosts")
    if not isinstance(hosts, list):
        return

    imported_at = utc_now()

    for host in hosts:
        if not isinstance(host, dict):
            continue

        host_id = str(
            host.get("host_id")
            or host.get("host")
            or host.get("ip")
            or host.get("ip_address")
            or ""
        ).strip()

        if not host_id:
            continue

        classification = _classification_v1_7_for_host(host)
        observed = _observed_v1_7_for_host(host)

        evidence = classification.get("evidence")
        contradictions = classification.get("contradictions")
        secondary_candidates = classification.get("secondary_candidates")
        findings = host.get("findings")

        connection.execute(
            """
            INSERT INTO netsniper_intelligence_hosts (
                scan_id,
                host_id,
                ip,
                mac,
                hostname,
                device_type,
                device_type_confidence,
                severity,
                score,
                primary_type,
                category,
                confidence,
                confidence_band,
                decision,
                siem_action,
                evidence_count,
                contradiction_count,
                secondary_candidate_count,
                explanation,
                observed_summary_json,
                observed_json,
                evidence_json,
                contradictions_json,
                secondary_candidates_json,
                findings_json,
                raw_host_json,
                imported_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id, host_id) DO UPDATE SET
                ip=excluded.ip,
                mac=excluded.mac,
                hostname=excluded.hostname,
                device_type=excluded.device_type,
                device_type_confidence=excluded.device_type_confidence,
                severity=excluded.severity,
                score=excluded.score,
                primary_type=excluded.primary_type,
                category=excluded.category,
                confidence=excluded.confidence,
                confidence_band=excluded.confidence_band,
                decision=excluded.decision,
                siem_action=excluded.siem_action,
                evidence_count=excluded.evidence_count,
                contradiction_count=excluded.contradiction_count,
                secondary_candidate_count=excluded.secondary_candidate_count,
                explanation=excluded.explanation,
                observed_summary_json=excluded.observed_summary_json,
                observed_json=excluded.observed_json,
                evidence_json=excluded.evidence_json,
                contradictions_json=excluded.contradictions_json,
                secondary_candidates_json=excluded.secondary_candidates_json,
                findings_json=excluded.findings_json,
                raw_host_json=excluded.raw_host_json,
                imported_at=excluded.imported_at
            """,
            (
                snapshot.scan_id,
                host_id,
                host.get("ip") or host.get("ip_address") or host.get("host"),
                host.get("mac") or host.get("mac_address"),
                host.get("hostname"),
                host.get("device_type"),
                safe_int(host.get("device_type_confidence")) or 0,
                host.get("severity"),
                safe_int(host.get("score")) or 0,
                classification.get("primary_type") or classification.get("type"),
                classification.get("category"),
                safe_int(classification.get("confidence")) or 0,
                classification.get("confidence_band") or classification.get("confidence_label"),
                classification.get("decision"),
                classification.get("siem_action"),
                _list_len(evidence),
                _list_len(contradictions),
                _list_len(secondary_candidates),
                classification.get("explanation"),
                json.dumps(classification.get("observed_summary") or {}, sort_keys=True),
                json.dumps(observed, sort_keys=True),
                json.dumps(evidence if isinstance(evidence, list) else [], sort_keys=True),
                json.dumps(contradictions if isinstance(contradictions, list) else [], sort_keys=True),
                json.dumps(secondary_candidates if isinstance(secondary_candidates, list) else [], sort_keys=True),
                json.dumps(findings if isinstance(findings, list) else [], sort_keys=True),
                json.dumps(host, sort_keys=True),
                imported_at,
            ),
        )


def latest_netsniper_intelligence_scan_id(connection: sqlite3.Connection) -> str | None:
    ensure_netsniper_intelligence_schema(connection)
    row = latest_netsniper_intelligence_summary(connection)
    if row is None:
        return None
    return str(row["scan_id"])


def list_netsniper_intelligence_hosts(
    connection: sqlite3.Connection,
    limit: int = 25,
    siem_action: str | None = None,
    decision: str | None = None,
    confidence_band: str | None = None,
) -> list[sqlite3.Row]:
    ensure_netsniper_intelligence_host_schema(connection)

    scan_id = latest_netsniper_intelligence_scan_id(connection)
    if scan_id is None:
        return []

    clauses = ["scan_id = ?"]
    params: list[Any] = [scan_id]

    if siem_action:
        clauses.append("siem_action = ?")
        params.append(siem_action)

    if decision:
        clauses.append("decision = ?")
        params.append(decision)

    if confidence_band:
        clauses.append("confidence_band = ?")
        params.append(confidence_band)

    params.append(max(1, int(limit)))

    return connection.execute(
        f"""
        SELECT *
        FROM netsniper_intelligence_hosts
        WHERE {' AND '.join(clauses)}
        ORDER BY
            CASE
                WHEN siem_action = 'review_queue' THEN 0
                WHEN decision = 'possible' THEN 1
                ELSE 2
            END,
            contradiction_count DESC,
            confidence ASC,
            host_id ASC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()


def get_netsniper_intelligence_host(
    connection: sqlite3.Connection,
    identity: str,
) -> sqlite3.Row | None:
    ensure_netsniper_intelligence_host_schema(connection)

    scan_id = latest_netsniper_intelligence_scan_id(connection)
    if scan_id is None:
        return None

    return connection.execute(
        """
        SELECT *
        FROM netsniper_intelligence_hosts
        WHERE scan_id = ?
          AND (
              host_id = ?
              OR ip = ?
              OR mac = ?
              OR hostname = ?
          )
        LIMIT 1
        """,
        (scan_id, identity, identity, identity, identity),
    ).fetchone()


def print_netsniper_intelligence_hosts(rows: list[sqlite3.Row]) -> None:
    if not rows:
        print("No NetSniper v1.7 intelligence host drilldown rows are available.")
        return

    print("Host Intelligence Review Queue")
    print()
    print(f"{'Host':<18} {'Type':<38} {'Conf':<5} {'Band':<10} {'Decision':<10} {'Action':<14} {'Ev':<3} {'Cx':<3}")
    print("-" * 112)

    for row in rows:
        print(
            f"{str(row['host_id'] or '-'):<18} "
            f"{str(row['primary_type'] or 'Unknown')[:38]:<38} "
            f"{int(row['confidence'] or 0):<5} "
            f"{str(row['confidence_band'] or '-'):<10} "
            f"{str(row['decision'] or '-'):<10} "
            f"{str(row['siem_action'] or '-'):<14} "
            f"{int(row['evidence_count'] or 0):<3} "
            f"{int(row['contradiction_count'] or 0):<3}"
        )


def print_netsniper_intelligence_host_detail(row: sqlite3.Row | None) -> None:
    if row is None:
        print("No matching NetSniper v1.7 intelligence host was found.")
        return

    evidence = _decode_json_list(row["evidence_json"])
    contradictions = _decode_json_list(row["contradictions_json"])
    secondary_candidates = _decode_json_list(row["secondary_candidates_json"])
    observed = _decode_json_dict(row["observed_json"])
    observed_summary = _decode_json_dict(row["observed_summary_json"])
    findings = _decode_json_list(row["findings_json"])

    print(f"Host:             {row['host_id']}")
    print(f"IP:               {row['ip'] or '-'}")
    print(f"MAC:              {row['mac'] or '-'}")
    print(f"Hostname:         {row['hostname'] or '-'}")
    print(f"Device Type:      {row['device_type'] or '-'}")
    print(f"Primary Type:     {row['primary_type'] or 'Unknown'}")
    print(f"Category:         {row['category'] or '-'}")
    print(f"Confidence:       {row['confidence']} ({row['confidence_band'] or '-'})")
    print(f"Decision:         {row['decision'] or '-'}")
    print(f"SIEM Action:      {row['siem_action'] or '-'}")
    print(f"Severity / Score: {row['severity'] or '-'} / {row['score']}")
    print(f"Explanation:      {row['explanation'] or '-'}")

    print()
    print("Observed summary:")
    if observed_summary:
        for key, value in observed_summary.items():
            print(f"  {key}: {value}")
    else:
        print("  None recorded.")

    print()
    print("Observed hints:")
    if observed:
        for key, value in observed.items():
            if isinstance(value, list):
                joined = ", ".join(str(item) for item in value) if value else "-"
                print(f"  {key}: {joined}")
            else:
                print(f"  {key}: {value}")
    else:
        print("  None recorded.")

    print()
    print("Evidence:")
    if evidence:
        for item in evidence:
            if not isinstance(item, dict):
                continue
            print(
                f"  - {item.get('id', '-')}: "
                f"{item.get('source', '-')}={item.get('value', '-')} "
                f"points={item.get('points', 0)} reliability={item.get('reliability', '-')}"
            )
            reason = item.get("reason")
            if reason:
                print(f"    reason: {reason}")
    else:
        print("  None recorded.")

    print()
    print("Contradictions:")
    if contradictions:
        for item in contradictions:
            print(f"  - {item}")
    else:
        print("  None recorded.")

    print()
    print("Secondary candidates:")
    if secondary_candidates:
        for item in secondary_candidates:
            print(f"  - {item}")
    else:
        print("  None recorded.")

    print()
    print("Findings:")
    if findings:
        for item in findings:
            if isinstance(item, dict):
                print(f"  - {item.get('id', '-')}: {item.get('name', '-')} on port {item.get('port', '-')}")
            else:
                print(f"  - {item}")
    else:
        print("  None recorded.")



def access_parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None

    text_value = str(value).strip()

    if not text_value:
        return None

    if text_value.endswith("Z"):
        text_value = text_value[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text_value)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def access_token_is_expired(expires_at: str | None) -> bool:
    parsed = access_parse_datetime(expires_at)

    if not parsed:
        return False

    return parsed <= datetime.now(timezone.utc)


def authenticate_access_api_token(
    connection: sqlite3.Connection,
    token: str,
    required_role: str = "VIEWER",
    update_last_used: bool = True,
) -> dict[str, Any] | None:
    ensure_enterprise_access_schema(connection)

    supplied = str(token or "").strip()

    if not supplied:
        return None

    token_hash = hash_access_api_token(supplied)
    row = connection.execute(
        "SELECT "
        "t.token_id, "
        "t.user_id, "
        "t.token_name, "
        "t.token_prefix, "
        "t.role AS token_role, "
        "t.is_active AS token_active, "
        "t.created_at AS token_created_at, "
        "t.updated_at AS token_updated_at, "
        "t.last_used_at, "
        "t.expires_at, "
        "u.username, "
        "u.display_name, "
        "u.role AS user_role, "
        "u.is_active AS user_active "
        "FROM access_api_tokens t "
        "JOIN access_users u ON u.user_id = t.user_id "
        "WHERE t.token_hash = ?",
        (token_hash,),
    ).fetchone()

    if not row:
        return None

    if not int(row["token_active"] or 0):
        return None

    if not int(row["user_active"] or 0):
        return None

    if access_token_is_expired(row["expires_at"]):
        return None

    token_role = normalize_access_role(row["token_role"])

    if not access_role_allows(token_role, required_role):
        return None

    authenticated_at = utc_now()

    if update_last_used:
        connection.execute(
            "UPDATE access_api_tokens "
            "SET last_used_at = ?, updated_at = ? "
            "WHERE token_id = ?",
            (authenticated_at, authenticated_at, row["token_id"]),
        )
        connection.commit()

    return {
        "auth_type": "api_token",
        "token_id": row["token_id"],
        "token_name": row["token_name"],
        "token_prefix": row["token_prefix"],
        "user_id": row["user_id"],
        "username": row["username"],
        "display_name": row["display_name"],
        "role": token_role,
        "user_role": row["user_role"],
        "last_used_at": authenticated_at if update_last_used else row["last_used_at"],
        "expires_at": row["expires_at"],
        "authenticated_at": authenticated_at,
    }


def list_access_api_tokens(
    connection: sqlite3.Connection,
    include_inactive: bool = False,
) -> list[dict[str, Any]]:
    ensure_enterprise_access_schema(connection)

    where = "" if include_inactive else "WHERE t.is_active = 1 AND u.is_active = 1"
    rows = connection.execute(
        "SELECT "
        "t.token_id, "
        "t.user_id, "
        "u.username, "
        "t.token_name, "
        "t.token_prefix, "
        "t.role, "
        "t.is_active, "
        "t.created_at, "
        "t.updated_at, "
        "t.last_used_at, "
        "t.expires_at "
        "FROM access_api_tokens t "
        "JOIN access_users u ON u.user_id = t.user_id "
        f"{where} "
        "ORDER BY t.created_at DESC, t.token_name"
    ).fetchall()

    return [dict(row) for row in rows]


def command_user_create(args: argparse.Namespace) -> int:
    with connect(args.db) as connection:
        user = create_access_user(
            connection,
            username=args.username,
            role=args.role,
            password=args.password,
            display_name=args.display_name,
            is_active=not args.inactive,
        )
        record_access_audit_event(
            connection,
            action="ACCESS_USER_CREATE",
            actor={
                "username": args.actor or "system",
                "role": "ADMIN",
            },
            target_type="access_user",
            target_key=user["username"],
            details={
                "created_user_id": user["user_id"],
                "created_username": user["username"],
                "created_role": user["role"],
                "is_active": user["is_active"],
                "password_set": bool(args.password),
            },
        )

    print("DeltaAegis access user created")
    print("==============================")
    print(f"Username:     {user['username']}")
    print(f"Display name: {user.get('display_name') or '-'}")
    print(f"Role:         {user['role']}")
    print(f"Active:       {'yes' if user['is_active'] else 'no'}")
    print(f"User ID:      {user['user_id']}")

    if not args.password:
        print("Password:     not set")

    return 0


def command_users(args: argparse.Namespace) -> int:
    with connect(args.db) as connection:
        rows = list_access_users(connection, include_inactive=args.include_inactive)

    print("DeltaAegis access users")
    print("=======================")

    if not rows:
        print("No access users found.")
        return 0

    for row in rows:
        active = "active" if int(row.get("is_active") or 0) else "inactive"
        print(
            f"{row['username']:<24} "
            f"{row['role']:<8} "
            f"{active:<8} "
            f"updated={row.get('updated_at') or '-'} "
            f"id={row['user_id']}"
        )

    return 0


def command_api_token_create(args: argparse.Namespace) -> int:
    with connect(args.db) as connection:
        user = access_user_by_username(connection, args.username)

        if not user:
            raise DeltaAegisError(f"access user not found: {args.username}")

        if not int(user.get("is_active") or 0):
            raise DeltaAegisError(f"access user is inactive: {user['username']}")

        token = create_access_api_token(
            connection,
            user_id=user["user_id"],
            token_name=args.name,
            role=args.role,
            expires_at=args.expires_at,
        )
        record_access_audit_event(
            connection,
            action="ACCESS_API_TOKEN_CREATE",
            actor={
                "username": args.actor or "system",
                "role": "ADMIN",
            },
            target_type="access_api_token",
            target_key=token["token_id"],
            details={
                "token_id": token["token_id"],
                "token_name": token["token_name"],
                "token_prefix": token["token_prefix"],
                "username": token["username"],
                "role": token["role"],
                "expires_at": token["expires_at"],
            },
        )

    print("DeltaAegis API token created")
    print("============================")
    print(f"Username:     {token['username']}")
    print(f"Token name:   {token['token_name']}")
    print(f"Role:         {token['role']}")
    print(f"Token ID:     {token['token_id']}")
    print(f"Token prefix: {token['token_prefix']}")
    print(f"Expires at:   {token.get('expires_at') or '-'}")
    print()
    print("Copy this token now. It will not be shown again:")
    print(token["token"])

    return 0


def command_api_tokens(args: argparse.Namespace) -> int:
    with connect(args.db) as connection:
        rows = list_access_api_tokens(connection, include_inactive=args.include_inactive)

    print("DeltaAegis API tokens")
    print("=====================")

    if not rows:
        print("No API tokens found.")
        return 0

    for row in rows:
        active = "active" if int(row.get("is_active") or 0) else "inactive"
        expired = "expired" if access_token_is_expired(row.get("expires_at")) else "valid"
        print(
            f"{row['username']:<24} "
            f"{row['role']:<8} "
            f"{active:<8} "
            f"{expired:<7} "
            f"prefix={row.get('token_prefix') or '-'} "
            f"last_used={row.get('last_used_at') or '-'} "
            f"name={row.get('token_name') or '-'}"
        )

    return 0


def list_access_audit_events(
    connection: sqlite3.Connection,
    limit: int = 50,
    action: str | None = None,
    actor: str | None = None,
    target_type: str | None = None,
) -> list[dict[str, Any]]:
    ensure_enterprise_access_schema(connection)

    requested_limit = max(1, min(int(limit or 50), 500))
    clauses = []
    values: list[Any] = []

    if action:
        clauses.append("action = ?")
        values.append(str(action).strip().upper())

    if actor:
        clauses.append("(actor_username = ? OR actor_user_id = ?)")
        values.extend([str(actor).strip(), str(actor).strip()])

    if target_type:
        clauses.append("target_type = ?")
        values.append(str(target_type).strip())

    where = "WHERE " + " AND ".join(clauses) if clauses else ""

    rows = connection.execute(
        "SELECT "
        "audit_id, "
        "actor_user_id, "
        "actor_username, "
        "actor_role, "
        "action, "
        "target_type, "
        "target_key, "
        "source_ip, "
        "user_agent, "
        "detail_json, "
        "created_at "
        "FROM access_audit_log "
        f"{where} "
        "ORDER BY audit_id DESC "
        "LIMIT ?",
        (*values, requested_limit),
    ).fetchall()

    events: list[dict[str, Any]] = []

    for row in rows:
        detail_json = row["detail_json"] or "{}"

        try:
            details = json.loads(detail_json)
        except json.JSONDecodeError:
            details = {"raw": detail_json}

        event = dict(row)
        event["details"] = details
        events.append(event)

    return events


def access_audit_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    action_counts = Counter(str(row.get("action") or "UNKNOWN") for row in rows)
    actor_counts = Counter(str(row.get("actor_username") or "system") for row in rows)

    return {
        "event_count": len(rows),
        "action_counts": dict(action_counts),
        "actor_counts": dict(actor_counts),
    }


def dashboard_access_audit_payload(
    connection: sqlite3.Connection,
    limit: int = 25,
    action: str | None = None,
    actor: str | None = None,
    target_type: str | None = None,
) -> dict[str, Any]:
    rows = list_access_audit_events(
        connection,
        limit=limit,
        action=action,
        actor=actor,
        target_type=target_type,
    )

    return {
        "available": True,
        "items": rows,
        "item_count": len(rows),
        "summary": access_audit_summary(rows),
        "filters": {
            "action": str(action or "").strip().upper() or "ALL",
            "actor": str(actor or "").strip() or "ALL",
            "target_type": str(target_type or "").strip() or "ALL",
        },
    }


def command_access_audit(args: argparse.Namespace) -> int:
    with connect(args.db) as connection:
        rows = list_access_audit_events(
            connection,
            limit=args.limit,
            action=args.action,
            actor=args.actor,
            target_type=args.target_type,
        )

    print("DeltaAegis access audit log")
    print("===========================")

    if args.action:
        print(f"Action filter: {str(args.action).strip().upper()}")

    if args.actor:
        print(f"Actor filter:  {args.actor}")

    if args.target_type:
        print(f"Target filter: {args.target_type}")

    if not rows:
        print("No access audit events found.")
        return 0

    for row in rows:
        print(
            f"{row.get('audit_id'):>5} "
            f"{row.get('created_at') or '-'} "
            f"{row.get('action') or '-':<36} "
            f"actor={row.get('actor_username') or '-'} "
            f"role={row.get('actor_role') or '-'} "
            f"target={row.get('target_type') or '-'}:{row.get('target_key') or '-'} "
            f"source={row.get('source_ip') or '-'}"
        )

    return 0

def command_intelligence_hosts(args: argparse.Namespace) -> int:
    connection = connect(args.db)
    rows = list_netsniper_intelligence_hosts(
        connection,
        limit=args.limit,
        siem_action=args.action,
        decision=args.decision,
        confidence_band=args.band,
    )
    print_netsniper_intelligence_hosts(rows)
    return 0


def command_intelligence_host(args: argparse.Namespace) -> int:
    connection = connect(args.db)
    row = get_netsniper_intelligence_host(connection, args.identity)
    print_netsniper_intelligence_host_detail(row)
    return 0


def latest_netsniper_intelligence_summary(connection: sqlite3.Connection) -> sqlite3.Row | None:
    ensure_netsniper_intelligence_schema(connection)
    return connection.execute(
        """
        SELECT *
        FROM netsniper_intelligence_summaries
        ORDER BY imported_at DESC
        LIMIT 1
        """
    ).fetchone()



def _decode_json_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value

    if value in {None, "", "{}"}:
        return {}

    try:
        decoded = json.loads(value)
    except Exception:
        return {}

    if isinstance(decoded, dict):
        return decoded

    return {}

def print_netsniper_intelligence_summary(row: sqlite3.Row | None) -> None:
    if row is None:
        print("No NetSniper v1.7 intelligence summary has been imported yet.")
        return

    print(f"Scan ID:                    {row['scan_id']}")
    print(f"Hosts:                      {row['host_count']}")
    print(f"Classified:                 {row['classified_count']}")
    print(f"Possible / review:          {row['possible_or_review_count']}")
    print(f"Unknown:                    {row['unknown_count']}")
    print(f"Contradiction hosts:         {row['contradiction_host_count']}")
    print(f"False-confidence candidates: {row['false_confidence_candidate_count']}")
    print(f"Unknown exposed services:    {row['unknown_with_exposed_services_count']}")
    print()
    print("Top device types:")

    top_types = _decode_json_dict(row["top_device_types_json"])
    if not top_types:
        print("  None recorded.")
    else:
        for name, count in top_types.items():
            print(f"  {name}: {count}")

    print()
    print("Confidence bands:")
    bands = _decode_json_dict(row["confidence_band_counts_json"])
    if not bands:
        print("  None recorded.")
    else:
        for name, count in bands.items():
            print(f"  {name}: {count}")

    print()
    print("Review queue sample:")
    review = _decode_json_list(row["review_queue_json"])
    if not review:
        print("  No review queue items.")
    else:
        for item in review[:10]:
            identity = item.get("identity") or item.get("ip") or item.get("host_id") or "unknown"
            classification = item.get("primary_type") or item.get("classification") or "Unknown"
            confidence = item.get("confidence", 0)
            decision = item.get("decision", "unknown")
            reason = item.get("reason") or item.get("siem_action") or "review"
            print(f"  {identity} | {classification} | confidence={confidence} | decision={decision} | reason={reason}")


def command_intelligence(args: argparse.Namespace) -> int:
    connection = connect(args.db)
    row = latest_netsniper_intelligence_summary(connection)
    print_netsniper_intelligence_summary(row)
    return 0


def snapshot_exists(connection: sqlite3.Connection, scan_id: str) -> bool:
    return connection.execute("SELECT 1 FROM snapshots WHERE scan_id = ?", (scan_id,)).fetchone() is not None


def latest_accepted_snapshot(connection: sqlite3.Connection, target: str) -> sqlite3.Row | None:
    network_scope = canonical_network_scope(target)

    return connection.execute(
        """
        SELECT *
        FROM snapshots
        WHERE network_scope = ?
          AND quality_status = 'ACCEPTED'
        ORDER BY created_at DESC, imported_at DESC
        LIMIT 1
        """,
        (network_scope,),
    ).fetchone()

def assess_quality(snapshot: Snapshot, baseline: sqlite3.Row | None) -> tuple[str, str]:
    if snapshot.bundle_status != "COMPLETE":
        return "REJECTED", "NetSniper bundle status is not COMPLETE."
    if snapshot.xml_exit_status != "success":
        return "REJECTED", f"Nmap XML exit status is {snapshot.xml_exit_status!r}, not 'success'."
    if snapshot.hosts_up <= 0 or not snapshot.assets:
        return "REVIEW_REQUIRED", "Snapshot contains no usable live assets."
    if baseline is not None:
        prior_hosts = int(baseline["hosts_up"])
        if prior_hosts > 0 and snapshot.hosts_up < prior_hosts * QUALITY_RATIO_THRESHOLD:
            return "REVIEW_REQUIRED", f"Host count dropped from {prior_hosts} to {snapshot.hosts_up}; snapshot requires review."
        prior_coverage = float(baseline["identity_coverage"])
        if prior_coverage >= IDENTITY_COVERAGE_THRESHOLD and snapshot.identity_coverage < IDENTITY_DROP_REVIEW_THRESHOLD:
            return "REVIEW_REQUIRED", f"MAC-backed identity coverage dropped from {prior_coverage:.0%} to {snapshot.identity_coverage:.0%}."
        old_fp = str(baseline["profile_fingerprint"] or "")
        if str(baseline["manifest_schema_version"]) == "netsniper-run-v2" and snapshot.manifest_schema_version == "netsniper-run-v2" and old_fp and old_fp != snapshot.profile_fingerprint:
            return "REVIEW_REQUIRED", "NetSniper scan profile fingerprint changed. Approve a new baseline before comparing monitored services."
    return "ACCEPTED", "Snapshot passed quality checks."


def insert_snapshot(connection: sqlite3.Connection, snapshot: Snapshot, quality_status: str, quality_reason: str) -> None:
    connection.execute("""INSERT INTO snapshots (scan_id, manifest_path, target, network_scope, scanner_version, scan_profile, created_at, imported_at, bundle_status, quality_status, quality_reason, xml_exit_status, hosts_up, hosts_down, hosts_total, mac_backed_assets, identity_coverage, is_accepted_baseline, manifest_schema_version, profile_fingerprint, monitored_ports_json, protocols_json, discovery_interface, nmap_version, scan_started_at, scan_completed_at, neighbors_captured_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (snapshot.scan_id, snapshot.manifest_path, snapshot.target, snapshot_network_scope(snapshot), snapshot.scanner_version, snapshot.scan_profile, snapshot.created_at, utc_now(), snapshot.bundle_status, quality_status, quality_reason, snapshot.xml_exit_status, snapshot.hosts_up, snapshot.hosts_down, snapshot.hosts_total, snapshot.mac_backed_assets, snapshot.identity_coverage, 1 if quality_status == "ACCEPTED" else 0, snapshot.manifest_schema_version, snapshot.profile_fingerprint, json.dumps(snapshot.monitored_ports), json.dumps(snapshot.protocols), snapshot.discovery_interface, snapshot.nmap_version, snapshot.scan_started_at, snapshot.scan_completed_at, snapshot.neighbors_captured_at))
    for asset in snapshot.assets.values():
        connection.execute(
            """INSERT INTO asset_observations (
                scan_id,
                asset_key,
                identity_class,
                identity_confidence,
                identity_source,
                ip_address,
                mac_address,
                vendor,
                hostname,
                device_type,
                device_type_confidence,
                classification_type,
                classification_primary_type,
                classification_confidence,
                classification_confidence_label,
                classification_decision,
                classification_method,
                classification_json,
                classification_evidence_json,
                classification_contradictions_json,
                classification_candidates_json,
                  classification_confidence_band,
                  classification_calibrated_decision,
                  classification_siem_action,
                  classification_calibration_reason,
                  classification_validation_state,
                  classification_contradiction_count,
                  classification_validator_summary_json,
                  classification_validators_json,
                  severity,
                  score
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                snapshot.scan_id,
                asset.asset_key,
                asset.identity_class,
                asset.identity_confidence,
                asset.identity_source,
                asset.ip_address,
                asset.mac_address,
                asset.vendor,
                asset.hostname,
                asset.device_type,
                asset.device_type_confidence,
                asset.classification_type,
                asset.classification_primary_type,
                asset.classification_confidence,
                asset.classification_confidence_label,
                asset.classification_decision,
                asset.classification_method,
                asset.classification_json,
                asset.classification_evidence_json,
                asset.classification_contradictions_json,
                asset.classification_candidates_json,
                  asset.classification_confidence_band,
                  asset.classification_calibrated_decision,
                  asset.classification_siem_action,
                  asset.classification_calibration_reason,
                  asset.classification_validation_state,
                  asset.classification_contradiction_count,
                  asset.classification_validator_summary_json,
                  asset.classification_validators_json,
                  asset.severity,
                  asset.score,
            ),
        )
        for service in asset.services:
            connection.execute("""INSERT INTO service_observations (scan_id, asset_key, protocol, port, state, service_name, product, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", (snapshot.scan_id, asset.asset_key, service.protocol, service.port, service.state, service.service_name, service.product, service.version))
        for finding in asset.findings:
            connection.execute("""INSERT OR IGNORE INTO finding_observations (scan_id, asset_key, finding_id, name, service, port, score, evidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", (snapshot.scan_id, asset.asset_key, str(finding.get("finding_id", finding.get("id", "UNKNOWN"))), finding.get("name"), finding.get("service"), int(finding.get("port", -1)), finding.get("score"), finding.get("evidence")))


def load_assets_from_db(connection: sqlite3.Connection, scan_id: str) -> dict[str, AssetObservation]:
    assets: dict[str, AssetObservation] = {}
    rows = connection.execute("SELECT * FROM asset_observations WHERE scan_id = ?", (scan_id,)).fetchall()
    for row in rows:
        services = [Service(item["protocol"], item["port"], item["state"], item["service_name"], item["product"], item["version"]) for item in connection.execute("SELECT * FROM service_observations WHERE scan_id = ? AND asset_key = ? ORDER BY protocol, port", (scan_id, row["asset_key"]))]
        findings = [dict(item) for item in connection.execute("SELECT * FROM finding_observations WHERE scan_id = ? AND asset_key = ?", (scan_id, row["asset_key"]))]
        assets[row["asset_key"]] = AssetObservation(
            row["asset_key"],
            row["identity_class"],
            row["identity_confidence"],
            row["identity_source"],
            row["ip_address"],
            row["mac_address"],
            row["vendor"],
            row["hostname"],
            row["device_type"],
            row["severity"],
            row["score"],
            services,
            findings,
            device_type_confidence=row["device_type_confidence"],
            classification_type=row["classification_type"],
            classification_primary_type=row["classification_primary_type"],
            classification_confidence=row["classification_confidence"],
            classification_confidence_label=row["classification_confidence_label"],
            classification_decision=row["classification_decision"],
            classification_method=row["classification_method"],
            classification_json=row["classification_json"],
            classification_evidence_json=row["classification_evidence_json"],
            classification_contradictions_json=row["classification_contradictions_json"],
            classification_candidates_json=row["classification_candidates_json"],
            classification_confidence_band=row["classification_confidence_band"],
            classification_calibrated_decision=row["classification_calibrated_decision"],
            classification_siem_action=row["classification_siem_action"],
            classification_calibration_reason=row["classification_calibration_reason"],
            classification_validation_state=row["classification_validation_state"],
            classification_contradiction_count=row["classification_contradiction_count"],
            classification_validator_summary_json=row["classification_validator_summary_json"],
            classification_validators_json=row["classification_validators_json"],
        )
    return assets


def event(event_type: str, severity: str, subject_key: str, summary: str, previous_value: Any = None, current_value: Any = None) -> dict[str, Any]:
    return {"event_type": event_type, "severity": severity, "subject_key": subject_key, "summary": summary, "previous_value": previous_value, "current_value": current_value}


def reset_lifecycle(
    connection: sqlite3.Connection,
    scan_id: str,
    created_at: str,
    assets: dict[str, AssetObservation],
    network_scope: str,
) -> None:
    connection.execute(
        "DELETE FROM asset_lifecycle WHERE network_scope = ?",
        (network_scope,),
    )

    for asset in assets.values():
        connection.execute(
            """
            INSERT INTO asset_lifecycle (
                network_scope,
                asset_key,
                identity_class,
                state,
                missing_count,
                current_ip,
                mac_address,
                vendor,
                hostname,
                first_seen_scan_id,
                last_seen_scan_id,
                first_seen_at,
                last_seen_at,
                removed_at
            )
            VALUES (?, ?, ?, 'ACTIVE', 0, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                network_scope,
                asset.asset_key,
                asset.identity_class,
                asset.ip_address,
                asset.mac_address,
                asset.vendor,
                asset.hostname,
                scan_id,
                scan_id,
                created_at,
                created_at,
            ),
        )

def initialize_lifecycle(connection: sqlite3.Connection, snapshot: Snapshot) -> None:
    reset_lifecycle(
        connection,
        snapshot.scan_id,
        snapshot.created_at,
        snapshot.assets,
        snapshot_network_scope(snapshot),
    )

def lifecycle_events(connection: sqlite3.Connection, snapshot: Snapshot) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    network_scope = snapshot_network_scope(snapshot)

    existing = {
        row["asset_key"]: row
        for row in connection.execute(
            "SELECT * FROM asset_lifecycle WHERE network_scope = ?",
            (network_scope,),
        )
    }

    current_keys = set(snapshot.assets)

    for key, asset in snapshot.assets.items():
        row = existing.get(key)

        if row is None:
            if asset.identity_class == "GLOBAL_MAC":
                events.append(event("ASSET_FIRST_OBSERVED", "MEDIUM", key, f"Asset {key} was observed for the first time at {asset.ip_address}."))
            elif asset.identity_class == "LOCAL_MAC":
                events.append(event("EPHEMERAL_IDENTITY_FIRST_OBSERVED", "INFO", key, f"Locally administered identity {key} was observed at {asset.ip_address}."))
            else:
                events.append(event("IP_FIRST_OBSERVED", "LOW", key, f"IP address {asset.ip_address} was observed for the first time."))

            connection.execute(
                """
                INSERT INTO asset_lifecycle (
                    network_scope,
                    asset_key,
                    identity_class,
                    state,
                    missing_count,
                    current_ip,
                    mac_address,
                    vendor,
                    hostname,
                    first_seen_scan_id,
                    last_seen_scan_id,
                    first_seen_at,
                    last_seen_at,
                    removed_at
                )
                VALUES (?, ?, ?, 'ACTIVE', 0, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    network_scope,
                    key,
                    asset.identity_class,
                    asset.ip_address,
                    asset.mac_address,
                    asset.vendor,
                    asset.hostname,
                    snapshot.scan_id,
                    snapshot.scan_id,
                    snapshot.created_at,
                    snapshot.created_at,
                ),
            )
            continue

        if row["state"] != "ACTIVE":
            if asset.identity_class == "GLOBAL_MAC":
                events.append(event("ASSET_REAPPEARED", "INFO", key, f"Asset {key} reappeared at {asset.ip_address}."))
            elif asset.identity_class == "LOCAL_MAC":
                events.append(event("EPHEMERAL_IDENTITY_REAPPEARED", "INFO", key, f"Locally administered identity {key} reappeared at {asset.ip_address}."))
            else:
                events.append(event("IP_REAPPEARED", "INFO", key, f"IP address {asset.ip_address} reappeared."))

        if asset.identity_class == "GLOBAL_MAC" and row["current_ip"] != asset.ip_address:
            events.append(event("IP_CHANGED", "INFO", key, f"Asset {key} changed IP address from {row['current_ip']} to {asset.ip_address}.", row["current_ip"], asset.ip_address))

        connection.execute(
            """
            UPDATE asset_lifecycle
            SET
                identity_class = ?,
                state = 'ACTIVE',
                missing_count = 0,
                current_ip = ?,
                mac_address = ?,
                vendor = COALESCE(?, vendor),
                hostname = COALESCE(?, hostname),
                last_seen_scan_id = ?,
                last_seen_at = ?,
                removed_at = NULL
            WHERE network_scope = ?
              AND asset_key = ?
            """,
            (
                asset.identity_class,
                asset.ip_address,
                asset.mac_address,
                asset.vendor,
                asset.hostname,
                snapshot.scan_id,
                snapshot.created_at,
                network_scope,
                key,
            ),
        )

    for key, row in existing.items():
        if key in current_keys:
            continue

        missing_count = int(row["missing_count"]) + 1

        if row["identity_class"] == "LOCAL_MAC":
            if row["state"] == "ACTIVE":
                events.append(event("EPHEMERAL_IDENTITY_NOT_OBSERVED", "INFO", key, f"Locally administered identity {key} was not observed in the current accepted snapshot. Last known IP: {row['current_ip']}."))

            connection.execute(
                """
                UPDATE asset_lifecycle
                SET state = 'EPHEMERAL_MISSING',
                    missing_count = ?
                WHERE network_scope = ?
                  AND asset_key = ?
                """,
                (missing_count, network_scope, key),
            )

        elif row["identity_class"] == "GLOBAL_MAC":
            if row["state"] == "ACTIVE":
                events.append(event("ASSET_NOT_OBSERVED", "LOW", key, f"Previously observed asset {key} was not observed in the current accepted snapshot. Last known IP: {row['current_ip']}."))
                connection.execute(
                    """
                    UPDATE asset_lifecycle
                    SET state = 'MISSING',
                        missing_count = ?
                    WHERE network_scope = ?
                      AND asset_key = ?
                    """,
                    (missing_count, network_scope, key),
                )
            elif row["state"] != "REMOVED" and missing_count >= REMOVAL_THRESHOLD:
                events.append(event("ASSET_REMOVED", "MEDIUM", key, f"Asset {key} has not been observed in {REMOVAL_THRESHOLD} consecutive accepted snapshots. Last known IP: {row['current_ip']}."))
                connection.execute(
                    """
                    UPDATE asset_lifecycle
                    SET state = 'REMOVED',
                        missing_count = ?,
                        removed_at = ?
                    WHERE network_scope = ?
                      AND asset_key = ?
                    """,
                    (missing_count, snapshot.created_at, network_scope, key),
                )
            elif row["state"] != "REMOVED":
                connection.execute(
                    """
                    UPDATE asset_lifecycle
                    SET missing_count = ?
                    WHERE network_scope = ?
                      AND asset_key = ?
                    """,
                    (missing_count, network_scope, key),
                )
        else:
            if row["state"] == "ACTIVE":
                events.append(event("IP_NOT_OBSERVED", "LOW", key, f"Previously observed IP address {row['current_ip']} was not observed in the current accepted snapshot."))

            connection.execute(
                """
                UPDATE asset_lifecycle
                SET state = 'MISSING',
                    missing_count = ?
                WHERE network_scope = ?
                  AND asset_key = ?
                """,
                (missing_count, network_scope, key),
            )

    return events


def _decode_json_list(value: str | None) -> list[Any]:
    if not value:
        return []
    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []
    return decoded if isinstance(decoded, list) else []


def _classification_type(asset: AssetObservation) -> str:
    return str(asset.classification_type or asset.classification_primary_type or "").strip()


def _classification_decision(asset: AssetObservation) -> str:
    decision = str(asset.classification_decision or "").strip().lower()
    if decision:
        return decision

    # Backward compatibility for early NetSniper v1.4-dev bundles that stored
    # classification confidence/type but did not yet include classification.decision.
    confidence = _classification_confidence(asset)

    if confidence >= 40:
        return "classified"
    if confidence > 0:
        return "possible"
    return "unknown"


def _classification_confidence(asset: AssetObservation) -> int:
    return int(asset.classification_confidence or asset.device_type_confidence or 0)


def _has_classification_intelligence(asset: AssetObservation) -> bool:
    # Important: this must check raw stored NetSniper v1.4 fields only.
    # Do not call _classification_decision() here, because that helper infers
    # a decision for backward compatibility. Older pre-v1.4 snapshots should
    # not be treated as classification-aware baselines.
    return bool(
        asset.classification_type
        or asset.classification_primary_type
        or asset.classification_decision
        or asset.classification_method
        or asset.classification_confidence is not None
        or asset.device_type_confidence is not None
        or asset.classification_json not in {None, "", "{}"}
        or asset.classification_evidence_json not in {None, "", "[]"}
        or asset.classification_contradictions_json not in {None, "", "[]"}
        or asset.classification_candidates_json not in {None, "", "[]"}
        or asset.classification_confidence_band
        or asset.classification_calibrated_decision
        or asset.classification_siem_action
        or asset.classification_calibration_reason
        or asset.classification_validation_state
        or asset.classification_contradiction_count is not None
        or asset.classification_validator_summary_json not in {None, "", "{}"}
        or asset.classification_validators_json not in {None, "", "[]"}
    )


def _classification_snapshot(asset: AssetObservation) -> dict[str, Any]:
    evidence = _decode_json_list(asset.classification_evidence_json)
    contradictions = _decode_json_list(asset.classification_contradictions_json)
    candidates = _decode_json_list(asset.classification_candidates_json)
    validators = _decode_json_list(asset.classification_validators_json)

    validator_summary = {}
    try:
        decoded_summary = json.loads(asset.classification_validator_summary_json or "{}")
        if isinstance(decoded_summary, dict):
            validator_summary = decoded_summary
    except (TypeError, json.JSONDecodeError):
        validator_summary = {}

    return {
        "ip_address": asset.ip_address,
        "device_type": asset.device_type,
        "device_type_confidence": asset.device_type_confidence,
        "classification_type": _classification_type(asset) or None,
        "classification_primary_type": asset.classification_primary_type,
        "classification_confidence": _classification_confidence(asset),
        "classification_confidence_label": asset.classification_confidence_label,
        "classification_decision": _classification_decision(asset) or None,
        "classification_method": asset.classification_method,
        "classification_confidence_band": asset.classification_confidence_band,
        "classification_calibrated_decision": asset.classification_calibrated_decision,
        "classification_siem_action": asset.classification_siem_action,
        "classification_calibration_reason": asset.classification_calibration_reason,
        "classification_validation_state": asset.classification_validation_state,
        "evidence_count": len(evidence),
        "contradiction_count": (
            asset.classification_contradiction_count
            if asset.classification_contradiction_count is not None
            else len(contradictions)
        ),
        "candidate_count": len(candidates),
        "validator_count": len(validators),
        "validator_summary": validator_summary,
    }


def classification_delta_events(previous: dict[str, AssetObservation], current: dict[str, AssetObservation]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []

    for key, new_asset in sorted(current.items()):
        old_asset = previous.get(key)
        if old_asset is None:
            continue

        # Avoid flooding when the baseline was produced before NetSniper v1.4.
        if not _has_classification_intelligence(old_asset) or not _has_classification_intelligence(new_asset):
            continue

        old_type = _classification_type(old_asset)
        new_type = _classification_type(new_asset)
        old_decision = _classification_decision(old_asset)
        new_decision = _classification_decision(new_asset)
        old_confidence = _classification_confidence(old_asset)
        new_confidence = _classification_confidence(new_asset)

        previous_value = _classification_snapshot(old_asset)
        current_value = _classification_snapshot(new_asset)

        if old_type != new_type and (old_decision != "unknown" or new_decision != "unknown"):
            severity = "MEDIUM" if new_decision == "classified" else "LOW"
            events.append(event(
                "DEVICE_CLASSIFICATION_CHANGED",
                severity,
                key,
                (
                    f"NetSniper classification for {key} changed from "
                    f"{old_type or 'Unknown'} ({old_confidence}) to "
                    f"{new_type or 'Unknown'} ({new_confidence})."
                ),
                previous_value,
                current_value,
            ))

        confidence_delta = abs(new_confidence - old_confidence)
        decision_changed = old_decision != new_decision

        if old_type == new_type and (decision_changed or confidence_delta >= 20):
            severity = "MEDIUM" if decision_changed and new_decision == "classified" else "INFO"
            events.append(event(
                "DEVICE_CLASSIFICATION_CONFIDENCE_CHANGED",
                severity,
                key,
                (
                    f"NetSniper classification confidence for {key} changed from "
                    f"{old_confidence} ({old_decision or 'unknown'}) to "
                    f"{new_confidence} ({new_decision or 'unknown'}) for "
                    f"{new_type or 'Unknown'}."
                ),
                previous_value,
                current_value,
            ))

        if new_decision == "possible" and old_decision != "possible":
            severity = "MEDIUM" if old_decision == "classified" else "LOW"
            events.append(event(
                "DEVICE_CLASSIFICATION_WEAK",
                severity,
                key,
                (
                    f"NetSniper classification for {key} is now weak/possible: "
                    f"{new_type or 'Unknown'} at confidence {new_confidence}."
                ),
                previous_value,
                current_value,
            ))

        old_contradictions = _decode_json_list(old_asset.classification_contradictions_json)
        new_contradictions = _decode_json_list(new_asset.classification_contradictions_json)

        if new_contradictions and new_contradictions != old_contradictions:
            events.append(event(
                "DEVICE_CLASSIFICATION_CONTRADICTION",
                "MEDIUM",
                key,
                (
                    f"NetSniper reported classification contradiction(s) for {key}: "
                    f"{len(new_contradictions)} contradiction(s) present."
                ),
                previous_value,
                current_value,
            ))

    return events

def comparison_events(previous: dict[str, AssetObservation], current: dict[str, AssetObservation]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for key in sorted(set(previous) & set(current)):
        old_asset, new_asset = previous[key], current[key]
        old_services = {service.key: service for service in old_asset.services}
        new_services = {service.key: service for service in new_asset.services}
        for service_key in sorted(set(new_services) - set(old_services)):
            service = new_services[service_key]
            events.append(event("MONITORED_SERVICE_OPENED", "MEDIUM", key, f"A newly observed monitored service appeared on {new_asset.ip_address}: {service.protocol}/{service.port}.", current_value=asdict(service)))
        for service_key in sorted(set(old_services) - set(new_services)):
            service = old_services[service_key]
            events.append(event("MONITORED_SERVICE_CLOSED", "INFO", key, f"A previously observed monitored service disappeared from {old_asset.ip_address}: {service.protocol}/{service.port}.", previous_value=asdict(service)))
        old_findings = {(str(item.get("finding_id", item.get("id", "UNKNOWN"))), int(item.get("port", -1))) for item in old_asset.findings}
        new_findings = {(str(item.get("finding_id", item.get("id", "UNKNOWN"))), int(item.get("port", -1))) for item in new_asset.findings}
        for finding_id, port in sorted(new_findings - old_findings):
            events.append(event("NETSNIPER_FINDING_ADDED", "MEDIUM", key, f"NetSniper reported a new interpreted finding on {new_asset.ip_address}: {finding_id} (port {port}).", current_value={"finding_id": finding_id, "port": port}))
        for finding_id, port in sorted(old_findings - new_findings):
            events.append(event("NETSNIPER_FINDING_REMOVED", "INFO", key, f"A previously reported NetSniper finding is no longer present on {old_asset.ip_address}: {finding_id} (port {port}).", previous_value={"finding_id": finding_id, "port": port}))
    return events


def alert_dedup_key(item: dict[str, Any]) -> str | None:
    etype = item["event_type"]
    subject = item["subject_key"]
    value = item.get("current_value") or item.get("previous_value") or {}
    if etype in {"MONITORED_SERVICE_OPENED", "MONITORED_SERVICE_CLOSED"}:
        return f"service:{subject}:{value.get('protocol')}:{value.get('port')}"
    if etype in {"NETSNIPER_FINDING_ADDED", "NETSNIPER_FINDING_REMOVED"}:
        return f"finding:{subject}:{value.get('finding_id')}:{value.get('port')}"
    if etype in {"ASSET_FIRST_OBSERVED", "ASSET_REMOVED", "ASSET_REAPPEARED"}:
        return f"asset:{subject}"
    if etype in {"SNAPSHOT_REVIEW_REQUIRED", "SNAPSHOT_PROFILE_CHANGED"}:
        return f"snapshot:{subject}"
    return None


def sync_alert(connection: sqlite3.Connection, item: dict[str, Any], event_id: int, created_at: str) -> None:
    key = alert_dedup_key(item)
    if key is None:
        return
    etype = item["event_type"]
    if etype in {"MONITORED_SERVICE_CLOSED", "NETSNIPER_FINDING_REMOVED", "ASSET_REAPPEARED"}:
        connection.execute("UPDATE alerts SET status = 'RESOLVED', resolved_at = ?, last_seen_at = ?, last_event_id = ? WHERE dedup_key = ? AND status != 'RESOLVED'", (created_at, created_at, event_id, key))
        return
    connection.execute("""INSERT INTO alerts (dedup_key, event_type, severity, subject_key, status, summary, opened_at, last_seen_at, first_event_id, last_event_id) VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?) ON CONFLICT(dedup_key) DO UPDATE SET event_type=excluded.event_type, severity=excluded.severity, subject_key=excluded.subject_key, summary=excluded.summary, last_seen_at=excluded.last_seen_at, last_event_id=excluded.last_event_id, status=CASE WHEN alerts.status='RESOLVED' THEN 'OPEN' ELSE alerts.status END, resolved_at=CASE WHEN alerts.status='RESOLVED' THEN NULL ELSE alerts.resolved_at END""", (key, etype, item["severity"], item["subject_key"], item["summary"], created_at, created_at, event_id, event_id))


def store_events(connection: sqlite3.Connection, scan_id: str, baseline_scan_id: str | None, events: Iterable[dict[str, Any]], export_path: Path) -> int:
    export_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with export_path.open("a", encoding="utf-8") as handle:
        for item in events:
            created_at = utc_now()
            cursor = connection.execute("""INSERT INTO delta_events (scan_id, baseline_scan_id, event_type, severity, subject_key, previous_value, current_value, summary, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", (scan_id, baseline_scan_id, item["event_type"], item["severity"], item["subject_key"], json.dumps(item.get("previous_value"), sort_keys=True), json.dumps(item.get("current_value"), sort_keys=True), item["summary"], created_at))
            sync_alert(connection, item, int(cursor.lastrowid), created_at)
            handle.write(json.dumps({"scan_id": scan_id, "baseline_scan_id": baseline_scan_id, "created_at": created_at, **item}, sort_keys=True) + "\n")
            count += 1
    return count


def identity_transition(previous_coverage: float, current_coverage: float) -> bool:
    return previous_coverage < IDENTITY_COVERAGE_THRESHOLD <= current_coverage


def profile_transition(baseline: sqlite3.Row, snapshot: Snapshot) -> bool:
    return str(baseline["manifest_schema_version"]) != "netsniper-run-v2" and snapshot.manifest_schema_version == "netsniper-run-v2"


def ingest_manifest(connection: sqlite3.Connection, manifest_path: Path, export_path: Path) -> str:
    snapshot = load_snapshot(manifest_path)
    if snapshot_exists(connection, snapshot.scan_id):
        return f"SKIP {snapshot.scan_id}: already imported"
    baseline = latest_accepted_snapshot(connection, snapshot.target)
    quality_status, quality_reason = assess_quality(snapshot, baseline)
    insert_snapshot(connection, snapshot, quality_status, quality_reason)
    manifest_data = load_json_file(manifest_path, {})
    if not isinstance(manifest_data, dict):
        manifest_data = {}
    store_netsniper_intelligence_summary(connection, snapshot, manifest_path, manifest_data)
    store_netsniper_intelligence_hosts(connection, snapshot, manifest_path, manifest_data)
    events: list[dict[str, Any]] = []
    if quality_status == "ACCEPTED":
        if baseline is None:
            initialize_lifecycle(connection, snapshot)
        elif profile_transition(baseline, snapshot):
            initialize_lifecycle(connection, snapshot)
            events.append(event("PROFILE_BASELINE_RESET", "INFO", f"scan:{snapshot.scan_id}", "NetSniper telemetry contract upgraded to netsniper-run-v2. This snapshot becomes the new profile baseline without generating service-change deltas."))
        elif identity_transition(float(baseline["identity_coverage"]), snapshot.identity_coverage):
            initialize_lifecycle(connection, snapshot)
            events.append(event("IDENTITY_BASELINE_RESET", "INFO", f"scan:{snapshot.scan_id}", f"MAC-backed identity coverage increased from {float(baseline['identity_coverage']):.0%} to {snapshot.identity_coverage:.0%}. This snapshot becomes the new identity baseline without generating asset-change deltas."))
        else:
            previous_assets = load_assets_from_db(connection, baseline["scan_id"])
            events.extend(comparison_events(previous_assets, snapshot.assets))
            events.extend(classification_delta_events(previous_assets, snapshot.assets))
            events.extend(lifecycle_events(connection, snapshot))
    else:
        etype = "SNAPSHOT_PROFILE_CHANGED" if "profile fingerprint changed" in quality_reason.lower() else "SNAPSHOT_REVIEW_REQUIRED"
        events.append(event(etype, "MEDIUM", f"scan:{snapshot.scan_id}", quality_reason))
    event_count = store_events(connection, snapshot.scan_id, baseline["scan_id"] if baseline else None, events, export_path)
    connection.commit()
    return f"IMPORT {snapshot.scan_id}: quality={quality_status}, assets={len(snapshot.assets)}, mac_identity={snapshot.identity_coverage:.0%}, events={event_count}"


def finalized_manifests(runs_dir: Path) -> list[Path]:
    if not runs_dir.is_dir():
        raise DeltaAegisError(f"NetSniper runs directory does not exist: {runs_dir}")
    return sorted(runs_dir.glob("*/manifest.json"))


def command_ingest(args: argparse.Namespace) -> int:
    connection = connect(args.db)
    manifests = finalized_manifests(args.runs_dir)
    if not manifests:
        print(f"No finalized NetSniper telemetry bundles found under {args.runs_dir}")
        return 0
    for manifest in manifests:
        try:
            print(ingest_manifest(connection, manifest, args.events))
        except DeltaAegisError as exc:
            print(f"ERROR {manifest}: {exc}", file=sys.stderr)
    return 0



def utc_now_text() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def validate_private_cidr(target: str) -> str:
    raw = (target or "").strip()

    if not raw:
        raise DeltaAegisError("target CIDR is required")

    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise DeltaAegisError(f"invalid target CIDR: {raw}") from exc

    if network.version != 4:
        raise DeltaAegisError("only IPv4 CIDR targets are supported")

    if not network.is_private:
        raise DeltaAegisError("target must be a private IPv4 CIDR")

    return str(network)


def build_netsniper_headless_command(netsniper_path: Path, target: str) -> list[str]:
    safe_target = validate_private_cidr(target)

    return [
        str(netsniper_path),
        "--non-interactive",
        "--target",
        safe_target,
        "--greenbone",
        "no",
        "--json-status",
    ]



def create_scan_job(
    connection: sqlite3.Connection,
    target: str,
    netsniper_path: Path,
    runs_dir: Path,
    auto_ingest: bool = False,
) -> dict[str, Any]:
    safe_target = validate_private_cidr(target)
    now = utc_now_text()
    job_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"

    connection.execute(
        """
        INSERT INTO scan_jobs (
            job_id,
            target,
            network_scope,
            status,
            created_at,
            updated_at,
            netsniper_path,
            runs_dir,
            auto_ingest,
            status_json,
            message
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            job_id,
            safe_target,
            safe_target,
            "QUEUED",
            now,
            now,
            str(netsniper_path),
            str(runs_dir),
            1 if auto_ingest else 0,
            "{}",
            "scan job queued",
        ),
    )

    return {
        "job_id": job_id,
        "target": safe_target,
        "network_scope": safe_target,
        "status": "QUEUED",
        "created_at": now,
        "updated_at": now,
        "netsniper_path": str(netsniper_path),
        "runs_dir": str(runs_dir),
        "auto_ingest": auto_ingest,
        "status_json": {},
        "message": "scan job queued",
    }


def update_scan_job(
    connection: sqlite3.Connection,
    job_id: str,
    **fields: Any,
) -> None:
    allowed = {
        "status",
        "started_at",
        "finished_at",
        "bundle_path",
        "exit_code",
        "stdout_log",
        "stderr_log",
        "status_json",
        "message",
    }

    updates = []
    params: list[Any] = []

    for key, value in fields.items():
        if key not in allowed:
            raise DeltaAegisError(f"invalid scan job field update: {key}")

        if key == "status":
            value = str(value).upper()

            if value not in SCAN_JOB_STATUSES:
                raise DeltaAegisError(f"invalid scan job status: {value}")

        if key == "status_json":
            value = json.dumps(value or {}, sort_keys=True)

        updates.append(f"{key} = ?")
        params.append(value)

    updates.append("updated_at = ?")
    params.append(utc_now_text())
    params.append(job_id)

    connection.execute(
        f"""
        UPDATE scan_jobs
        SET {", ".join(updates)}
        WHERE job_id = ?
        """,
        tuple(params),
    )


def extract_netsniper_status_json(stdout_text: str) -> dict[str, Any]:
    for raw_line in reversed((stdout_text or "").splitlines()):
        line = raw_line.strip()

        if not line:
            continue

        candidates = [line]

        if "{" in line and "}" in line:
            candidates.append(line[line.find("{"): line.rfind("}") + 1])

        for candidate in candidates:
            try:
                value = json.loads(candidate)
            except json.JSONDecodeError:
                continue

            if isinstance(value, dict):
                return value

    return {}


def extract_netsniper_bundle_path(status_json: dict[str, Any]) -> str | None:
    for key in ("bundle_path", "bundle_dir", "run_dir", "run_directory"):
        value = status_json.get(key)

        if value:
            return str(value)

    return None


def execute_scan_job(
    connection: sqlite3.Connection,
    job_id: str,
    target: str,
    netsniper_path: Path,
    runs_dir: Path,
    logs_dir: Path,
    events_path: Path,
    auto_ingest: bool = False,
) -> dict[str, Any]:
    safe_target = validate_private_cidr(target)
    netsniper_path = Path(netsniper_path).expanduser()
    runs_dir = Path(runs_dir).expanduser()
    logs_dir = Path(logs_dir).expanduser()
    events_path = Path(events_path).expanduser()

    if not netsniper_path.is_file():
        raise DeltaAegisError(f"NetSniper executable not found: {netsniper_path}")

    command = build_netsniper_headless_command(netsniper_path, safe_target)

    logs_dir.mkdir(parents=True, exist_ok=True)

    stdout_log = logs_dir / f"{job_id}.stdout.log"
    stderr_log = logs_dir / f"{job_id}.stderr.log"

    started_at = utc_now_text()

    update_scan_job(
        connection,
        job_id,
        status="RUNNING",
        started_at=started_at,
        stdout_log=str(stdout_log),
        stderr_log=str(stderr_log),
        message="NetSniper scan running",
    )
    connection.commit()

    try:
        completed = subprocess.run(
            command,
            cwd=str(netsniper_path.parent),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        update_scan_job(
            connection,
            job_id,
            status="FAILED",
            finished_at=utc_now_text(),
            exit_code=127,
            message=f"failed to launch NetSniper: {exc}",
        )
        connection.commit()
        raise DeltaAegisError(f"failed to launch NetSniper: {exc}") from exc

    stdout_log.write_text(completed.stdout or "", encoding="utf-8")
    stderr_log.write_text(completed.stderr or "", encoding="utf-8")

    status_json = extract_netsniper_status_json(completed.stdout)
    bundle_path = extract_netsniper_bundle_path(status_json)
    final_status = "COMPLETED" if completed.returncode == 0 else "FAILED"

    message_parts = []

    if final_status == "COMPLETED":
        message_parts.append("NetSniper scan completed")
    else:
        message_parts.append(f"NetSniper scan failed with exit code {completed.returncode}")

    if bundle_path:
        message_parts.append(f"bundle={bundle_path}")

    if final_status == "COMPLETED" and auto_ingest and bundle_path:
        manifest = Path(bundle_path) / "manifest.json"

        if manifest.is_file():
            ingest_result = ingest_manifest(connection, manifest, events_path)
            message_parts.append(f"auto-ingest={ingest_result}")
        else:
            final_status = "FAILED"
            message_parts.append(f"auto-ingest failed: manifest not found at {manifest}")

    update_scan_job(
        connection,
        job_id,
        status=final_status,
        finished_at=utc_now_text(),
        bundle_path=bundle_path,
        exit_code=completed.returncode,
        status_json=status_json,
        message="; ".join(message_parts),
    )

    connection.commit()

    row = connection.execute(
        "SELECT * FROM scan_jobs WHERE job_id = ?",
        (job_id,),
    ).fetchone()

    if row is None:
        raise DeltaAegisError(f"scan job disappeared unexpectedly: {job_id}")

    return scan_job_to_dict(row)


def command_scan_start(args: argparse.Namespace) -> int:
    connection = connect(args.db)

    safe_target = validate_private_cidr(args.target)
    netsniper_path = Path(args.netsniper_path).expanduser()
    logs_dir = Path(args.scan_logs_dir).expanduser()
    runs_dir = Path(args.runs_dir).expanduser()

    job = create_scan_job(
        connection,
        safe_target,
        netsniper_path,
        runs_dir,
        auto_ingest=args.auto_ingest,
    )
    connection.commit()

    print(f"Created scan job: {job['job_id']}")
    print(f"Target: {safe_target}")
    print(f"NetSniper: {netsniper_path}")
    print(f"Auto-ingest: {'yes' if args.auto_ingest else 'no'}")
    print()

    try:
        result = execute_scan_job(
            connection,
            job["job_id"],
            safe_target,
            netsniper_path,
            runs_dir,
            logs_dir,
            args.events,
            auto_ingest=args.auto_ingest,
        )
    except DeltaAegisError as exc:
        print(f"Scan job failed: {exc}", file=sys.stderr)
        return 1

    print(f"Job: {result['job_id']}")
    print(f"Status: {result['status']}")
    print(f"Exit code: {result.get('exit_code')}")
    print(f"Stdout log: {result.get('stdout_log') or '-'}")
    print(f"Stderr log: {result.get('stderr_log') or '-'}")

    if result.get("bundle_path"):
        print(f"Bundle: {result['bundle_path']}")

    if result.get("message"):
        print(f"Message: {result['message']}")

    return 0 if result["status"] == "COMPLETED" else 1


def decode_json_field(value: str | None, default):
    if not value:
        return default

    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def scan_job_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)

    item["auto_ingest"] = bool(item.get("auto_ingest"))
    item["status_json"] = decode_json_field(item.get("status_json"), {})

    return item


def query_scan_jobs(
    connection: sqlite3.Connection,
    limit: int = 20,
    status: str | None = None,
    scope: str | None = None,
) -> list[sqlite3.Row]:
    clauses = []
    params: list[Any] = []

    if status:
        normalized_status = status.strip().upper()

        if normalized_status not in SCAN_JOB_STATUSES:
            raise DeltaAegisError(f"invalid scan job status: {status}")

        clauses.append("status = ?")
        params.append(normalized_status)

    if scope:
        clauses.append("network_scope = ?")
        params.append(scope)

    where = " WHERE " + " AND ".join(clauses) if clauses else ""

    params.append(limit)

    return connection.execute(
        f"""
        SELECT
            job_id,
            target,
            network_scope,
            status,
            created_at,
            updated_at,
            started_at,
            finished_at,
            netsniper_path,
            runs_dir,
            bundle_path,
            exit_code,
            auto_ingest,
            stdout_log,
            stderr_log,
            status_json,
            message
        FROM scan_jobs
        {where}
        ORDER BY created_at DESC, updated_at DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()


def dashboard_scan_jobs_payload(
    connection: sqlite3.Connection,
    limit: int = 20,
    scope: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    return [
        scan_job_to_dict(row)
        for row in query_scan_jobs(
            connection,
            limit=limit,
            status=status,
            scope=scope,
        )
    ]


def print_scan_job_rows(rows: Iterable[sqlite3.Row]) -> None:
    rows = list(rows)

    if not rows:
        print("No scan jobs found.")
        return

    print("DeltaAegis Scan Jobs")
    print("====================")
    print()

    for row in rows:
        item = scan_job_to_dict(row)
        print(
            f"{item['job_id']}  "
            f"{item['status']:<9}  "
            f"{item['target']:<18}  "
            f"scope={item['network_scope'] or '-'}"
        )
        print(f"  created={item['created_at']}  updated={item['updated_at']}")

        if item.get("bundle_path"):
            print(f"  bundle={item['bundle_path']}")

        if item.get("message"):
            print(f"  message={item['message']}")


def command_scan_jobs(args: argparse.Namespace) -> int:
    connection = connect(args.db)
    scope = optional_network_scope(getattr(args, "scope", None))

    print_scan_job_rows(
        query_scan_jobs(
            connection,
            limit=args.limit,
            status=getattr(args, "status", None),
            scope=scope,
        )
    )

    return 0


def query_events(
    connection: sqlite3.Connection,
    limit: int,
    severity: str | None = None,
    event_type: str | None = None,
    scope: str | None = None,
) -> list[sqlite3.Row]:
    clauses = []
    params = []

    if severity:
        clauses.append("e.severity = ?")
        params.append(severity.upper())

    if event_type:
        clauses.append("e.event_type = ?")
        params.append(event_type.upper())

    if scope:
        clauses.append("s.network_scope = ?")
        params.append(scope)

    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    params.append(limit)

    return connection.execute(
        f"""
        SELECT
            e.event_id,
            e.created_at,
            e.severity,
            e.event_type,
            e.subject_key,
            e.summary,
            e.scan_id,
            e.baseline_scan_id,
            s.network_scope
        FROM delta_events e
        JOIN snapshots s ON s.scan_id = e.scan_id
        {where}
        ORDER BY e.event_id DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()

def print_event_rows(rows: Iterable[sqlite3.Row]) -> None:
    rows = list(rows)
    if not rows:
        print("No matching delta events found.")
    for row in rows:
        print(f"{row['event_id']:>5}  {row['severity']:<6}  {row['event_type']:<36}  {row['subject_key']}")
        print(f"       {row['summary']}")


def command_events(args: argparse.Namespace) -> int:
    scope = optional_network_scope(getattr(args, "scope", None))

    print_event_rows(
        query_events(
            connect(args.db),
            args.limit,
            getattr(args, "severity", None),
            getattr(args, "event_type", None),
            scope,
        )
    )

    return 0

def command_scopes(args: argparse.Namespace) -> int:
    connection = connect(args.db)

    rows = connection.execute(
        """
        SELECT
            network_scope,
            COUNT(*) AS snapshots,
            SUM(CASE WHEN quality_status = 'ACCEPTED' THEN 1 ELSE 0 END) AS accepted_snapshots,
            MAX(created_at) AS latest_scan_at
        FROM snapshots
        GROUP BY network_scope
        ORDER BY latest_scan_at DESC
        """
    ).fetchall()

    if not rows:
        print("No network scopes found.")
        return 0

    print("DeltaAegis Network Scopes")
    print("=========================")
    print()

    for row in rows:
        print(
            f"{row['network_scope']:<18} "
            f"snapshots={row['snapshots']} "
            f"accepted={row['accepted_snapshots']} "
            f"latest={row['latest_scan_at']}"
        )

    return 0


def command_snapshots(args: argparse.Namespace) -> int:
    connection = connect(args.db)
    scope = optional_network_scope(getattr(args, "scope", None))

    where = ""
    params = []

    if scope:
        where = "WHERE network_scope = ?"
        params.append(scope)

    params.append(args.limit)

    rows = connection.execute(
        f"""
        SELECT
            scan_id,
            created_at,
            manifest_schema_version,
            target,
            network_scope,
            scan_profile,
            quality_status,
            hosts_up,
            hosts_total,
            identity_coverage
        FROM snapshots
        {where}
        ORDER BY created_at DESC, imported_at DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()

    for row in rows:
        print(
            f"{row['scan_id']} {row['quality_status']:<15} "
            f"hosts={row['hosts_up']}/{row['hosts_total']} "
            f"mac_identity={float(row['identity_coverage']):.0%} "
            f"scope={row['network_scope']} "
            f"schema={row['manifest_schema_version']} "
            f"profile={row['scan_profile']} "
            f"target={row['target']}"
        )

    return 0


def command_summary(args: argparse.Namespace) -> int:
    connection = connect(args.db)
    snapshot_count = connection.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
    scope_count = connection.execute("SELECT COUNT(DISTINCT network_scope) FROM snapshots").fetchone()[0]
    accepted_count = connection.execute("SELECT COUNT(*) FROM snapshots WHERE quality_status = 'ACCEPTED'").fetchone()[0]
    event_count = connection.execute("SELECT COUNT(*) FROM delta_events").fetchone()[0]
    open_alerts = connection.execute("SELECT COUNT(*) FROM alerts WHERE status = 'OPEN'").fetchone()[0]
    latest = connection.execute("SELECT scan_id, quality_status, hosts_up, identity_coverage FROM snapshots ORDER BY created_at DESC LIMIT 1").fetchone()
    print("DeltaAegis v0.11.1 Summary")
    print(f"Snapshots imported: {snapshot_count}")
    print(f"Network scopes: {scope_count}")
    print(f"Accepted snapshots: {accepted_count}")
    print(f"Delta events:       {event_count}")
    print(f"Open alerts:        {open_alerts}")
    if latest:
        print(f"Latest snapshot:    {latest['scan_id']} ({latest['quality_status']}, hosts={latest['hosts_up']}, mac_identity={float(latest['identity_coverage']):.0%})")
    return 0


def command_approve(args: argparse.Namespace) -> int:
    connection = connect(args.db)
    row = connection.execute("SELECT * FROM snapshots WHERE scan_id = ?", (args.scan_id,)).fetchone()
    if row is None:
        raise DeltaAegisError(f"snapshot not found: {args.scan_id}")
    if row["quality_status"] == "ACCEPTED":
        print(f"Snapshot {args.scan_id} is already accepted.")
        return 0
    previous = latest_accepted_snapshot(connection, row["target"])
    assets = load_assets_from_db(connection, args.scan_id)
    reset_lifecycle(
        connection,
        args.scan_id,
        row["created_at"],
        assets,
        row["network_scope"],
    )
    connection.execute("UPDATE snapshots SET quality_status = 'ACCEPTED', quality_reason = ?, is_accepted_baseline = 1 WHERE scan_id = ?", ("Manually approved as the new baseline by the operator.", args.scan_id))
    approval = event("PROFILE_BASELINE_APPROVED", "INFO", f"scan:{args.scan_id}", "Operator approved this reviewed snapshot as the new comparison baseline.")
    store_events(connection, args.scan_id, previous["scan_id"] if previous else None, [approval], args.events)
    connection.commit()
    print(f"Snapshot {args.scan_id} approved as the new baseline.")
    return 0


def command_alerts(args: argparse.Namespace) -> int:
    connection = connect(args.db)
    scope = optional_network_scope(getattr(args, "scope", None))

    sql = """
        SELECT DISTINCT
            a.alert_id,
            a.status,
            a.severity,
            a.event_type,
            a.subject_key,
            a.summary,
            a.opened_at
        FROM alerts a
        LEFT JOIN delta_events e ON e.event_id = a.last_event_id
        LEFT JOIN snapshots s ON s.scan_id = e.scan_id
        WHERE a.status = ?
    """

    params = [args.status.upper()]

    if scope:
        sql += " AND s.network_scope = ?"
        params.append(scope)

    sql += " ORDER BY a.alert_id DESC LIMIT ?"
    params.append(args.limit)

    rows = connection.execute(sql, tuple(params)).fetchall()

    if not rows:
        scope_note = f" in scope {scope}" if scope else ""
        print(f"No {args.status.upper()} alerts found{scope_note}.")

    for row in rows:
        print(
            f"{row['alert_id']:>5} "
            f"{row['status']:<12} "
            f"{row['severity']:<6} "
            f"{row['event_type']:<30} "
            f"{row['subject_key']}"
        )
        print(f"      {row['summary']}")

    return 0

def set_alert_status(args, status):
    connection = connect(args.db)

    alert = connection.execute(
        """
        SELECT alert_id, status, severity, event_type, subject_key, summary
        FROM alerts
        WHERE alert_id = ?
        """,
        (args.alert_id,),
    ).fetchone()

    if alert is None:
        raise DeltaAegisError(f"alert not found: {args.alert_id}")

    now = utc_now()

    if status == "ACKNOWLEDGED":
        cursor = connection.execute(
            """
            UPDATE alerts
            SET status = ?,
                last_seen_at = ?
            WHERE alert_id = ?
            """,
            (
                status,
                now,
                args.alert_id,
            ),
        )
    elif status == "SUPPRESSED":
        cursor = connection.execute(
            """
            UPDATE alerts
            SET status = ?,
                last_seen_at = ?
            WHERE alert_id = ?
            """,
            (
                status,
                now,
                args.alert_id,
            ),
        )
    else:
        cursor = connection.execute(
            """
            UPDATE alerts
            SET status = ?,
                last_seen_at = ?
            WHERE alert_id = ?
            """,
            (
                status,
                now,
                args.alert_id,
            ),
        )

    if cursor.rowcount != 1:
        raise DeltaAegisError(f"alert not found: {args.alert_id}")

    reason = getattr(args, "reason", None)
    add_alert_note(connection, args.alert_id, status, reason)

    connection.commit()

    print(f"Alert {args.alert_id} marked {status}.")

    if reason:
        print(f"Reason: {reason}")

    return 0

def command_assets(args: argparse.Namespace) -> int:
    connection = connect(args.db)
    scope = optional_network_scope(getattr(args, "scope", None))

    clauses = []
    params = []

    if scope:
        clauses.append("network_scope = ?")
        params.append(scope)

    if args.state:
        clauses.append("state = ?")
        params.append(args.state.upper())

    if args.identity:
        clauses.append("identity_class = ?")
        params.append(args.identity.upper())

    where = "WHERE " + " AND ".join(clauses) if clauses else ""

    params.append(args.limit)

    rows = connection.execute(
        f"""
        SELECT
            network_scope,
            asset_key,
            identity_class,
            state,
            missing_count,
            current_ip,
            mac_address,
            vendor,
            hostname,
            first_seen_at,
            last_seen_at
        FROM asset_lifecycle
        {where}
        ORDER BY network_scope ASC, state ASC, current_ip ASC, asset_key ASC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()

    print("DeltaAegis Asset Inventory")
    print("==========================")

    if scope:
        print(f"Network scope: {scope}")

    if args.state:
        print(f"State filter:  {args.state.upper()}")

    if args.identity:
        print(f"Identity type:  {args.identity.upper()}")

    print()

    if not rows:
        print("No assets matched the requested filters.")
        return 0

    print(
        f"{'Scope':<18} "
        f"{'State':<18} "
        f"{'Identity':<11} "
        f"{'IP':<15} "
        f"{'MAC':<17} "
        f"Asset"
    )
    print("-" * 110)

    for row in rows:
        print(
            f"{row['network_scope']:<18} "
            f"{row['state']:<18} "
            f"{row['identity_class']:<11} "
            f"{row['current_ip']:<15} "
            f"{row['mac_address'] or '-':<17} "
            f"{row['asset_key']}"
        )

    print()
    print(f"Displayed {len(rows)} asset(s).")

    return 0

def command_asset(args: argparse.Namespace) -> int:
    connection = connect(args.db)
    identifier = args.identifier.strip().lower()
    scope = optional_network_scope(getattr(args, "scope", None))

    clauses = [
        """
        (
            LOWER(asset_key) = ?
            OR LOWER(current_ip) = ?
            OR LOWER(COALESCE(mac_address, '')) = ?
        )
        """
    ]

    params = [identifier, identifier, identifier]

    if scope:
        clauses.append("network_scope = ?")
        params.append(scope)

    rows = connection.execute(
        f"""
        SELECT *
        FROM asset_lifecycle
        WHERE {" AND ".join(clauses)}
        ORDER BY network_scope ASC, asset_key ASC
        """,
        tuple(params),
    ).fetchall()

    if not rows:
        if scope:
            raise DeltaAegisError(f"asset not found in scope {scope}: {args.identifier}")
        raise DeltaAegisError(f"asset not found: {args.identifier}")

    if len(rows) > 1 and not scope:
        print(f"Multiple assets matched {args.identifier!r}. Re-run with --scope.")
        print()
        for row in rows:
            print(f"{row['network_scope']:<18} {row['current_ip']:<15} {row['mac_address'] or '-':<17} {row['asset_key']}")
        return 1

    row = rows[0]

    print("Asset History")
    print("────────────────────────────────────────")

    for label, key in [
        ("Network scope", "network_scope"),
        ("Asset key", "asset_key"),
        ("Identity class", "identity_class"),
        ("State", "state"),
        ("Missing scans", "missing_count"),
        ("Current IP", "current_ip"),
        ("MAC address", "mac_address"),
        ("Vendor", "vendor"),
        ("Hostname", "hostname"),
        ("First seen", "first_seen_at"),
        ("Last seen", "last_seen_at"),
    ]:
        value = row[key]
        if value is None or value == "":
            value = "-"
        print(f"{label + ':':<18}{value}")

    print("\nRecent events")

    print_event_rows(
        connection.execute(
            """
            SELECT
                e.event_id,
                e.created_at,
                e.severity,
                e.event_type,
                e.subject_key,
                e.summary
            FROM delta_events e
            JOIN snapshots s ON s.scan_id = e.scan_id
            WHERE e.subject_key = ?
              AND s.network_scope = ?
            ORDER BY e.event_id DESC
            LIMIT ?
            """,
            (row["asset_key"], row["network_scope"], args.limit),
        ).fetchall()
    )

    return 0

def command_health(args: argparse.Namespace) -> int:
    rows = connect(args.db).execute("SELECT scan_id, quality_status, quality_reason, manifest_schema_version, scan_profile, profile_fingerprint, hosts_up, hosts_total, identity_coverage, xml_exit_status, nmap_version, discovery_interface FROM snapshots ORDER BY created_at DESC, imported_at DESC LIMIT ?", (args.limit,)).fetchall()
    for row in rows:
        print(f"{row['scan_id']}  quality={row['quality_status']}  hosts={row['hosts_up']}/{row['hosts_total']}  mac={float(row['identity_coverage']):.0%}  schema={row['manifest_schema_version']}  xml={row['xml_exit_status']}")
        print(f"  profile={row['scan_profile']}  nmap={row['nmap_version'] or '-'}  interface={row['discovery_interface'] or '-'}")
        if row["quality_status"] != "ACCEPTED":
            print(f"  reason={row['quality_reason']}")
    return 0


def command_latest(args: argparse.Namespace) -> int:
    connection = connect(args.db)
    scope = optional_network_scope(getattr(args, "scope", None))

    if scope:
        row = connection.execute(
            """
            SELECT *
            FROM snapshots
            WHERE quality_status = 'ACCEPTED'
              AND network_scope = ?
            ORDER BY created_at DESC, imported_at DESC
            LIMIT 1
            """,
            (scope,),
        ).fetchone()
    else:
        row = connection.execute(
            """
            SELECT *
            FROM snapshots
            WHERE quality_status = 'ACCEPTED'
            ORDER BY created_at DESC, imported_at DESC
            LIMIT 1
            """
        ).fetchone()

    if not row:
        if scope:
            print(f"No accepted snapshot found for scope {scope}.")
        else:
            print("No accepted snapshots.")
        return 1

    print(f"Scan ID: {row['scan_id']}")
    print(f"Target: {row['target']}")
    print(f"Network scope: {row['network_scope']}")
    print(f"Created: {row['created_at']}")
    print(f"Hosts: {row['hosts_up']}/{row['hosts_total']}")
    print(f"MAC identity: {float(row['identity_coverage']):.0%}")
    print(f"Quality: {row['quality_status']}")

    return 0

def command_paths(args):
    print(f"Database: {args.db}")
    print(f"NetSniper runs: {args.runs_dir}")
    print(f"JSONL events: {args.events}")
    print(f"Reports: {args.reports_dir}")
    return 0

def safe_markdown(value):
    if value is None:
        return "-"
    return str(value).replace("|", "\\|").replace("\n", " ").strip() or "-"


def severity_explanation(severity):
    severity = str(severity or "INFO").upper()

    explanations = {
        "CRITICAL": "Immediate review is recommended. This change may represent a major exposure or high-impact network-state change.",
        "HIGH": "Prompt review is recommended. This change may expose a sensitive service, asset, or security-relevant condition.",
        "MEDIUM": "Review is recommended. This change may be expected, but it is important enough to verify.",
        "LOW": "Low-priority review. This change is useful for awareness and historical tracking.",
        "INFO": "Informational event. This primarily supports asset history and investigation context.",
    }

    return explanations.get(
        severity,
        "Review this event in the context of the asset and surrounding network changes.",
    )


def recommended_followup(event_type):
    event_type = str(event_type or "").upper()

    if event_type == "MONITORED_SERVICE_OPENED":
        return [
            "Confirm whether the newly opened service is expected.",
            "Validate the service banner and version.",
            "Check whether authentication is required.",
            "Compare the asset against the previous accepted snapshot.",
        ]

    if event_type == "MONITORED_SERVICE_CLOSED":
        return [
            "Confirm whether the service closure was expected.",
            "Check whether this indicates device hardening, outage, or scan-quality differences.",
            "Compare against the previous accepted snapshot.",
        ]

    if event_type == "NETSNIPER_FINDING_ADDED":
        return [
            "Validate the finding with TrueAegis or manual review.",
            "Confirm whether the exposure is intentional.",
            "Check whether remediation or firewall scoping is required.",
            "Document the asset owner if known.",
        ]

    if event_type in {"ASSET_FIRST_OBSERVED", "IP_FIRST_OBSERVED"}:
        return [
            "Identify the device owner or purpose.",
            "Confirm that the asset is authorized on the network.",
            "Review exposed services on the asset.",
        ]

    if event_type in {"ASSET_NOT_OBSERVED", "ASSET_REMOVED", "IP_NOT_OBSERVED"}:
        return [
            "Confirm whether the asset was intentionally removed or powered off.",
            "Check whether the missing asset affects expected inventory.",
            "Review whether the disappearance could be caused by scan quality or network reachability.",
        ]

    if event_type == "IP_CHANGED":
        return [
            "Confirm whether the IP change is expected from DHCP behavior.",
            "Verify that the MAC-backed identity still maps to the same physical asset.",
            "Review recent services and findings for the asset.",
        ]

    return [
        "Review the event in context.",
        "Compare against the previous accepted snapshot.",
        "Document whether the change is expected or unexpected.",
    ]




def collect_report_alert_notes(connection, alert_ids):
    alert_ids = [alert_id for alert_id in alert_ids if alert_id is not None]

    if not alert_ids:
        return {}

    placeholders = ", ".join(["?"] * len(alert_ids))

    rows = connection.execute(
        f"""
        SELECT note_id, alert_id, action, reason, created_at
        FROM alert_notes
        WHERE alert_id IN ({placeholders})
        ORDER BY alert_id ASC, note_id ASC
        """,
        tuple(alert_ids),
    ).fetchall()

    notes_by_alert = {}

    for row in rows:
        notes_by_alert.setdefault(row["alert_id"], []).append(row)

    return notes_by_alert


def report_alert_review_rows(connection, subjects, limit):
    subjects = [str(subject or "").strip() for subject in subjects]
    subjects = [subject for subject in subjects if subject]

    if not subjects:
        return []

    unique_subjects = []

    for subject in subjects:
        if subject not in unique_subjects:
            unique_subjects.append(subject)

    placeholders = ", ".join(["?"] * len(unique_subjects))

    rows = connection.execute(
        f"""
        SELECT
            a.alert_id,
            a.status,
            a.severity,
            a.event_type,
            a.subject_key,
            a.summary,
            n.note_id,
            n.action,
            n.reason,
            n.created_at
        FROM alerts a
        JOIN alert_notes n ON n.alert_id = a.alert_id
        WHERE a.subject_key IN ({placeholders})
        ORDER BY n.created_at DESC, n.note_id DESC
        LIMIT ?
        """,
        tuple(unique_subjects) + (limit,),
    ).fetchall()

    return rows


def append_report_alert_notes(lines, notes):
    lines.append("")
    lines.append("**Review notes:**")
    lines.append("")

    if not notes:
        lines.append("- No review notes have been recorded for this alert.")
        return

    for note in notes:
        lines.append(
            f"- `{safe_markdown(note['created_at'])}` "
            f"**{safe_markdown(note['action'])}** — "
            f"{safe_markdown(note['reason'])}"
        )

def report_annotation_candidates(subject_key):
    raw = str(subject_key or "").strip()
    candidates = []

    def add(value):
        value = str(value or "").strip()

        if value and value not in candidates:
            candidates.append(value)

    add(raw)

    service_match = re.match(r"^(.+):(tcp|udp)/\d+$", raw, re.IGNORECASE)

    if service_match:
        base = service_match.group(1)
        add(base)

        if base.startswith("ip:"):
            add(base[3:])

    if raw.startswith("ip:"):
        add(raw[3:])

    return candidates


def fetch_report_asset_annotation(connection, subject_key):
    for candidate in report_annotation_candidates(subject_key):
        annotation = connection.execute(
            """
            SELECT asset_key, owner, role, criticality, notes, updated_at
            FROM asset_annotations
            WHERE asset_key = ?
            """,
            (candidate,),
        ).fetchone()

        if annotation is not None:
            return annotation, candidate

    return None


def collect_report_asset_context(connection, subjects):
    context = {}

    for subject in subjects:
        subject = str(subject or "").strip()

        if not subject or subject in context:
            continue

        match = fetch_report_asset_annotation(connection, subject)

        if match is not None:
            context[subject] = match

    return context


def append_report_asset_context(lines, annotation, matched_key):
    lines.append("")
    lines.append("**Asset context:**")
    lines.append("")
    lines.append(f"- Matched annotation: `{safe_markdown(matched_key)}`")
    lines.append(f"- Owner: **{safe_markdown(annotation['owner'] or '-')}**")
    lines.append(f"- Role: **{safe_markdown(annotation['role'] or '-')}**")
    lines.append(f"- Criticality: **{safe_markdown(annotation['criticality'] or '-')}**")
    lines.append(f"- Notes: {safe_markdown(annotation['notes'] or '-')}")
    lines.append(f"- Annotation updated: `{safe_markdown(annotation['updated_at'])}`")

def fetch_latest_accepted_snapshot(connection):
    return connection.execute(
        """
        SELECT *
        FROM snapshots
        WHERE quality_status = 'ACCEPTED'
        ORDER BY created_at DESC, imported_at DESC
        LIMIT 1
        """
    ).fetchone()


def report_event_rows(connection, latest_only, since, severity, limit, scope=None):
    clauses = []
    params = []

    if latest_only:
        if scope:
            latest = connection.execute(
                """
                SELECT scan_id
                FROM snapshots
                WHERE quality_status = 'ACCEPTED'
                  AND network_scope = ?
                ORDER BY created_at DESC, imported_at DESC
                LIMIT 1
                """,
                (scope,),
            ).fetchone()
        else:
            latest = connection.execute(
                """
                SELECT scan_id
                FROM snapshots
                WHERE quality_status = 'ACCEPTED'
                ORDER BY created_at DESC, imported_at DESC
                LIMIT 1
                """
            ).fetchone()

        if latest is None:
            return []

        clauses.append("e.scan_id = ?")
        params.append(latest["scan_id"])

    if since:
        clauses.append("e.created_at >= ?")
        params.append(since)

    if severity:
        clauses.append("e.severity = ?")
        params.append(severity.upper())

    if scope:
        clauses.append("s.network_scope = ?")
        params.append(scope)

    where = "WHERE " + " AND ".join(clauses) if clauses else ""

    params.append(limit)

    return connection.execute(
        f"""
        SELECT
            e.event_id,
            e.scan_id,
            e.baseline_scan_id,
            e.created_at,
            e.severity,
            e.event_type,
            e.subject_key,
            e.previous_value,
            e.current_value,
            e.summary,
            s.network_scope
        FROM delta_events e
        JOIN snapshots s ON s.scan_id = e.scan_id
        {where}
        ORDER BY e.event_id DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()

def risk_level(score):
    if score >= 85:
        return "CRITICAL"

    if score >= 65:
        return "HIGH"

    if score >= 35:
        return "MEDIUM"

    if score >= 15:
        return "LOW"

    return "INFO"


def risk_add_reason(reasons, reason):
    reason = str(reason or "").strip()

    if reason and reason not in reasons:
        reasons.append(reason)



PORT_BEHAVIOR_HIGH_SIGNAL_PORTS = {
    21, 22, 23, 135, 139, 445, 1433, 1521, 2375, 2376,
    3306, 3389, 5000, 5432, 5900, 5985, 5986, 6379,
    9200, 9300, 27017,
}

PORT_BEHAVIOR_MEDIUM_SIGNAL_PORTS = {
    80, 443, 554, 631, 8080, 8443, 8554, 8888, 9100,
}

PORT_BEHAVIOR_SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def normalize_mac_identity(asset_key, mac_address):
    key = str(asset_key or "").strip().lower()
    mac = str(mac_address or "").strip().lower()

    if key.startswith("mac:"):
        return key

    if MAC_RE.match(mac):
        return f"mac:{mac}"

    return None


def port_behavior_key(protocol, port):
    protocol_text = str(protocol or "tcp").strip().lower() or "tcp"

    try:
        port_number = int(port)
    except (TypeError, ValueError):
        port_number = -1

    return f"{protocol_text}/{port_number}"


def port_behavior_signal_severity(behavior, port, currently_open):
    if behavior == "PORT_FLAPPING":
        if currently_open and port in PORT_BEHAVIOR_HIGH_SIGNAL_PORTS:
            return "HIGH"
        return "MEDIUM"

    if behavior == "UNEXPECTED_PORT_OPENED":
        if port in PORT_BEHAVIOR_HIGH_SIGNAL_PORTS:
            return "HIGH"
        if port in PORT_BEHAVIOR_MEDIUM_SIGNAL_PORTS:
            return "MEDIUM"
        return "LOW"

    if behavior == "PORT_NO_LONGER_OBSERVED":
        return "INFO"

    return "INFO"


def accepted_snapshots_for_port_behavior(connection, scope=None, limit=6):
    clauses = ["(is_accepted_baseline = 1 OR quality_status = 'ACCEPTED')"]
    params = []

    if scope:
        clauses.append("network_scope = ?")
        params.append(scope)

    params.append(limit)

    return connection.execute(
        f"""
        SELECT scan_id, network_scope, created_at, imported_at
        FROM snapshots
        WHERE {" AND ".join(clauses)}
        ORDER BY created_at DESC, imported_at DESC, scan_id DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()


def load_mac_open_ports_for_scans(connection, scan_ids):
    if not scan_ids:
        return {}

    placeholders = ",".join("?" for _ in scan_ids)

    rows = connection.execute(
        f"""
        SELECT
            ao.scan_id,
            ao.asset_key,
            ao.ip_address,
            ao.mac_address,
            ao.hostname,
            ao.vendor,
            COALESCE(
                ao.classification_type,
                ao.classification_primary_type,
                ao.device_type,
                'Unknown'
            ) AS device_type,
            so.protocol,
            so.port,
            so.state,
            so.service_name,
            so.product,
            so.version
        FROM asset_observations ao
        JOIN service_observations so
          ON so.scan_id = ao.scan_id
         AND so.asset_key = ao.asset_key
        WHERE ao.scan_id IN ({placeholders})
          AND lower(COALESCE(so.state, 'open')) = 'open'
        ORDER BY ao.scan_id, ao.asset_key, so.protocol, so.port
        """,
        tuple(scan_ids),
    ).fetchall()

    by_scan = {}

    for row in rows:
        mac_identity = normalize_mac_identity(row["asset_key"], row["mac_address"])

        if not mac_identity:
            continue

        scan_entry = by_scan.setdefault(row["scan_id"], {})
        mac_entry = scan_entry.setdefault(
            mac_identity,
            {
                "mac_identity": mac_identity,
                "asset_key": row["asset_key"],
                "ip_address": row["ip_address"],
                "mac_address": row["mac_address"],
                "hostname": row["hostname"],
                "vendor": row["vendor"],
                "device_type": row["device_type"],
                "ports": set(),
                "port_details": {},
            },
        )

        port_key = port_behavior_key(row["protocol"], row["port"])
        mac_entry["ports"].add(port_key)
        mac_entry["port_details"][port_key] = {
            "protocol": str(row["protocol"] or "tcp").lower(),
            "port": int(row["port"]),
            "service_name": row["service_name"],
            "product": row["product"],
            "version": row["version"],
        }

    return by_scan


def mac_port_behavior_rows(connection, limit=50, scope=None, lookback=5):
    lookback = max(1, int(lookback or 5))
    latest_candidates = accepted_snapshots_for_port_behavior(
        connection,
        scope=scope,
        limit=1,
    )

    if not latest_candidates:
        return []

    latest = latest_candidates[0]
    effective_scope = scope or latest["network_scope"]

    snapshots = accepted_snapshots_for_port_behavior(
        connection,
        scope=effective_scope,
        limit=lookback + 1,
    )

    if not snapshots:
        return []

    ordered_snapshots = list(reversed(snapshots))
    latest_scan = snapshots[0]
    latest_scan_id = latest_scan["scan_id"]
    scan_ids = [row["scan_id"] for row in ordered_snapshots]
    prior_scan_ids = [scan_id for scan_id in scan_ids if scan_id != latest_scan_id]

    ports_by_scan = load_mac_open_ports_for_scans(connection, scan_ids)
    latest_ports_by_mac = ports_by_scan.get(latest_scan_id, {})
    rows = []

    for mac_identity, latest_entry in latest_ports_by_mac.items():
        current_ports = set(latest_entry.get("ports") or set())
        historical_ports = set()

        for scan_id in prior_scan_ids:
            historical_ports.update(
                ports_by_scan.get(scan_id, {})
                .get(mac_identity, {})
                .get("ports", set())
            )

        candidate_ports = set(current_ports) | historical_ports

        if not prior_scan_ids:
            for port_key in sorted(current_ports):
                detail = latest_entry["port_details"].get(port_key, {})
                rows.append(
                    {
                        "behavior": "PORT_BASELINE_ESTABLISHED",
                        "severity": "INFO",
                        "mac_identity": mac_identity,
                        "asset_key": latest_entry.get("asset_key"),
                        "ip_address": latest_entry.get("ip_address"),
                        "hostname": latest_entry.get("hostname"),
                        "vendor": latest_entry.get("vendor"),
                        "device_type": latest_entry.get("device_type"),
                        "port_key": port_key,
                        "protocol": detail.get("protocol", "tcp"),
                        "port": detail.get("port"),
                        "current_state": "OPEN",
                        "baseline_state": "NO_PRIOR_BASELINE",
                        "seen_count": 1,
                        "missing_count": 0,
                        "transition_count": 0,
                        "latest_scan_id": latest_scan_id,
                        "baseline_scan_ids": prior_scan_ids,
                        "reason": f"{port_key} is part of the first accepted MAC-port baseline for {mac_identity}.",
                    }
                )
            continue

        for port_key in sorted(candidate_ports):
            states = [
                port_key
                in ports_by_scan.get(scan_id, {})
                .get(mac_identity, {})
                .get("ports", set())
                for scan_id in scan_ids
            ]

            currently_open = states[-1]
            was_seen_before = any(states[:-1])
            seen_count = sum(1 for state in states if state)
            missing_count = len(states) - seen_count
            transition_count = sum(
                1
                for previous, current in zip(states, states[1:])
                if previous != current
            )

            behavior = None

            if currently_open and not was_seen_before:
                behavior = "UNEXPECTED_PORT_OPENED"
            elif transition_count >= 2:
                behavior = "PORT_FLAPPING"
            elif was_seen_before and not currently_open:
                behavior = "PORT_NO_LONGER_OBSERVED"

            if behavior is None:
                continue

            detail = latest_entry.get("port_details", {}).get(port_key, {})

            if not detail:
                for scan_id in reversed(prior_scan_ids):
                    detail = (
                        ports_by_scan.get(scan_id, {})
                        .get(mac_identity, {})
                        .get("port_details", {})
                        .get(port_key, {})
                    )

                    if detail:
                        break

            port_number = int(detail.get("port") or str(port_key).split("/")[-1])
            severity = port_behavior_signal_severity(
                behavior,
                port_number,
                currently_open,
            )

            if behavior == "UNEXPECTED_PORT_OPENED":
                reason = (
                    f"{port_key} is open in latest scan {latest_scan_id} but was not "
                    f"observed for {mac_identity} across {len(prior_scan_ids)} prior accepted scan(s)."
                )
                baseline_state = "NOT_PREVIOUSLY_OBSERVED"
                current_state = "OPEN"
            elif behavior == "PORT_FLAPPING":
                reason = (
                    f"{port_key} changed open/not-observed state {transition_count} time(s) "
                    f"across {len(scan_ids)} accepted scan(s) for {mac_identity}."
                )
                baseline_state = "VOLATILE"
                current_state = "OPEN" if currently_open else "NOT_OBSERVED"
            else:
                reason = (
                    f"{port_key} was previously observed for {mac_identity} but is not open "
                    f"in latest scan {latest_scan_id}."
                )
                baseline_state = "PREVIOUSLY_OBSERVED"
                current_state = "NOT_OBSERVED"

            rows.append(
                {
                    "behavior": behavior,
                    "severity": severity,
                    "mac_identity": mac_identity,
                    "asset_key": latest_entry.get("asset_key"),
                    "ip_address": latest_entry.get("ip_address"),
                    "hostname": latest_entry.get("hostname"),
                    "vendor": latest_entry.get("vendor"),
                    "device_type": latest_entry.get("device_type"),
                    "port_key": port_key,
                    "protocol": detail.get("protocol", "tcp"),
                    "port": port_number,
                    "current_state": current_state,
                    "baseline_state": baseline_state,
                    "seen_count": seen_count,
                    "missing_count": missing_count,
                    "transition_count": transition_count,
                    "latest_scan_id": latest_scan_id,
                    "baseline_scan_ids": prior_scan_ids,
                    "reason": reason,
                }
            )

    rows.sort(
        key=lambda row: (
            PORT_BEHAVIOR_SEVERITY_ORDER.get(row["severity"], 99),
            row["behavior"],
            row["mac_identity"],
            int(row["port"] or 0),
        )
    )

    return rows[:limit]


def print_port_behavior_rows(rows):
    rows = list(rows)

    if not rows:
        print("No MAC-port behavior changes found.")
        return

    print("DeltaAegis MAC-Port Behavior")
    print("============================")
    print()

    for row in rows:
        print(
            f"{row['severity']:<8} "
            f"{row['behavior']:<26} "
            f"{row['mac_identity']} "
            f"{row['port_key']} "
            f"{row['current_state']}"
        )
        print(f"  IP:       {row.get('ip_address') or '-'}")
        print(f"  Device:   {row.get('device_type') or 'Unknown'}")
        print(f"  Scan:     {row.get('latest_scan_id')}")
        print(f"  Reason:   {row.get('reason')}")
        print()


def command_port_behavior(args):
    connection = connect(args.db)
    scope = optional_network_scope(getattr(args, "scope", None))

    rows = mac_port_behavior_rows(
        connection,
        limit=args.limit,
        scope=scope,
        lookback=args.lookback,
    )

    print_port_behavior_rows(rows)
    return 0


def risk_subject_record(subject_key):
    return {
        "subject_key": subject_key,
        "identity_asset_key": None,
        "ip_address": None,
        "mac_address": None,
        "hostname": None,
        "vendor": None,
        "identity_state": None,
        "identity_last_seen_at": None,
        "identity_confidence": None,
        "score": 0,
        "level": "INFO",
        "event_count": 0,
        "open_alerts": 0,
        "acknowledged_alerts": 0,
        "suppressed_alerts": 0,
        "resolved_alerts": 0,
        "max_event_severity": "INFO",
        "latest_event_at": None,
        "latest_alert_at": None,
        "owner": None,
        "role": None,
        "criticality": None,
        "notes": None,
        "annotation_key": None,
        "reasons": [],
    }


def severity_rank(severity):
    order = {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    return order.get(str(severity or "").upper(), 0)


def set_max_severity(record, severity):
    severity = str(severity or "INFO").upper()

    if severity_rank(severity) > severity_rank(record["max_event_severity"]):
        record["max_event_severity"] = severity


def fetch_risk_annotation(connection, subject_key):
    if "fetch_report_asset_annotation" in globals():
        match = fetch_report_asset_annotation(connection, subject_key)

        if match is not None:
            return match

    try:
        annotation = connection.execute(
            """
            SELECT asset_key, owner, role, criticality, notes, updated_at
            FROM asset_annotations
            WHERE asset_key = ?
            """,
            (subject_key,),
        ).fetchone()
    except Exception:
        return None

    if annotation is None:
        return None

    return annotation, subject_key



def subject_identity_candidates(subject_key):
    raw = str(subject_key or "").strip()
    candidates = []
    ip_candidates = []
    mac_candidates = []

    def add_candidate(value):
        value = str(value or "").strip()

        if value and value not in candidates:
            candidates.append(value)

    def add_ip(value):
        value = str(value or "").strip()

        if not value:
            return

        try:
            ipaddress.ip_address(value)
        except ValueError:
            return

        if value not in ip_candidates:
            ip_candidates.append(value)

    def add_mac(value):
        value = normalize_mac(value)

        if value and value not in mac_candidates:
            mac_candidates.append(value)

    if "report_annotation_candidates" in globals():
        for candidate in report_annotation_candidates(raw):
            add_candidate(candidate)
    else:
        add_candidate(raw)

    for candidate in list(candidates):
        if candidate.startswith("ip:"):
            add_ip(candidate[3:])
        elif candidate.startswith("mac:"):
            add_mac(candidate[4:])
        else:
            add_ip(candidate)
            add_mac(candidate)

    return candidates, ip_candidates, mac_candidates


def fetch_subject_identity(connection, subject_key, scope=None):
    candidates, ip_candidates, mac_candidates = subject_identity_candidates(subject_key)

    lifecycle_scope_clause = ""
    lifecycle_params = []

    if scope:
        lifecycle_scope_clause = " AND network_scope = ?"
        lifecycle_params.append(scope)

    for candidate in candidates:
        row = connection.execute(
            f"""
            SELECT
                asset_key,
                current_ip AS ip_address,
                mac_address,
                vendor,
                hostname,
                state,
                last_seen_at,
                network_scope
            FROM asset_lifecycle
            WHERE asset_key = ?
            {lifecycle_scope_clause}
            """,
            (candidate, *lifecycle_params),
        ).fetchone()

        if row is not None:
            return dict(row)

    for ip_address in ip_candidates:
        row = connection.execute(
            f"""
            SELECT
                asset_key,
                current_ip AS ip_address,
                mac_address,
                vendor,
                hostname,
                state,
                last_seen_at,
                network_scope
            FROM asset_lifecycle
            WHERE current_ip = ?
            {lifecycle_scope_clause}
            """,
            (ip_address, *lifecycle_params),
        ).fetchone()

        if row is not None:
            return dict(row)

    for mac_address in mac_candidates:
        row = connection.execute(
            f"""
            SELECT
                asset_key,
                current_ip AS ip_address,
                mac_address,
                vendor,
                hostname,
                state,
                last_seen_at,
                network_scope
            FROM asset_lifecycle
            WHERE mac_address = ?
            {lifecycle_scope_clause}
            """,
            (mac_address, *lifecycle_params),
        ).fetchone()

        if row is not None:
            return dict(row)

    observation_scope_clause = ""
    observation_params = []

    if scope:
        observation_scope_clause = " AND s.network_scope = ?"
        observation_params.append(scope)

    for candidate in candidates:
        row = connection.execute(
            f"""
            SELECT
                ao.asset_key,
                ao.ip_address,
                ao.mac_address,
                ao.vendor,
                ao.hostname,
                'OBSERVED' AS state,
                s.created_at AS last_seen_at,
                s.network_scope
            FROM asset_observations ao
            JOIN snapshots s ON s.scan_id = ao.scan_id
            WHERE ao.asset_key = ?
            {observation_scope_clause}
            ORDER BY s.created_at DESC, s.imported_at DESC
            LIMIT 1
            """,
            (candidate, *observation_params),
        ).fetchone()

        if row is not None:
            return dict(row)

    for ip_address in ip_candidates:
        row = connection.execute(
            f"""
            SELECT
                ao.asset_key,
                ao.ip_address,
                ao.mac_address,
                ao.vendor,
                ao.hostname,
                'OBSERVED' AS state,
                s.created_at AS last_seen_at,
                s.network_scope
            FROM asset_observations ao
            JOIN snapshots s ON s.scan_id = ao.scan_id
            WHERE ao.ip_address = ?
            {observation_scope_clause}
            ORDER BY s.created_at DESC, s.imported_at DESC
            LIMIT 1
            """,
            (ip_address, *observation_params),
        ).fetchone()

        if row is not None:
            return dict(row)

    for mac_address in mac_candidates:
        row = connection.execute(
            f"""
            SELECT
                ao.asset_key,
                ao.ip_address,
                ao.mac_address,
                ao.vendor,
                ao.hostname,
                'OBSERVED' AS state,
                s.created_at AS last_seen_at,
                s.network_scope
            FROM asset_observations ao
            JOIN snapshots s ON s.scan_id = ao.scan_id
            WHERE ao.mac_address = ?
            {observation_scope_clause}
            ORDER BY s.created_at DESC, s.imported_at DESC
            LIMIT 1
            """,
            (mac_address, *observation_params),
        ).fetchone()

        if row is not None:
            return dict(row)

    fallback_ip = ip_candidates[0] if ip_candidates else None
    fallback_mac = mac_candidates[0] if mac_candidates else None

    return {
        "asset_key": candidates[0] if candidates else str(subject_key or ""),
        "ip_address": fallback_ip,
        "mac_address": fallback_mac,
        "vendor": None,
        "hostname": None,
        "state": "UNKNOWN",
        "last_seen_at": None,
        "network_scope": scope,
    }

def identity_confidence_label(ip_address, mac_address):
    ip_value = str(ip_address or "").strip().lower()
    mac_value = str(mac_address or "").strip().lower()

    ip_present = bool(ip_value and ip_value != "unknown" and ip_value != "-")
    mac_present = bool(mac_value and mac_value != "unknown" and mac_value != "-")

    if ip_present and mac_present:
        return "Strong identity: MAC + IP observed"

    if ip_present:
        return "Partial identity: IP only"

    if mac_present:
        return "Partial identity: MAC only"

    return "Unknown identity: no MAC/IP mapping found"

def apply_identity_to_risk_record(connection, subject_key, record, scope=None):
    identity = fetch_subject_identity(connection, subject_key, scope=scope)

    record["identity_asset_key"] = identity.get("asset_key")
    record["ip_address"] = identity.get("ip_address")
    record["mac_address"] = identity.get("mac_address")
    record["hostname"] = identity.get("hostname")
    record["vendor"] = identity.get("vendor")
    record["identity_state"] = identity.get("state")
    record["identity_last_seen_at"] = identity.get("last_seen_at")
    record["identity_network_scope"] = identity.get("network_scope")
    record["identity_confidence"] = identity_confidence_label(
        record.get("ip_address"),
        record.get("mac_address"),
    )

    return record

def dashboard_enrich_subject_rows(connection, rows, subject_field="subject_key", scope=None):
    enriched = []

    for row in rows:
        item = dict(row)
        identity = fetch_subject_identity(
            connection,
            item.get(subject_field),
            scope=scope,
        )

        item["identity_asset_key"] = identity.get("asset_key")
        item["identity_ip_address"] = identity.get("ip_address")
        item["identity_mac_address"] = identity.get("mac_address")
        item["identity_hostname"] = identity.get("hostname")
        item["identity_vendor"] = identity.get("vendor")
        item["identity_network_scope"] = identity.get("network_scope")
        item["identity_confidence"] = identity_confidence_label(
            item.get("identity_ip_address"),
            item.get("identity_mac_address"),
        )

        enriched.append(item)

    return enriched

RISK_SEVERITY_POINTS = {
    "INFO": 5,
    "LOW": 10,
    "MEDIUM": 25,
    "HIGH": 45,
    "CRITICAL": 65,
}


RISK_CRITICALITY_POINTS = {
    "LOW": 5,
    "MEDIUM": 10,
    "HIGH": 20,
    "CRITICAL": 35,
    "MISSION_CRITICAL": 45,
}


def risk_json_list(value):
    if value in {None, "", "[]"}:
        return []

    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []

    return parsed if isinstance(parsed, list) else []


def risk_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def risk_latest_asset_context(connection, subject_key, scope=None):
    if not subject_key or str(subject_key).startswith("scan:"):
        return None

    clauses = ["al.asset_key = ?"]
    params = [subject_key]

    if scope:
        clauses.append("al.network_scope = ?")
        params.append(scope)

    where = " AND ".join(clauses)

    row = connection.execute(
        f"""
        SELECT
            al.network_scope,
            al.asset_key,
            al.identity_class,
            al.state,
            al.current_ip,
            al.mac_address,
            al.vendor,
            al.hostname,
            al.last_seen_scan_id,
            ao.scan_id,
            ao.device_type,
            ao.device_type_confidence,
            ao.classification_type,
            ao.classification_primary_type,
            ao.classification_confidence,
            ao.classification_confidence_label,
            ao.classification_decision,
            ao.classification_method,
              ao.classification_confidence_band,
              ao.classification_calibrated_decision,
              ao.classification_siem_action,
              ao.classification_calibration_reason,
              ao.classification_validation_state,
              ao.classification_contradiction_count,
              ao.classification_validator_summary_json,
              ao.classification_validators_json,
            ao.classification_evidence_json,
            ao.classification_contradictions_json,
            ao.classification_candidates_json
        FROM asset_lifecycle al
        LEFT JOIN asset_observations ao
          ON ao.scan_id = al.last_seen_scan_id
         AND ao.asset_key = al.asset_key
        WHERE {where}
        ORDER BY al.last_seen_at DESC
        LIMIT 1
        """,
        tuple(params),
    ).fetchone()

    if not row:
        return None

    context = dict(row)
    scan_id = context.get("scan_id") or context.get("last_seen_scan_id")
    services = []

    if scan_id:
        services = [
            dict(item)
            for item in connection.execute(
                """
                SELECT protocol, port, state, service_name, product, version
                FROM service_observations
                WHERE scan_id = ?
                  AND asset_key = ?
                ORDER BY protocol ASC, port ASC
                """,
                (scan_id, subject_key),
            ).fetchall()
        ]

    context["services"] = services
    return context


def risk_classification_context(asset_context):
    if not asset_context:
        return {
            "classification": None,
            "classification_decision": "unknown",
            "classification_confidence": 0,
            "classification_risk_points": 0,
            "classification_risk_reasons": [],
            "classification_open_ports": [],
        }

    classification = (
        asset_context.get("classification_type")
        or asset_context.get("classification_primary_type")
        or asset_context.get("device_type")
        or "Unknown"
    )

    confidence = risk_int(
        asset_context.get("classification_confidence")
        if asset_context.get("classification_confidence") is not None
        else asset_context.get("device_type_confidence"),
        0,
    )

    decision = str(asset_context.get("classification_decision") or "").strip().lower()
    confidence_band = str(asset_context.get("classification_confidence_band") or "").strip().lower()
    calibrated_decision = str(asset_context.get("classification_calibrated_decision") or "").strip().lower()
    siem_action = str(asset_context.get("classification_siem_action") or "").strip().lower()
    validation_state = str(asset_context.get("classification_validation_state") or "").strip().lower()


    if calibrated_decision in {"classified", "possible", "unknown"}:
        decision = calibrated_decision

    if decision not in {"classified", "possible", "unknown"}:
        if confidence >= 40:
            decision = "classified"
        elif confidence > 0:
            decision = "possible"
        else:
            decision = "unknown"

    services = asset_context.get("services") or []
    open_ports = sorted(
        {
            risk_int(service.get("port"), -1)
            for service in services
            if str(service.get("state") or "open").lower() == "open"
        }
    )
    open_ports = [port for port in open_ports if port > 0]
    port_set = set(open_ports)

    contradictions = risk_json_list(asset_context.get("classification_contradictions_json"))
    contradiction_count = risk_int(
        asset_context.get("classification_contradiction_count"),
        len(contradictions),
    )
    if contradiction_count < len(contradictions):
        contradiction_count = len(contradictions)
    classification_text = str(classification or "Unknown").lower()

    points = 0
    reasons = []

    def add(amount, reason):
        nonlocal points
        points += amount
        reasons.append(f"{reason}: +{amount}")

    # NetSniper v1.6 SIEM action policy. Low-confidence labels should not
    # inflate asset risk unless review or contradiction handling requires it.
    if siem_action == "display_only":
        return {
            "classification": classification,
            "classification_decision": decision,
            "classification_confidence": confidence,
            "classification_confidence_band": confidence_band or None,
            "classification_calibrated_decision": calibrated_decision or None,
            "classification_siem_action": siem_action,
            "classification_validation_state": validation_state or None,
            "classification_risk_points": 0,
            "classification_risk_reasons": [],
            "classification_open_ports": open_ports,
        }

    if siem_action == "review_queue":
        if confidence > 0 or open_ports:
            add(5, "NetSniper v1.6 marked classification for review queue")
        return {
            "classification": classification,
            "classification_decision": decision,
            "classification_confidence": confidence,
            "classification_confidence_band": confidence_band or None,
            "classification_calibrated_decision": calibrated_decision or None,
            "classification_siem_action": siem_action,
            "classification_validation_state": validation_state or None,
            "classification_risk_points": min(points, 5),
            "classification_risk_reasons": reasons,
            "classification_open_ports": open_ports,
        }

    # nudge risk priority, not override event severity or confirmed alerts.
    if contradiction_count or siem_action == "contradiction_review":
        add(20, "Classification-aware role context found contradictory device evidence")

    if "active directory" in classification_text or "domain controller" in classification_text:
        add(15, "Classification-aware role context identified identity infrastructure")
        if port_set & {23, 3389, 5985, 5986}:
            add(10, "Identity infrastructure exposes remote administration service(s)")

    if "container" in classification_text or "kubernetes" in classification_text:
        exposed = sorted(port_set & {2375, 2376, 5000, 6443, 9000, 9443, 10250, 10255})
        if exposed:
            add(
                15,
                "Classification-aware role context identified container/orchestration exposure "
                f"on tcp/{','.join(str(port) for port in exposed)}",
            )

    if "printer" in classification_text:
        exposed = sorted(port_set & {631, 9100})
        if exposed:
            add(
                5,
                "Classification-aware role context identified printer management/printing exposure "
                f"on tcp/{','.join(str(port) for port in exposed)}",
            )

        suspicious = sorted(port_set & {23, 445, 3389})
        if suspicious:
            add(
                15,
                "Printer-class device exposes unusual remote access/file-sharing service(s) "
                f"on tcp/{','.join(str(port) for port in suspicious)}",
            )

    if "camera" in classification_text or "nvr" in classification_text:
        exposed = sorted(port_set & {554, 8554})
        if exposed:
            add(
                5,
                "Classification-aware role context identified camera/RTSP exposure "
                f"on tcp/{','.join(str(port) for port in exposed)}",
            )

        suspicious = sorted(port_set & {23, 445, 3389})
        if suspicious:
            add(
                15,
                "Camera/NVR-class device exposes unusual remote access/file-sharing service(s) "
                f"on tcp/{','.join(str(port) for port in suspicious)}",
            )

    if "database" in classification_text:
        exposed = sorted(port_set & {1433, 1521, 3306, 5432, 6379, 9200, 9300, 27017})
        if exposed:
            add(
                15,
                "Classification-aware role context identified database exposure "
                f"on tcp/{','.join(str(port) for port in exposed)}",
            )

    is_unknown = classification in {None, "", "Unknown", "Unknown / Ambiguous"}

    if (decision in {"possible", "unknown"} or is_unknown) and open_ports:
        add(
            10,
            "Classification-aware role context found exposed services on weak/unknown asset",
        )

    if decision == "possible" and confidence > 0:
        add(5, "Classification-aware role context requires manual verification of weak classification")

    points = min(points, 30)

    return {
        "classification": classification,
        "classification_decision": decision,
        "classification_confidence": confidence,
        "classification_confidence_band": confidence_band or None,
        "classification_calibrated_decision": calibrated_decision or None,
        "classification_siem_action": siem_action or None,
        "classification_validation_state": validation_state or None,
        "classification_risk_points": points,
        "classification_risk_reasons": reasons,
        "classification_open_ports": open_ports,
    }


def apply_classification_to_risk_record(connection, subject_key, record, scope=None):
    context = risk_classification_context(
        risk_latest_asset_context(connection, subject_key, scope=scope)
    )

    record["classification"] = context["classification"]
    record["classification_decision"] = context["classification_decision"]
    record["classification_confidence"] = context["classification_confidence"]
    record["classification_confidence_band"] = context.get("classification_confidence_band")
    record["classification_calibrated_decision"] = context.get("classification_calibrated_decision")
    record["classification_siem_action"] = context.get("classification_siem_action")
    record["classification_validation_state"] = context.get("classification_validation_state")
    record["classification_risk_points"] = context["classification_risk_points"]
    record["classification_risk_reasons"] = context["classification_risk_reasons"]
    record["classification_open_ports"] = context["classification_open_ports"]



def risk_role_recommended_actions(record):
    classification = str(record.get("classification") or "Unknown").strip() or "Unknown"
    classification_text = classification.lower()
    decision = str(record.get("classification_decision") or "unknown").lower()
    confidence = risk_int(record.get("classification_confidence"), 0)
    open_ports = set(record.get("classification_open_ports") or [])
    subject_key = record.get("subject_key") or "this asset"

    unknown_labels = {
        "",
        "unknown",
        "unknown / ambiguous",
        "unknown/ambiguous",
        "ambiguous",
    }

    is_unknown_role = classification_text in unknown_labels
    actions = []

    def add(action):
        if action and action not in actions:
            actions.append(action)

    if any(
        "contradictory" in str(reason).lower()
        for reason in record.get("classification_risk_reasons", [])
    ):
        add("Resolve contradictory device evidence before treating the asset role as confirmed.")

    if record.get("port_behavior_points") or record.get("port_behavior"):
        add("Review MAC-port behavior changes and confirm whether the new or volatile service is expected for this device.")

    if is_unknown_role:
        if open_ports:
            add("Identify this unknown asset before closing the investigation; exposed services are present but the role is not established.")
        else:
            add("Annotate this unknown asset if it is expected infrastructure, otherwise monitor for future service changes.")
    else:
        if decision == "classified" and confidence >= 40:
            add(f"Confirm the {classification} role is expected for this network scope and annotate ownership if it is known.")
        elif decision == "possible":
            add(f"Verify the suspected {classification} role with banner review, hostname/vendor context, or manual asset annotation.")
        else:
            add(f"Treat the {classification} role as suspected, not confirmed; validate it with service evidence, vendor context, or manual asset annotation.")

    if "active directory" in classification_text or "domain controller" in classification_text:
        add("Confirm this is an authorized domain controller and verify ownership, patch level, and backup/restore coverage.")
        if open_ports & {3389, 5985, 5986, 23}:
            add("Review remote administration exposure on the domain-controller candidate and restrict access to management networks.")
        if open_ports & {445, 139}:
            add("Validate SMB exposure, signing posture, and administrative share access on the identity-infrastructure candidate.")

    if "container" in classification_text or "kubernetes" in classification_text:
        if open_ports & {2375, 2376, 5000, 6443, 9000, 9443, 10250, 10255}:
            add("Review exposed container or orchestration management services for authentication, TLS, and network restriction.")
        add("Confirm whether this asset should be treated as infrastructure and annotate its owner and environment.")

    if "printer" in classification_text:
        if open_ports & {631, 9100}:
            add("Verify printer management/printing exposure is expected and restrict it to trusted print clients where possible.")
        if open_ports & {23, 80, 443, 445, 3389}:
            add("Review printer administrative interfaces and disable unusual remote access or file-sharing services if not required.")
        add("Annotate printer location, owner, and business criticality to reduce future review noise.")

    if "camera" in classification_text or "nvr" in classification_text:
        if open_ports & {554, 8554}:
            add("Verify RTSP/camera exposure requires authentication and is limited to approved monitoring systems.")
        if open_ports & {23, 80, 443, 445, 3389}:
            add("Review camera/NVR administrative services for default credentials, patching, and management-network restriction.")
        add("Confirm camera/NVR placement and expected monitoring role before suppressing future alerts.")

    if "database" in classification_text:
        if open_ports & {1433, 1521, 3306, 5432, 6379, 9200, 9300, 27017}:
            add("Validate database listener exposure, authentication requirements, TLS posture, and backup ownership.")
        add("Confirm whether the database should be reachable from this network scope.")

    if "web server" in classification_text or classification_text == "web":
        if open_ports & {80, 443, 8000, 8080, 8443, 8888}:
            add("Review the web interface for expected ownership, authentication, TLS, and whether it is a management portal.")
        if confidence < 40:
            add("Treat the web-server label as tentative until service banners or manual review confirm the asset role.")

    if not actions:
        add(f"Review {subject_key} using event history, service inventory, and asset annotations before changing alert status.")

    return actions[:5]


def build_risk_register(connection, limit, subject_filter=None, scope=None):
    subjects = {}

    def ensure(subject_key):
        subject_key = str(subject_key or "").strip()

        if not subject_key:
            return None

        if subject_filter and subject_filter not in subject_key:
            return None

        if subject_key not in subjects:
            subjects[subject_key] = risk_subject_record(subject_key)

        return subjects[subject_key]

    event_scope_clause = ""
    event_params = []

    if scope:
        event_scope_clause = "JOIN snapshots s ON s.scan_id = e.scan_id WHERE s.network_scope = ?"
        event_params.append(scope)

    event_rows = connection.execute(
        f"""
        SELECT
            e.subject_key,
            e.severity,
            e.event_type,
            e.created_at,
            e.summary
        FROM delta_events e
        {event_scope_clause}
        ORDER BY e.event_id DESC
        LIMIT 500
        """,
        tuple(event_params),
    ).fetchall()

    for row in event_rows:
        record = ensure(row["subject_key"])

        if record is None:
            continue

        severity = str(row["severity"] or "INFO").upper()
        event_type = str(row["event_type"] or "UNKNOWN")

        record["event_count"] += 1
        set_max_severity(record, severity)

        if record["latest_event_at"] is None:
            record["latest_event_at"] = row["created_at"]

        risk_add_reason(
            record["reasons"],
            f"{severity} event observed: {event_type}",
        )

    alert_scope_clause = ""
    alert_params = []

    if scope:
        alert_scope_clause = """
        LEFT JOIN delta_events e ON e.event_id = a.last_event_id
        LEFT JOIN snapshots s ON s.scan_id = e.scan_id
        WHERE s.network_scope = ?
        """
        alert_params.append(scope)

    alert_rows = connection.execute(
        f"""
        SELECT
            a.alert_id,
            a.status,
            a.severity,
            a.event_type,
            a.subject_key,
            a.summary,
            a.last_seen_at
        FROM alerts a
        {alert_scope_clause}
        ORDER BY a.alert_id DESC
        LIMIT 500
        """,
        tuple(alert_params),
    ).fetchall()

    for row in alert_rows:
        record = ensure(row["subject_key"])

        if record is None:
            continue

        status = str(row["status"] or "OPEN").upper()
        severity = str(row["severity"] or "INFO").upper()

        if status == "OPEN":
            record["open_alerts"] += 1
            risk_add_reason(
                record["reasons"],
                f"Open {severity} alert present",
            )
        elif status == "ACKNOWLEDGED":
            record["acknowledged_alerts"] += 1
            risk_add_reason(
                record["reasons"],
                f"Acknowledged {severity} alert has review history",
            )
        elif status == "SUPPRESSED":
            record["suppressed_alerts"] += 1
            risk_add_reason(
                record["reasons"],
                f"Suppressed {severity} alert exists",
            )
        elif status == "RESOLVED":
            record["resolved_alerts"] += 1

        if record["latest_alert_at"] is None:
            record["latest_alert_at"] = row["last_seen_at"]

    for subject_key, record in subjects.items():
        apply_identity_to_risk_record(connection, subject_key, record, scope=scope)
        apply_classification_to_risk_record(connection, subject_key, record, scope=scope)

        score = 0

        max_severity = record["max_event_severity"]
        severity_points = RISK_SEVERITY_POINTS.get(max_severity, 0)

        if severity_points:
            score += severity_points
            risk_add_reason(
                record["reasons"],
                f"Highest event severity {max_severity}: +{severity_points}",
            )

        if record["open_alerts"]:
            points = min(50, record["open_alerts"] * 25)
            score += points
            risk_add_reason(
                record["reasons"],
                f"{record['open_alerts']} open alert(s): +{points}",
            )

        if record["acknowledged_alerts"]:
            points = min(15, record["acknowledged_alerts"] * 5)
            score += points
            risk_add_reason(
                record["reasons"],
                f"{record['acknowledged_alerts']} acknowledged alert(s): +{points}",
            )

        if record["event_count"] >= 5:
            score += 10
            risk_add_reason(record["reasons"], "Repeated recent activity: +10")
        elif record["event_count"] >= 2:
            score += 5
            risk_add_reason(record["reasons"], "Multiple recent events: +5")

        annotation_match = fetch_risk_annotation(connection, subject_key)

        if annotation_match is not None:
            annotation, matched_key = annotation_match

            record["annotation_key"] = matched_key
            record["owner"] = annotation["owner"]
            record["role"] = annotation["role"]
            record["criticality"] = annotation["criticality"]
            record["notes"] = annotation["notes"]

            criticality = str(annotation["criticality"] or "").upper()
            criticality_points = RISK_CRITICALITY_POINTS.get(criticality, 0)

            if criticality_points:
                score += criticality_points
                risk_add_reason(
                    record["reasons"],
                    f"Asset criticality {criticality}: +{criticality_points}",
                )

            if not annotation["owner"]:
                score += 5
                risk_add_reason(record["reasons"], "Annotated asset has no owner: +5")
        else:
            score += 5
            risk_add_reason(record["reasons"], "No asset annotation recorded: +5")

        classification_points = int(record.get("classification_risk_points") or 0)

        if classification_points:
            score += classification_points
            for reason in record.get("classification_risk_reasons", []):
                risk_add_reason(record["reasons"], reason)

        record["score"] = min(100, score)
        record["level"] = risk_level(record["score"])
        record["recommended_actions"] = risk_role_recommended_actions(record)

    rows = sorted(
        subjects.values(),
        key=lambda row: (
            row["score"],
            row["open_alerts"],
            row["event_count"],
            row["subject_key"],
        ),
        reverse=True,
    )

    if limit is not None:
        rows = rows[:limit]

    return rows


def print_risk_record(record, detailed=False):
    print(f"{record['level']:<8} {record['score']:>3}  {record['subject_key']}")
    print(f"  IP address:  {record.get('ip_address') or 'unknown'}")
    print(f"  MAC address: {record.get('mac_address') or 'unknown'}")
    print(f"  Owner:       {record['owner'] or '-'}")
    print(f"  Role:        {record['role'] or '-'}")
    print(f"  Criticality: {record['criticality'] or '-'}")
    print(f"  Open alerts: {record['open_alerts']}")
    print(f"  Events:      {record['event_count']}")
    print(f"  Latest event:{' ' if record['latest_event_at'] else ''}{record['latest_event_at'] or '-'}")

    if record["annotation_key"]:
        print(f"  Annotation:  {record['annotation_key']}")

    if record["notes"]:
        print(f"  Notes:       {record['notes']}")

    if detailed:
        print("  Reasons:")

        for reason in record["reasons"]:
            print(f"    - {reason}")

    else:
        if record["reasons"]:
            print(f"  Reason:      {record['reasons'][0]}")

    print()


def command_risk(args):
    connection = connect(args.db)
    scope = optional_network_scope(getattr(args, "scope", None))

    rows = build_risk_register(
        connection,
        args.limit,
        subject_filter=args.subject,
        scope=scope,
    )

    print("DeltaAegis Risk Register")
    print("========================")

    if scope:
        print(f"Network scope: {scope}")

    print()

    if not rows:
        if scope:
            print(f"No risk subjects were found in scope {scope}.")
        else:
            print("No risk subjects were found.")
        return 0

    for record in rows:
        print_risk_record(record, detailed=args.details)

    return 0

def command_asset_risk(args):
    connection = connect(args.db)
    scope = optional_network_scope(getattr(args, "scope", None))

    rows = build_risk_register(
        connection,
        None,
        subject_filter=args.subject_key,
        scope=scope,
    )

    exact = [
        row for row in rows
        if row["subject_key"] == args.subject_key
    ]

    if exact:
        rows = exact

    print(f"Asset Risk: {args.subject_key}")

    if scope:
        print(f"Network scope: {scope}")

    print("=" * (12 + len(args.subject_key)))
    print()

    if not rows:
        print("No risk data matched this subject key.")
        return 1

    for record in rows:
        print_risk_record(record, detailed=True)

    return 0

def report_snapshot_count(connection, scope=None, accepted_only=False):
    sql = "SELECT COUNT(*) FROM snapshots WHERE 1 = 1"
    params = []

    if accepted_only:
        sql += " AND quality_status = 'ACCEPTED'"

    if scope:
        sql += " AND network_scope = ?"
        params.append(scope)

    return connection.execute(sql, tuple(params)).fetchone()[0]


def report_latest_snapshot(connection, scope=None):
    if scope:
        return connection.execute(
            """
            SELECT *
            FROM snapshots
            WHERE quality_status = 'ACCEPTED'
              AND network_scope = ?
            ORDER BY created_at DESC, imported_at DESC
            LIMIT 1
            """,
            (scope,),
        ).fetchone()

    return fetch_latest_accepted_snapshot(connection)


def report_open_alert_rows(connection, limit, scope=None):
    sql = """
        SELECT DISTINCT
            a.alert_id,
            a.severity,
            a.event_type,
            a.subject_key,
            a.summary,
            a.opened_at
        FROM alerts a
        LEFT JOIN delta_events e ON e.event_id = a.last_event_id
        LEFT JOIN snapshots s ON s.scan_id = e.scan_id
        WHERE a.status = 'OPEN'
    """

    params = []

    if scope:
        sql += " AND s.network_scope = ?"
        params.append(scope)

    sql += " ORDER BY a.alert_id DESC LIMIT ?"
    params.append(limit)

    return connection.execute(sql, tuple(params)).fetchall()


def report_asset_lifecycle_summary(connection, scope=None):
    sql = """
        SELECT
            state,
            identity_class,
            COUNT(*) AS asset_count
        FROM asset_lifecycle
        WHERE 1 = 1
    """
    params = []

    if scope:
        sql += " AND network_scope = ?"
        params.append(scope)

    sql += """
        GROUP BY state, identity_class
        ORDER BY state ASC, identity_class ASC
    """

    return connection.execute(sql, tuple(params)).fetchall()


def report_asset_inventory_rows(connection, limit, scope=None):
    sql = """
        SELECT
            al.network_scope,
            al.asset_key,
            al.identity_class,
            al.state,
            al.current_ip,
            al.mac_address,
            al.hostname,
            al.first_seen_at,
            al.last_seen_at,
            ao.device_type,
            ao.device_type_confidence,
            ao.classification_type,
            ao.classification_primary_type,
            ao.classification_confidence,
            ao.classification_confidence_label,
            ao.classification_decision,
            ao.classification_method,
            ao.classification_evidence_json,
            ao.classification_contradictions_json,
            ao.classification_candidates_json
        FROM asset_lifecycle al
        LEFT JOIN asset_observations ao
          ON ao.scan_id = al.last_seen_scan_id
         AND ao.asset_key = al.asset_key
        WHERE 1 = 1
    """
    params = []

    if scope:
        sql += " AND al.network_scope = ?"
        params.append(scope)

    sql += """
        ORDER BY al.network_scope ASC, al.state ASC, al.current_ip ASC, al.asset_key ASC
        LIMIT ?
    """
    params.append(limit)

    rows = connection.execute(sql, tuple(params)).fetchall()
    return dashboard_enrich_classification_rows(rows)

def append_report_network_scope_summary(lines, connection, scope=None):
    lines.append("## Network Scope Summary")
    lines.append("")

    rows = connection.execute(
        """
        SELECT
            network_scope,
            COUNT(*) AS snapshots,
            SUM(CASE WHEN quality_status = 'ACCEPTED' THEN 1 ELSE 0 END) AS accepted_snapshots,
            MAX(created_at) AS latest_scan_at
        FROM snapshots
        WHERE (? IS NULL OR network_scope = ?)
        GROUP BY network_scope
        ORDER BY network_scope ASC
        """,
        (scope, scope),
    ).fetchall()

    if not rows:
        lines.append("No network scope data matched this report.")
        lines.append("")
        return

    lines.append("| Network Scope | Snapshots | Accepted | Latest Scan |")
    lines.append("|---|---:|---:|---|")

    for row in rows:
        lines.append(
            "| "
            f"`{safe_markdown(row['network_scope'])}` | "
            f"{row['snapshots']} | "
            f"{row['accepted_snapshots'] or 0} | "
            f"`{safe_markdown(row['latest_scan_at'] or '-')}` |"
        )

    lines.append("")
    lines.append("Network scope isolation prevents baselines, lifecycle state, and reports from mixing unrelated subnets.")
    lines.append("")


def append_report_dashboard_usage_section(lines, scope=None):
    lines.append("## Dashboard and API Usage Notes")
    lines.append("")

    if scope:
        lines.append(f"- Dashboard scope view: `deltaaegis dashboard --scope {safe_markdown(scope)}`")
        lines.append(f"- Asset inventory API: `/api/assets?scope={safe_markdown(scope)}&limit=25`")
        lines.append(f"- Asset detail API: `/api/asset?scope={safe_markdown(scope)}&identifier=<asset-or-ip>`")
    else:
        lines.append("- Dashboard: `deltaaegis dashboard`")
        lines.append("- Asset inventory API: `/api/assets?limit=25`")
        lines.append("- Asset detail API: `/api/asset?identifier=<asset-or-ip>`")

    lines.append("- The dashboard remains read-only and is intended for local or trusted-access investigation.")
    lines.append("- Port behavior API: `/api/port-behavior?limit=25&lookback=5`")
    lines.append("- Investigation Center API: `/api/investigation-center?limit=25`")
    lines.append("- Investigation Center workflow filter API: `/api/investigation-center?limit=25&ticket_status=OPEN`")
    lines.append("- Investigation Center signal filter API: `/api/investigation-center?limit=25&ticket_signal=ACTIONABLE`")
    lines.append("- Combined ticket filters are supported with `ticket_status` and `ticket_signal` query parameters.")
    lines.append("- Use the Asset Inventory table, asset selector, or clickable risk/event/alert subjects to open Asset Detail.")
    lines.append("")


def append_report_recommended_next_actions(lines, risk_rows, open_alerts, asset_rows):
    lines.append("## Recommended Next Actions")
    lines.append("")

    if open_alerts:
        lines.append(f"- Review and triage **{len(open_alerts)}** open alert(s), starting with the highest-severity subjects.")
    else:
        lines.append("- No open alerts were included in this report.")

    if risk_rows:
        top = risk_rows[0]
        lines.append(
            "- Investigate the highest-risk subject first: "
            f"`{safe_markdown(top.get('subject_key'))}` "
            f"with score **{safe_markdown(top.get('score'))}**."
        )
    else:
        lines.append("- No risk subjects were calculated for this report.")

    if asset_rows:
        lines.append("- Use the asset inventory section to identify unknown hosts, missing identity context, and unannotated important devices.")
    else:
        lines.append("- No asset inventory rows were included; verify accepted snapshots and lifecycle data exist for this scope.")

    lines.append("- Add asset annotations for known infrastructure, owners, roles, and criticality to improve future risk prioritization.")
    lines.append("")

def append_report_asset_lifecycle_section(lines, lifecycle_rows):
    lines.append("## Asset Lifecycle Summary")
    lines.append("")

    if not lifecycle_rows:
        lines.append("No asset lifecycle rows matched this report.")
        lines.append("")
        return

    lines.append("| State | Identity Class | Assets |")
    lines.append("|---|---|---:|")

    for row in lifecycle_rows:
        lines.append(
            "| "
            f"{safe_markdown(row['state'])} | "
            f"{safe_markdown(row['identity_class'])} | "
            f"{row['asset_count']} |"
        )

    lines.append("")
    lines.append(
        "Lifecycle state tracks whether assets are active, missing, removed, "
        "or temporarily absent across accepted scans."
    )
    lines.append("")


def append_report_classification_summary_section(lines, classification_summary):
    lines.append("## NetSniper Intelligence Summary")
    lines.append("")

    if not classification_summary:
        lines.append("No NetSniper classification summary was available for this report.")
        lines.append("")
        return

    lines.append(
        "This section summarizes NetSniper's evidence-based device classification "
        "for the selected network scope."
    )
    lines.append("")

    summary_rows = [
        ("Total assets", classification_summary.get("total_assets", 0)),
        ("Classified assets", classification_summary.get("classified_assets", 0)),
        ("Possible / weak classifications", classification_summary.get("possible_assets", 0)),
        ("Unknown assets", classification_summary.get("unknown_assets", 0)),
        ("Evidence-backed assets", classification_summary.get("evidence_backed_assets", 0)),
        ("Classification contradictions", classification_summary.get("contradiction_assets", 0)),
        ("High-confidence assets", classification_summary.get("high_confidence_assets", 0)),
        ("Classified percentage", f"{classification_summary.get('classified_percent', 0)}%"),
    ]

    lines.append("| Metric | Value |")
    lines.append("|---|---:|")

    for label, value in summary_rows:
        lines.append(f"| {safe_markdown(label)} | {safe_markdown(value)} |")

    lines.append("")

    top_classifications = classification_summary.get("top_classifications") or []

    lines.append("### Top Classifications")
    lines.append("")

    if not top_classifications:
        lines.append("No classified device categories were available.")
        lines.append("")
    else:
        lines.append("| Classification | Assets |")
        lines.append("|---|---:|")

        for row in top_classifications:
            lines.append(
                "| "
                f"{safe_markdown(row.get('classification'))} | "
                f"{safe_markdown(row.get('count'))} |"
            )

        lines.append("")

    review_queue = classification_summary.get("review_queue") or []

    lines.append("### Classification Review Queue")
    lines.append("")

    if not review_queue:
        lines.append("No weak, unknown, or contradictory classifications require review.")
        lines.append("")
    else:
        lines.append("| Priority Reason | Asset | IP Address | Classification | Decision | Confidence | Evidence | Contradictions |")
        lines.append("|---|---|---|---|---|---:|---:|---:|")

        for row in review_queue:
            lines.append(
                "| "
                f"{safe_markdown(row.get('reason'))} | "
                f"`{safe_markdown(row.get('asset_key'))}` | "
                f"`{safe_markdown(row.get('ip_address'))}` | "
                f"{safe_markdown(row.get('classification'))} | "
                f"{safe_markdown(row.get('decision'))} | "
                f"{safe_markdown(row.get('confidence'))} | "
                f"{safe_markdown(row.get('evidence_count'))} | "
                f"{safe_markdown(row.get('contradiction_count'))} |"
            )

        lines.append("")

    lines.append(
        "Use weak, unknown, or contradictory classifications as review targets. "
        "They usually require vendor confirmation, service validation, or asset annotation."
    )
    lines.append("")

def append_report_asset_inventory_section(lines, asset_rows, limit):
    lines.append("## Asset Inventory")
    lines.append("")

    if not asset_rows:
        lines.append("No assets matched this report.")
        lines.append("")
        return

    lines.append(f"Showing up to **{limit}** assets.")
    lines.append("")
    lines.append("| Scope | State | Identity | IP Address | MAC Address | Hostname | Classification | Decision | Confidence | Evidence | Contradictions | Asset Key | Last Seen |")
    lines.append("|---|---|---|---|---|---|---|---|---:|---:|---:|---|---|")

    for row in asset_rows:
        classification = row.get("classification_display_type") or row.get("device_type") or "Unknown"
        decision = row.get("classification_display_decision") or "unknown"
        confidence = row.get("classification_display_confidence")
        evidence_count = row.get("classification_evidence_count", 0)
        contradiction_count = row.get("classification_contradiction_count", 0)

        lines.append(
            "| "
            f"`{safe_markdown(row['network_scope'])}` | "
            f"{safe_markdown(row['state'])} | "
            f"{safe_markdown(row['identity_class'])} | "
            f"`{safe_markdown(row['current_ip'])}` | "
            f"`{safe_markdown(row['mac_address'] or '-')}` | "
            f"{safe_markdown(row['hostname'] or '-')} | "
            f"{safe_markdown(classification)} | "
            f"{safe_markdown(decision)} | "
            f"{safe_markdown(confidence)} | "
            f"{safe_markdown(evidence_count)} | "
            f"{safe_markdown(contradiction_count)} | "
            f"`{safe_markdown(row['asset_key'])}` | "
            f"`{safe_markdown(row['last_seen_at'])}` |"
        )

    lines.append("")

def append_report_role_aware_recommendations_section(lines, risk_rows):
    lines.append("## Role-Aware Recommended Actions")
    lines.append("")

    rows = [
        record for record in risk_rows
        if record.get("recommended_actions")
    ]

    if not rows:
        lines.append("No role-aware recommended actions were generated for this report.")
        lines.append("")
        return

    lines.append(
        "These actions use NetSniper classification context to make follow-up guidance "
        "more specific to the suspected asset role."
    )
    lines.append("")

    for record in rows[:10]:
        lines.append(
            f"### `{safe_markdown(record.get('subject_key'))}` "
            f"— {safe_markdown(record.get('classification') or 'Unknown')} "
            f"({safe_markdown(record.get('classification_decision') or 'unknown')}, "
            f"confidence {safe_markdown(record.get('classification_confidence') or 0)})"
        )
        lines.append("")
        lines.append(
            f"- Risk level: **{safe_markdown(record.get('level'))}** "
            f"with score **{safe_markdown(record.get('score'))}**."
        )

        points = int(record.get("classification_risk_points") or 0)

        if points:
            lines.append(f"- Classification-aware risk contribution: **+{points}**.")

        for action in record.get("recommended_actions") or []:
            lines.append(f"- Recommended action: {safe_markdown(action)}")

        lines.append("")



def append_report_investigation_center_section(lines, investigation_rows):
    lines.append("## Investigation Command Center")
    lines.append("")
    lines.append(
        "This section summarizes the highest-priority investigation queue from the "
        "same Command Center logic used by the dashboard and `investigation-center` CLI."
    )
    lines.append("")
    lines.append(
        "Queue priority combines current risk, open alerts, recent delta events, "
        "MAC-port behavior, identity context, classification context, recommended actions, "
        "and v0.22 operator triage state."
    )
    lines.append("")

    rows = list(investigation_rows or [])
    workflow_summary = investigation_center_workflow_summary(rows)
    signal_summary = investigation_center_signal_summary(rows)
    triage_summary = operator_triage_summary(rows)

    lines.append("### Investigation Queue Operator Summary")
    lines.append("")
    lines.append(
        "- Workflow states: "
        f"OPEN={workflow_summary.get('open', 0)}, "
        f"IN_REVIEW={workflow_summary.get('in_review', 0)}, "
        f"RESOLVED={workflow_summary.get('resolved', 0)}, "
        f"SUPPRESSED={workflow_summary.get('suppressed', 0)}"
    )
    lines.append(
        "- Signal labels: "
        f"ACTIONABLE={signal_summary.get('actionable', 0)}, "
        f"MEANINGFUL_CHANGE={signal_summary.get('meaningful_change', 0)}, "
        f"BASELINE_CONTEXT={signal_summary.get('baseline_context', 0)}"
    )
    lines.append(
        "- Operator triage buckets: "
        f"NEEDS_REVIEW={triage_summary.get('needs_review', 0)}, "
        f"CHANGED_SINCE_REVIEW={triage_summary.get('changed_since_review', 0)}, "
        f"NEEDS_CONTEXT={triage_summary.get('needs_context', 0)}, "
        f"STALE_CLOSED={triage_summary.get('stale_closed', 0)}, "
        f"BASELINE_CONTEXT={triage_summary.get('baseline_context', 0)}, "
        f"MONITOR={triage_summary.get('monitor', 0)}"
    )
    lines.append(
        "- Operator triage urgency: "
        f"IMMEDIATE={triage_summary.get('immediate', 0)}, "
        f"HIGH={triage_summary.get('high', 0)}, "
        f"NORMAL={triage_summary.get('normal', 0)}, "
        f"LOW={triage_summary.get('low', 0)}"
    )
    lines.append(
        "- Missing context flags: "
        f"owner={triage_summary.get('missing_owner', 0)}, "
        f"role_or_criticality={triage_summary.get('missing_context', 0)}"
    )
    lines.append("")

    if not rows:
        lines.append("No Investigation Command Center queue items matched this report scope.")
        lines.append("")
        return

    lines.append(
        "| Priority | Score | Workflow | Signal | Subject | Triage | Triage Score | "
        "IP Address | MAC Address | Device / Role | Triggers | Why Review? | "
        "Recommended Action | Counts |"
    )
    lines.append("|---|---:|---|---|---|---|---:|---|---|---|---|---|---|---|")

    for row in rows:
        role = row.get("role") or row.get("classification") or row.get("device_type") or "Unknown"
        device = row.get("device_type") or "Unknown"

        if device != role:
            device_role = f"{device} / {role}"
        else:
            device_role = role

        triggers = ", ".join(row.get("triggers") or []) or "-"
        workflow = str(row.get("ticket_status") or "OPEN").upper()
        signal = str(row.get("ticket_signal_state") or "ACTIONABLE").upper()
        triage_bucket = str(row.get("triage_bucket") or "MONITOR").upper()
        triage_label = str(row.get("triage_urgency_label") or "LOW").upper()
        triage_score = int(row.get("triage_urgency_score") or 0)
        triage_display = f"{triage_bucket} / {triage_label}"
        counts = (
            f"alerts={int(row.get('open_alerts') or 0)}, "
            f"events={int(row.get('recent_events') or 0)}, "
            f"ports={int(row.get('port_behavior_count') or 0)}, "
            f"findings={int(row.get('current_finding_count') or 0)}"
        )

        lines.append(
            "| "
            f"{safe_markdown(row.get('priority_level') or 'INFO')} | "
            f"{safe_markdown(row.get('priority_score') or 0)} | "
            f"{safe_markdown(workflow)} | "
            f"{safe_markdown(signal)} | "
            f"`{safe_markdown(row.get('subject_key'))}` | "
            f"{safe_markdown(triage_display)} | "
            f"{safe_markdown(triage_score)} | "
            f"`{safe_markdown(row.get('ip_address') or '-')}` | "
            f"`{safe_markdown(row.get('mac_address') or '-')}` | "
            f"{safe_markdown(device_role)} | "
            f"{safe_markdown(triggers)} | "
            f"{safe_markdown(row.get('primary_reason') or '-')} | "
            f"{safe_markdown(row.get('recommended_action') or '-')} | "
            f"`{safe_markdown(counts)}` |"
        )

    lines.append("")
    lines.append(
        "Use this queue as the starting point for review. The detailed Risk, "
        "MAC-Port Behavior, Active Alerts, Delta Events, Ticket Evidence, and Asset "
        "Inventory sections provide supporting evidence for each item."
    )
    lines.append("")

def append_report_risk_section(lines, risk_rows):
    lines.append("## Top Risk Subjects")
    lines.append("")

    if not risk_rows:
        lines.append("No risk subjects were calculated for this report.")
        lines.append("")
        return

    lines.append("| Level | Score | Subject | IP Address | MAC Address | Owner | Role | Criticality | Open Alerts | Events | Primary Reason |")
    lines.append("|---|---:|---|---|---|---|---|---|---:|---:|---|")

    for record in risk_rows:
        reasons = record.get("reasons") or []
        primary_reason = reasons[0] if reasons else "-"

        lines.append(
            "| "
            f"{safe_markdown(record['level'])} | "
            f"{record['score']} | "
            f"`{safe_markdown(record['subject_key'])}` | "
            f"`{safe_markdown(record.get('ip_address') or 'unknown')}` | "
            f"`{safe_markdown(record.get('mac_address') or 'unknown')}` | "
            f"{safe_markdown(record.get('owner') or '-')} | "
            f"{safe_markdown(record.get('role') or '-')} | "
            f"{safe_markdown(record.get('criticality') or '-')} | "
            f"{record.get('open_alerts', 0)} | "
            f"{record.get('event_count', 0)} | "
            f"{safe_markdown(primary_reason)} |"
        )

    lines.append("")
    lines.append("Risk scores are explainable and are calculated from recent delta events, alert state, repeated activity, asset criticality, missing asset context, and classification-aware role context.")
    lines.append("")


def append_report_port_behavior_section(lines, port_behavior_rows):
    lines.append("## MAC-Port Behavior Changes")
    lines.append("")
    lines.append(
        "This section correlates stable MAC-backed device identity with open-port "
        "history across accepted scans. It highlights ports that appeared "
        "unexpectedly, disappeared, or repeatedly changed open/not-observed state."
    )
    lines.append("")
    lines.append(
        "Normal infrastructure ports can fluctuate because of scan timing, device sleep "
        "states, or printer/web management behavior. Treat volatile printer ports such "
        "as `tcp/631` and `tcp/9100` as review context unless combined with unusual "
        "remote-access or file-sharing services."
    )
    lines.append("")

    rows = list(port_behavior_rows or [])

    if not rows:
        lines.append("No MAC-port behavior changes were detected for this report scope.")
        lines.append("")
        return

    lines.append("| Severity | Behavior | MAC Identity | IP Address | Device | Port | Current State | Seen | Missing | Transitions | Reason |")
    lines.append("|---|---|---|---|---|---|---|---:|---:|---:|---|")

    for row in rows:
        lines.append(
            "| "
            f"{safe_markdown(row.get('severity'))} | "
            f"{safe_markdown(row.get('behavior'))} | "
            f"`{safe_markdown(row.get('mac_identity'))}` | "
            f"`{safe_markdown(row.get('ip_address'))}` | "
            f"{safe_markdown(row.get('device_type') or 'Unknown')} | "
            f"`{safe_markdown(row.get('port_key'))}` | "
            f"{safe_markdown(row.get('current_state'))} | "
            f"{safe_markdown(row.get('seen_count'))} | "
            f"{safe_markdown(row.get('missing_count'))} | "
            f"{safe_markdown(row.get('transition_count'))} | "
            f"{safe_markdown(row.get('reason'))} |"
        )

    lines.append("")
    lines.append(
        "High-signal unexpected ports, such as Telnet, SMB, RDP, exposed databases, "
        "or container-management services, should be validated before treating the "
        "device as normal."
    )
    lines.append("")


def report_ticket_evidence_rows(
    connection,
    investigation_rows,
    scope=None,
    limit=5,
    evidence_limit=5,
):
    evidence_rows = []

    for row in list(investigation_rows or [])[:limit]:
        subject_key = row.get("subject_key")

        if not subject_key:
            continue

        payload = dashboard_ticket_evidence_payload(
            connection,
            subject_key=subject_key,
            scope=scope,
            limit=evidence_limit,
        )

        if payload.get("available", False):
            evidence_rows.append(payload)

    return evidence_rows


def append_report_ticket_evidence_appendix(lines, evidence_payloads):
    lines.append("## Ticket Evidence Appendix")
    lines.append("")
    lines.append(
        "This appendix preserves the operator-facing evidence package behind top "
        "Investigation Command Center tickets. Each entry ties workflow state, "
        "risk reasoning, recent delta events, MAC-port behavior, and ticket history "
        "back to the same subject key used by the dashboard and CLI."
    )
    lines.append("")

    payloads = list(evidence_payloads or [])

    if not payloads:
        lines.append("No ticket evidence payloads were available for this report scope.")
        lines.append("")
        return

    for index, payload in enumerate(payloads, start=1):
        summary = payload.get("summary") or {}
        ticket_state = payload.get("ticket_state") or {}
        subject_key = payload.get("subject_key") or summary.get("subject_key") or "-"

        lines.append(f"### Ticket Evidence {index}: `{safe_markdown(subject_key)}`")
        lines.append("")
        lines.append(f"- Workflow: **{safe_markdown(summary.get('ticket_status') or ticket_state.get('ticket_status') or 'OPEN')}**")
        lines.append(f"- Signal: **{safe_markdown(summary.get('ticket_signal') or 'ACTIONABLE')}**")
        lines.append(
            f"- Priority: **{safe_markdown(summary.get('priority_level') or 'INFO')}** "
            f"({safe_markdown(summary.get('priority_score') or 0)})"
        )
        lines.append(f"- Primary reason: {safe_markdown(summary.get('primary_reason') or '-')}")
        lines.append(f"- Why now: {safe_markdown(summary.get('why_now') or '-')}")
        lines.append(f"- Recommended action: {safe_markdown(summary.get('recommended_action') or '-')}")
        lines.append(
            "- Evidence counts: "
            f"risk `{safe_markdown(summary.get('risk_count') or 0)}`, "
            f"alerts `{safe_markdown(summary.get('alert_count') or 0)}`, "
            f"events `{safe_markdown(summary.get('event_count') or 0)}`, "
            f"ports `{safe_markdown(summary.get('port_behavior_count') or 0)}`, "
            f"history `{safe_markdown(summary.get('ticket_history_count') or 0)}`, "
            f"timeline `{safe_markdown(summary.get('timeline_count') or 0)}`"
        )
        lines.append("")

        timeline = list(payload.get("timeline") or [])[:8]
        lines.append("#### Evidence Timeline Sample")
        lines.append("")

        if not timeline:
            lines.append("No timeline evidence was available for this ticket.")
            lines.append("")
        else:
            lines.append("| Time | Category | Severity | Source | Summary |")
            lines.append("|---|---|---|---|---|")
            for item in timeline:
                lines.append(
                    "| "
                    f"{safe_markdown(item.get('timestamp') or '-')} | "
                    f"{safe_markdown(item.get('category') or '-')} | "
                    f"{safe_markdown(item.get('severity') or '-')} | "
                    f"{safe_markdown(item.get('source') or '-')} | "
                    f"{safe_markdown(item.get('summary') or '-')} |"
                )
            lines.append("")

        risk_rows = list(payload.get("risk") or [])[:3]
        lines.append("#### Current Risk Evidence")
        lines.append("")

        if not risk_rows:
            lines.append("No current risk rows were attached to this ticket evidence package.")
            lines.append("")
        else:
            lines.append("| Level | Score | Subject | Primary Reason |")
            lines.append("|---|---:|---|---|")
            for risk in risk_rows:
                reasons = risk.get("reasons") or []
                primary_reason = risk.get("primary_reason") or (reasons[0] if reasons else "-")
                lines.append(
                    "| "
                    f"{safe_markdown(risk.get('level') or '-')} | "
                    f"{safe_markdown(risk.get('score') or 0)} | "
                    f"`{safe_markdown(risk.get('subject_key') or subject_key)}` | "
                    f"{safe_markdown(primary_reason)} |"
                )
            lines.append("")

        event_rows = list(payload.get("events") or [])[:5]
        lines.append("#### Delta Events")
        lines.append("")

        if not event_rows:
            lines.append("No delta events were attached to this ticket evidence package.")
            lines.append("")
        else:
            lines.append("| Event | Time | Severity | Type | Summary |")
            lines.append("|---:|---|---|---|---|")
            for event in event_rows:
                lines.append(
                    "| "
                    f"{safe_markdown(event.get('event_id') or event.get('id') or '-')} | "
                    f"{safe_markdown(event.get('created_at') or '-')} | "
                    f"{safe_markdown(event.get('severity') or '-')} | "
                    f"{safe_markdown(event.get('event_type') or event.get('type') or '-')} | "
                    f"{safe_markdown(event.get('summary') or '-')} |"
                )
            lines.append("")

        port_rows = list(payload.get("port_behavior") or [])[:5]
        lines.append("#### MAC-Port Behavior")
        lines.append("")

        if not port_rows:
            lines.append("No MAC-port behavior rows were attached to this ticket evidence package.")
            lines.append("")
        else:
            lines.append("| Severity | Behavior | Port | Reason |")
            lines.append("|---|---|---|---|")
            for port in port_rows:
                port_label = port.get("port_key")
                if not port_label:
                    proto = port.get("protocol") or "tcp"
                    port_number = port.get("port") or "-"
                    port_label = f"{proto}/{port_number}"

                lines.append(
                    "| "
                    f"{safe_markdown(port.get('severity') or '-')} | "
                    f"{safe_markdown(port.get('behavior') or '-')} | "
                    f"`{safe_markdown(port_label)}` | "
                    f"{safe_markdown(port.get('reason') or '-')} |"
                )
            lines.append("")

        history_rows = list(payload.get("ticket_history") or [])[:5]
        lines.append("#### Ticket History")
        lines.append("")

        if not history_rows:
            lines.append("No ticket workflow history was attached to this evidence package.")
            lines.append("")
        else:
            lines.append("| Time | Previous | New | Analyst | Note |")
            lines.append("|---|---|---|---|---|")
            for history in history_rows:
                lines.append(
                    "| "
                    f"{safe_markdown(history.get('created_at') or '-')} | "
                    f"{safe_markdown(history.get('previous_status') or '-')} | "
                    f"{safe_markdown(history.get('new_status') or '-')} | "
                    f"{safe_markdown(history.get('analyst') or '-')} | "
                    f"{safe_markdown(history.get('note') or '-')} |"
                )
            lines.append("")

def command_report(args):
    from collections import Counter
    from datetime import datetime, timezone

    connection = connect(args.db)
    scope = optional_network_scope(getattr(args, "scope", None))

    reports_dir = args.reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)

    events = report_event_rows(
        connection=connection,
        latest_only=args.latest,
        since=args.since,
        severity=args.severity,
        limit=args.limit,
        scope=scope,
    )

    latest_snapshot = report_latest_snapshot(connection, scope=scope)

    snapshot_count = report_snapshot_count(connection, scope=scope)

    accepted_count = report_snapshot_count(
        connection,
        scope=scope,
        accepted_only=True,
    )

    open_alerts = report_open_alert_rows(
        connection,
        limit=25,
        scope=scope,
    )

    report_subjects = [row["subject_key"] for row in events]
    report_subjects.extend(alert["subject_key"] for alert in open_alerts)
    asset_context = collect_report_asset_context(connection, report_subjects)

    report_alert_notes = collect_report_alert_notes(
        connection,
        [alert["alert_id"] for alert in open_alerts],
    )
    report_review_rows = report_alert_review_rows(
        connection,
        report_subjects,
        args.limit,
    )

    report_risk_rows = build_risk_register(
        connection,
        args.risk_limit,
        scope=scope,
    )

    report_port_behavior_rows = mac_port_behavior_rows(
        connection,
        limit=25,
        scope=scope,
        lookback=5,
    )

    report_investigation_center_rows = tune_investigation_center_ticket_signals(
        investigation_center_rows(
            connection,
            limit=max(args.risk_limit * 4, 50),
            scope=scope,
        )
    )[:args.risk_limit]

    report_ticket_evidence_payloads = report_ticket_evidence_rows(
        connection,
        report_investigation_center_rows,
        scope=scope,
        limit=min(args.risk_limit, 5),
        evidence_limit=5,
    )

    report_lifecycle_rows = report_asset_lifecycle_summary(
        connection,
        scope=scope,
    )

    report_asset_rows = report_asset_inventory_rows(
        connection,
        limit=args.asset_limit,
        scope=scope,
    )

    report_classification_summary = dashboard_classification_summary_payload(
        connection,
        scope=scope,
    )

    event_type_counts = Counter(row["event_type"] for row in events)
    severity_counts = Counter(row["severity"] for row in events)

    report_time = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    output_path = args.output or reports_dir / f"deltaaegis-report-{report_time}.md"

    lines = []

    lines.append("# DeltaAegis Investigation Report")
    lines.append("")
    lines.append(f"Generated: `{generated_at}`")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")

    if latest_snapshot:
        lines.append(
            f"The latest accepted snapshot is `{latest_snapshot['scan_id']}` "
            f"for target `{latest_snapshot['target']}` with "
            f"`{latest_snapshot['hosts_up']}` observed hosts and "
            f"`{float(latest_snapshot['identity_coverage']):.0%}` MAC-backed identity coverage."
        )
    else:
        lines.append("No accepted snapshot has been imported yet.")

    lines.append("")
    lines.append(f"- Network scope: **`{scope or 'all scopes'}`**")
    lines.append(f"- Snapshots imported: **{snapshot_count}**")
    lines.append(f"- Accepted snapshots: **{accepted_count}**")
    lines.append(f"- Events included in this report: **{len(events)}**")
    lines.append(f"- Open alerts: **{len(open_alerts)}**")
    lines.append(f"- Assets included: **{len(report_asset_rows)}**")
    lines.append("")

    lines.append("## Report Scope")
    lines.append("")
    lines.append(f"- Network scope: `{scope or 'all scopes'}`")
    lines.append(f"- Latest snapshot only: `{args.latest}`")
    lines.append(f"- Since: `{args.since or 'not specified'}`")
    lines.append(f"- Severity filter: `{args.severity or 'not specified'}`")
    lines.append(f"- Event limit: `{args.limit}`")
    lines.append(f"- Risk limit: `{args.risk_limit}`")
    lines.append(f"- Asset inventory limit: `{args.asset_limit}`")
    lines.append("")

    append_report_network_scope_summary(lines, connection, scope=scope)
    append_report_asset_lifecycle_section(lines, report_lifecycle_rows)
    append_report_classification_summary_section(lines, report_classification_summary)
    append_report_asset_inventory_section(lines, report_asset_rows, args.asset_limit)
    append_report_investigation_center_section(lines, report_investigation_center_rows)
    append_report_ticket_evidence_appendix(lines, report_ticket_evidence_payloads)
    append_report_risk_section(lines, report_risk_rows)
    append_report_port_behavior_section(lines, report_port_behavior_rows)
    append_report_role_aware_recommendations_section(lines, report_risk_rows)

    lines.append("## Annotated Asset Context")
    lines.append("")

    if not asset_context:
        lines.append("No matching asset annotations were found for the events or open alerts in this report.")
        lines.append("")
    else:
        lines.append("| Subject | Matched Annotation | Owner | Role | Criticality | Notes |")
        lines.append("|---|---|---|---|---|---|")

        for subject in sorted(asset_context):
            annotation, matched_key = asset_context[subject]

            lines.append(
                "| "
                f"`{safe_markdown(subject)}` | "
                f"`{safe_markdown(matched_key)}` | "
                f"{safe_markdown(annotation['owner'] or '-')} | "
                f"{safe_markdown(annotation['role'] or '-')} | "
                f"{safe_markdown(annotation['criticality'] or '-')} | "
                f"{safe_markdown(annotation['notes'] or '-')} |"
            )

        lines.append("")

    lines.append("## Alert Review Notes")
    lines.append("")

    if not report_review_rows:
        lines.append("No alert review notes matched the events or open alerts in this report.")
        lines.append("")
    else:
        lines.append("| Alert | Status | Severity | Subject | Action | Reason | Recorded |")
        lines.append("|---|---|---|---|---|---|---|")

        for row in report_review_rows:
            lines.append(
                "| "
                f"`{row['alert_id']}` | "
                f"{safe_markdown(row['status'])} | "
                f"{safe_markdown(row['severity'])} | "
                f"`{safe_markdown(row['subject_key'])}` | "
                f"{safe_markdown(row['action'])} | "
                f"{safe_markdown(row['reason'])} | "
                f"`{safe_markdown(row['created_at'])}` |"
            )

        lines.append("")

    lines.append("## Event Breakdown")
    lines.append("")

    if event_type_counts:
        lines.append("### By Event Type")
        lines.append("")
        for event_type, count in event_type_counts.most_common():
            lines.append(f"- `{event_type}`: **{count}**")
        lines.append("")

    if severity_counts:
        lines.append("### By Severity")
        lines.append("")
        for severity_name, count in severity_counts.most_common():
            lines.append(f"- `{severity_name}`: **{count}**")
        lines.append("")

    lines.append("## Active Alerts")
    lines.append("")

    if not open_alerts:
        lines.append("No open alerts were found.")
        lines.append("")
    else:
        lines.append("| Alert ID | Severity | Type | Subject | Opened | Summary |")
        lines.append("|---:|---|---|---|---|---|")
        for alert in open_alerts:
            lines.append(
                "| "
                f"{alert['alert_id']} | "
                f"{safe_markdown(alert['severity'])} | "
                f"{safe_markdown(alert['event_type'])} | "
                f"`{safe_markdown(alert['subject_key'])}` | "
                f"{safe_markdown(alert['opened_at'])} | "
                f"{safe_markdown(alert['summary'])} |"
            )
        lines.append("")

    lines.append("## Delta Events")
    lines.append("")

    if not events:
        lines.append("No delta events matched the selected report scope.")
        lines.append("")
    else:
        for row in events:
            lines.append(f"### Event {row['event_id']}: `{row['event_type']}`")
            lines.append("")
            lines.append(f"- Severity: **{row['severity']}**")
            lines.append(f"- Subject: `{row['subject_key']}`")
            lines.append(f"- Snapshot: `{row['scan_id']}`")
            lines.append(f"- Baseline: `{row['baseline_scan_id'] or '-'}`")
            lines.append(f"- Created: `{row['created_at']}`")
            lines.append("")
            lines.append(str(row["summary"] or "No event summary was recorded."))
            lines.append("")
            annotation_match = asset_context.get(str(row["subject_key"]))

            if annotation_match is not None:
                annotation, matched_key = annotation_match
                append_report_asset_context(lines, annotation, matched_key)

            lines.append("**Why this matters:**")
            lines.append("")
            lines.append(severity_explanation(row["severity"]))
            lines.append("")
            lines.append("**Recommended follow-up:**")
            lines.append("")
            for item in recommended_followup(row["event_type"]):
                lines.append(f"- {item}")
            lines.append("")

    lines.append("## Recommended Analyst Workflow")
    lines.append("")
    lines.append("1. Review open alerts first.")
    lines.append("2. Validate new or changed services.")
    lines.append("3. Confirm whether new assets are authorized.")
    lines.append("4. Compare questionable changes against the previous accepted snapshot.")
    lines.append("5. Suppress expected recurring alerts only after verification.")
    lines.append("")

    append_report_dashboard_usage_section(lines, scope=scope)
    append_report_recommended_next_actions(lines, report_risk_rows, open_alerts, report_asset_rows)

    output_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"Report written to: {output_path}")
    return 0

def clear_screen() -> None:
    if sys.stdout.isatty() and os.environ.get("DELTAAEGIS_NO_CLEAR") != "1":
        os.system("clear" if os.name == "posix" else "cls")


def pause() -> None:
    try: input("\nPress Enter to return to the menu...")
    except EOFError: pass


def print_banner() -> None:
    print("╔══════════════════════════════════════════════╗")
    print("║                  DELTAAEGIS                  ║")
    print("║       Network-State Monitoring Console       ║")
    print("╚══════════════════════════════════════════════╝\n")


def run_interactive_menu(args: argparse.Namespace) -> int:
    try:
        while True:
            clear_screen()
            print_banner()

            print(
                "[1] Ingest new NetSniper bundles\n"
                "[2] Show system summary\n"
                "[3] List imported snapshots\n"
                "[4] Show recent delta events\n"
                "[5] Show open alerts\n"
                "[6] Show asset history\n"
                "[7] Show snapshot health\n"
                "[8] Approve reviewed snapshot as baseline\n"
                "[9] Generate investigation report\n"
                "[10] Show telemetry paths\n"
                "[11] Exit\n"
            )

            choice = input("deltaaegis> ").strip()
            print()

            if choice == "1":
                command_ingest(args)
            elif choice == "2":
                command_summary(args)
            elif choice == "3":
                args.limit = 20
                command_snapshots(args)
            elif choice == "4":
                args.limit = 20
                args.severity = None
                args.event_type = None
                command_events(args)
            elif choice == "5":
                args.status = "OPEN"
                args.limit = 20
                command_alerts(args)
            elif choice == "6":
                args.identifier = input("Asset key or current IP: ").strip()
                args.limit = 20
                command_asset(args)
            elif choice == "7":
                args.limit = 20
                command_health(args)
            elif choice == "8":
                args.scan_id = input("Reviewed snapshot ID: ").strip()
                command_approve(args)
            elif choice == "9":
                args.latest = True
                args.since = None
                args.severity = None
                args.limit = 100
                args.output = None
                command_report(args)
            elif choice == "10":
                command_paths(args)
            elif choice == "11":
                print("Exiting DeltaAegis.")
                return 0
            else:
                print("Invalid selection.")

            pause()

    except (KeyboardInterrupt, EOFError):
        print("\nExiting DeltaAegis.")
        return 0

def normalize_optional_text(value):
    if value is None:
        return None

    value = str(value).strip()

    if value == "":
        return None

    return value


INVESTIGATION_STATUSES = {
    "NEW",
    "REVIEWING",
    "NEEDS_OWNER",
    "EXPECTED",
    "FALSE_POSITIVE",
    "MONITORING",
    "RESOLVED",
}


def normalize_investigation_status(value):
    status = str(value or "").strip().upper().replace("-", "_")

    if status not in INVESTIGATION_STATUSES:
        allowed = ", ".join(sorted(INVESTIGATION_STATUSES))
        raise DeltaAegisError(
            f"invalid investigation status: {status}. Allowed: {allowed}"
        )

    return status


def fetch_asset_investigation(connection, asset_key, scope):
    row = connection.execute(
        """
        SELECT network_scope, asset_key, status, reason, created_at, updated_at
        FROM asset_investigations
        WHERE asset_key = ?
          AND network_scope = ?
        """,
        (asset_key, scope),
    ).fetchone()

    return dict(row) if row else None


def resolve_asset_for_investigation(connection, identifier, scope=None):
    identifier = str(identifier or "").strip()

    if not identifier:
        raise DeltaAegisError("asset identifier cannot be empty")

    normalized = identifier.lower()

    clauses = [
        """
        (
            LOWER(asset_key) = ?
            OR LOWER(current_ip) = ?
            OR LOWER(COALESCE(mac_address, '')) = ?
        )
        """
    ]

    params = [normalized, normalized, normalized]

    if scope:
        clauses.append("network_scope = ?")
        params.append(scope)

    rows = connection.execute(
        f"""
        SELECT network_scope, asset_key, current_ip, mac_address
        FROM asset_lifecycle
        WHERE {" AND ".join(clauses)}
        ORDER BY network_scope ASC, asset_key ASC
        """,
        tuple(params),
    ).fetchall()

    if not rows:
        raise DeltaAegisError(
            f"asset not found for investigation status: {identifier}"
        )

    if len(rows) > 1 and not scope:
        matches = ", ".join(
            f"{row['network_scope']}:{row['asset_key']}" for row in rows
        )
        raise DeltaAegisError(
            "multiple assets matched. Re-run with --scope. "
            f"Matches: {matches}"
        )

    row = rows[0]
    return row["asset_key"], row["network_scope"]


def set_asset_investigation_status(connection, asset_key, scope, status, reason):
    status = normalize_investigation_status(status)
    reason = normalize_optional_text(reason)

    if reason is None:
        raise DeltaAegisError(
            "provide --reason when setting an investigation status"
        )

    now = utc_now()
    existing = fetch_asset_investigation(connection, asset_key, scope)

    if existing:
        connection.execute(
            """
            UPDATE asset_investigations
            SET status = ?,
                reason = ?,
                updated_at = ?
            WHERE asset_key = ?
              AND network_scope = ?
            """,
            (status, reason, now, asset_key, scope),
        )
    else:
        connection.execute(
            """
            INSERT INTO asset_investigations (
                network_scope,
                asset_key,
                status,
                reason,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (scope, asset_key, status, reason, now, now),
        )

    connection.execute(
        """
        INSERT INTO asset_investigation_history (
            network_scope,
            asset_key,
            status,
            reason,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (scope, asset_key, status, reason, now),
    )

    return fetch_asset_investigation(connection, asset_key, scope)


def command_investigate_asset(args):
    connection = connect(args.db)
    scope = optional_network_scope(getattr(args, "scope", None))

    asset_key, resolved_scope = resolve_asset_for_investigation(
        connection,
        args.identifier,
        scope=scope,
    )

    record = set_asset_investigation_status(
        connection,
        asset_key,
        resolved_scope,
        args.status,
        args.reason,
    )

    connection.commit()

    print(f"Asset investigation status saved: {asset_key}")
    print(f"Scope:  {resolved_scope}")
    print(f"Status: {record['status']}")
    print(f"Reason: {record['reason']}")
    print(f"Updated: {record['updated_at']}")

    return 0


def command_annotate_asset(args):
    connection = connect(args.db)

    asset_key = args.asset_key.strip()

    if not asset_key:
        raise DeltaAegisError("asset key cannot be empty")

    existing = connection.execute(
        """
        SELECT asset_key, owner, role, criticality, notes, updated_at
        FROM asset_annotations
        WHERE asset_key = ?
        """,
        (asset_key,),
    ).fetchone()

    owner = normalize_optional_text(args.owner)
    role = normalize_optional_text(args.role)
    criticality = normalize_optional_text(args.criticality)
    notes = normalize_optional_text(args.notes)

    if existing:
        owner = owner if owner is not None else existing["owner"]
        role = role if role is not None else existing["role"]
        criticality = criticality if criticality is not None else existing["criticality"]
        notes = notes if notes is not None else existing["notes"]

    if owner is None and role is None and criticality is None and notes is None:
        raise DeltaAegisError(
            "provide at least one annotation field: --owner, --role, --criticality, or --notes"
        )

    now = utc_now()

    if existing:
        connection.execute(
            """
            UPDATE asset_annotations
            SET owner = ?,
                role = ?,
                criticality = ?,
                notes = ?,
                updated_at = ?
            WHERE asset_key = ?
            """,
            (
                owner,
                role,
                criticality,
                notes,
                now,
                asset_key,
            ),
        )
    else:
        connection.execute(
            """
            INSERT INTO asset_annotations (
                asset_key,
                owner,
                role,
                criticality,
                notes,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                asset_key,
                owner,
                role,
                criticality,
                notes,
                now,
            ),
        )

    connection.execute(
        """
        INSERT INTO asset_annotation_history (
            asset_key,
            owner,
            role,
            criticality,
            notes,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            asset_key,
            owner,
            role,
            criticality,
            notes,
            now,
        ),
    )

    connection.commit()

    print(f"Asset annotation saved: {asset_key}")
    print()
    print(f"Owner:       {owner or '-'}")
    print(f"Role:        {role or '-'}")
    print(f"Criticality: {criticality or '-'}")
    print(f"Notes:       {notes or '-'}")
    print(f"Updated:     {now}")

    return 0


def command_asset_notes(args):
    connection = connect(args.db)

    asset_key = args.asset_key.strip()

    annotation = connection.execute(
        """
        SELECT asset_key, owner, role, criticality, notes, updated_at
        FROM asset_annotations
        WHERE asset_key = ?
        """,
        (asset_key,),
    ).fetchone()

    print(f"Asset Notes: {asset_key}")
    print("=" * (13 + len(asset_key)))
    print()

    if annotation is None:
        print("No annotation has been recorded for this asset.")
    else:
        print(f"Owner:       {annotation['owner'] or '-'}")
        print(f"Role:        {annotation['role'] or '-'}")
        print(f"Criticality: {annotation['criticality'] or '-'}")
        print(f"Notes:       {annotation['notes'] or '-'}")
        print(f"Updated:     {annotation['updated_at']}")

    if args.history:
        print()
        print("Annotation History")
        print("------------------")

        rows = connection.execute(
            """
            SELECT annotation_id, owner, role, criticality, notes, created_at
            FROM asset_annotation_history
            WHERE asset_key = ?
            ORDER BY annotation_id ASC
            """,
            (asset_key,),
        ).fetchall()

        if not rows:
            print("No annotation history has been recorded for this asset.")
        else:
            for row in rows:
                print(f"[{row['annotation_id']}] {row['created_at']}")
                print(f"  Owner:       {row['owner'] or '-'}")
                print(f"  Role:        {row['role'] or '-'}")
                print(f"  Criticality: {row['criticality'] or '-'}")
                print(f"  Notes:       {row['notes'] or '-'}")
                print()

    return 0


def command_asset_annotations(args):
    connection = connect(args.db)

    rows = connection.execute(
        """
        SELECT asset_key, owner, role, criticality, notes, updated_at
        FROM asset_annotations
        ORDER BY updated_at DESC, asset_key ASC
        LIMIT ?
        """,
        (args.limit,),
    ).fetchall()

    if not rows:
        print("No asset annotations have been recorded.")
        return 0

    print("Asset Annotations")
    print("=================")
    print()

    for row in rows:
        print(row["asset_key"])
        print(f"  Owner:       {row['owner'] or '-'}")
        print(f"  Role:        {row['role'] or '-'}")
        print(f"  Criticality: {row['criticality'] or '-'}")
        print(f"  Notes:       {row['notes'] or '-'}")
        print(f"  Updated:     {row['updated_at']}")
        print()

    return 0

def add_alert_note(connection, alert_id, action, reason):
    reason = (reason or "").strip()

    if not reason:
        reason = "No reason provided."

    connection.execute(
        """
        INSERT INTO alert_notes (
            alert_id,
            action,
            reason,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            alert_id,
            action.upper(),
            reason,
            utc_now(),
        ),
    )


def command_alert_notes(args):
    connection = connect(args.db)

    alert = connection.execute(
        """
        SELECT alert_id, status, severity, event_type, subject_key, summary
        FROM alerts
        WHERE alert_id = ?
        """,
        (args.alert_id,),
    ).fetchone()

    if alert is None:
        print(f"No alert found with alert_id={args.alert_id}")
        return 1

    notes = connection.execute(
        """
        SELECT note_id, action, reason, created_at
        FROM alert_notes
        WHERE alert_id = ?
        ORDER BY note_id ASC
        """,
        (args.alert_id,),
    ).fetchall()

    print(f"Alert Notes: {args.alert_id}")
    print("=" * (13 + len(str(args.alert_id))))
    print()
    print(f"Status:   {alert['status']}")
    print(f"Severity: {alert['severity']}")
    print(f"Type:     {alert['event_type']}")
    print(f"Subject:  {alert['subject_key']}")
    print(f"Summary:  {alert['summary']}")
    print()

    if not notes:
        print("No review notes have been recorded for this alert.")
        return 0

    for note in notes:
        print(f"[{note['note_id']}] {note['created_at']}  {note['action']}")
        print(f"  Reason: {note['reason']}")
        print()

    return 0

def command_asset_timeline(args):
    connection = connect(args.db)

    clauses = ["(subject_key = ? OR subject_key LIKE ?)"]
    params = [args.asset_key, f"%{args.asset_key}%"]

    if args.severity:
        clauses.append("severity = ?")
        params.append(args.severity.upper())

    params.append(args.limit)

    rows = connection.execute(
        f"""
        SELECT
            event_id,
            scan_id,
            baseline_scan_id,
            created_at,
            severity,
            event_type,
            subject_key,
            previous_value,
            current_value,
            summary
        FROM delta_events
        WHERE {" AND ".join(clauses)}
        ORDER BY created_at ASC, event_id ASC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()

    print(f"Asset Timeline: {args.asset_key}")
    print("=" * (16 + len(args.asset_key)))
    print()

    if not rows:
        print("No delta events matched this asset or subject key.")
        return 0

    for row in rows:
        print(f"[{row['event_id']}] {row['created_at']}  {row['severity']}  {row['event_type']}")
        print(f"  Subject:  {row['subject_key']}")
        print(f"  Snapshot: {row['scan_id']}")
        print(f"  Baseline: {row['baseline_scan_id'] or '-'}")

        if row["previous_value"]:
            print(f"  Previous: {row['previous_value']}")

        if row["current_value"]:
            print(f"  Current:  {row['current_value']}")

        print(f"  Summary:  {row['summary']}")
        print()

    return 0


def command_alert_detail(args):
    connection = connect(args.db)

    alert = connection.execute(
        """
        SELECT *
        FROM alerts
        WHERE alert_id = ?
        """,
        (args.alert_id,),
    ).fetchone()

    if alert is None:
        print(f"No alert found with alert_id={args.alert_id}")
        return 1

    alert_columns = set(alert.keys())

    print(f"Alert Detail: {args.alert_id}")
    print("=" * (14 + len(str(args.alert_id))))
    print()

    for field in [
        "alert_id",
        "status",
        "severity",
        "event_type",
        "subject_key",
        "opened_at",
        "updated_at",
        "resolved_at",
        "suppressed_at",
        "summary",
    ]:
        if field in alert_columns:
            print(f"{field}: {alert[field]}")

    print()

    related_event = None

    if "event_id" in alert_columns and alert["event_id"] is not None:
        related_event = connection.execute(
            """
            SELECT *
            FROM delta_events
            WHERE event_id = ?
            """,
            (alert["event_id"],),
        ).fetchone()

    if related_event is None and {"event_type", "subject_key"}.issubset(alert_columns):
        related_event = connection.execute(
            """
            SELECT *
            FROM delta_events
            WHERE event_type = ?
              AND subject_key = ?
            ORDER BY event_id DESC
            LIMIT 1
            """,
            (alert["event_type"], alert["subject_key"]),
        ).fetchone()

    if related_event:
        print("Related Event")
        print("-------------")

        for field in [
            "event_id",
            "scan_id",
            "baseline_scan_id",
            "created_at",
            "severity",
            "event_type",
            "subject_key",
            "previous_value",
            "current_value",
            "summary",
        ]:
            if field in related_event.keys():
                print(f"{field}: {related_event[field]}")

        print()

        print("Why this matters")
        print("----------------")
        print(severity_explanation(related_event["severity"]))
        print()

        print("Recommended follow-up")
        print("---------------------")
        for item in recommended_followup(related_event["event_type"]):
            print(f"- {item}")

        print()
    else:
        print("No directly related delta event was found.")
        print()


    notes = connection.execute(
        """
        SELECT note_id, action, reason, created_at
        FROM alert_notes
        WHERE alert_id = ?
        ORDER BY note_id ASC
        """,
        (args.alert_id,),
    ).fetchall()

    print("Review Notes")
    print("------------")

    if not notes:
        print("No review notes have been recorded for this alert.")
    else:
        for note in notes:
            print(f"[{note['note_id']}] {note['created_at']}  {note['action']}")
            print(f"  Reason: {note['reason']}")

    print()

    return 0



def dashboard_json_response(handler, payload, status=200):
    body = json.dumps(payload, indent=2, default=str).encode("utf-8")

    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def dashboard_html_response(handler, body, status=200):
    body = body.encode("utf-8")

    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def dashboard_text_response(handler, body, status=200):
    body = str(body).encode("utf-8")

    handler.send_response(status)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def dashboard_safe_query(connection, sql, params=()):
    try:
        rows = connection.execute(sql, params).fetchall()
    except Exception:
        return []

    return [dict(row) for row in rows]


def dashboard_json_list(value):
    if value is None or value == "":
        return []

    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []

    return decoded if isinstance(decoded, list) else []


def dashboard_enrich_classification_payload(row):
    if row is None:
        return None

    item = dict(row)

    evidence = dashboard_json_list(item.get("classification_evidence_json"))
    contradictions = dashboard_json_list(item.get("classification_contradictions_json"))
    candidates = dashboard_json_list(item.get("classification_candidates_json"))

    item["classification_evidence"] = evidence
    item["classification_contradictions"] = contradictions
    item["classification_candidates"] = candidates
    item["classification_evidence_count"] = len(evidence)
    item["classification_contradiction_count"] = len(contradictions)
    item["classification_candidate_count"] = len(candidates)

    item["classification_display_type"] = (
        item.get("classification_type")
        or item.get("classification_primary_type")
        or item.get("device_type")
        or "Unknown"
    )

    item["classification_display_decision"] = (
        item.get("classification_decision")
        or "unknown"
    )

    item["classification_display_confidence"] = (
        item.get("classification_confidence")
        if item.get("classification_confidence") is not None
        else item.get("device_type_confidence")
    )

    if item["classification_display_confidence"] is None:
        item["classification_display_confidence"] = 0

    item["classification_has_intelligence"] = bool(
        item.get("classification_type")
        or item.get("classification_primary_type")
        or item.get("classification_method")
        or item.get("classification_confidence") is not None
        or evidence
        or contradictions
        or candidates
    )

    return item


def dashboard_enrich_classification_rows(rows):
    return [dashboard_enrich_classification_payload(row) for row in rows]


def dashboard_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def dashboard_classification_summary_payload(connection, scope=None, limit=10):
    assets = dashboard_assets_payload(
        connection,
        limit=10000,
        scope=scope,
    )

    total_assets = len(assets)
    classified_assets = 0
    possible_assets = 0
    unknown_assets = 0
    evidence_backed_assets = 0
    contradiction_assets = 0
    high_confidence_assets = 0

    type_counts = {}
    review_rows = []

    for asset in assets:
        decision = str(asset.get("classification_display_decision") or "unknown").lower()
        classification = str(asset.get("classification_display_type") or "Unknown").strip()
        confidence = dashboard_int(asset.get("classification_display_confidence"), 0)
        evidence_count = dashboard_int(asset.get("classification_evidence_count"), 0)
        contradiction_count = dashboard_int(asset.get("classification_contradiction_count"), 0)

        is_unknown_type = classification in {"", "Unknown", "Unknown / Ambiguous"}

        if decision == "classified":
            classified_assets += 1
        elif decision == "possible":
            possible_assets += 1
        else:
            unknown_assets += 1

        if evidence_count > 0:
            evidence_backed_assets += 1

        if contradiction_count > 0:
            contradiction_assets += 1

        if confidence >= 80:
            high_confidence_assets += 1

        if not is_unknown_type:
            type_counts[classification] = type_counts.get(classification, 0) + 1

        review_reason = None
        review_priority = 99

        if contradiction_count > 0:
            review_reason = "Classification contradiction present"
            review_priority = 1
        elif decision == "possible":
            review_reason = "Weak/possible classification"
            review_priority = 2
        elif decision == "unknown" or confidence == 0 or is_unknown_type:
            review_reason = "Unknown or ambiguous classification"
            review_priority = 3
        elif confidence < 40:
            review_reason = "Low classification confidence"
            review_priority = 4

        if review_reason:
            review_rows.append(
                {
                    "asset_key": asset.get("asset_key"),
                    "network_scope": asset.get("network_scope"),
                    "ip_address": asset.get("current_ip"),
                    "mac_address": asset.get("mac_address"),
                    "classification": classification or "Unknown",
                    "decision": decision,
                    "confidence": confidence,
                    "evidence_count": evidence_count,
                    "contradiction_count": contradiction_count,
                    "reason": review_reason,
                    "priority": review_priority,
                }
            )

    top_classifications = [
        {
            "classification": classification,
            "count": count,
        }
        for classification, count in sorted(
            type_counts.items(),
            key=lambda item: (-item[1], item[0].lower()),
        )[:limit]
    ]

    review_queue = sorted(
        review_rows,
        key=lambda row: (
            row["priority"],
            row["confidence"],
            row["classification"].lower(),
            str(row.get("ip_address") or ""),
            str(row.get("asset_key") or ""),
        ),
    )[:limit]

    classified_percent = 0

    if total_assets:
        classified_percent = round((classified_assets / total_assets) * 100, 1)

    return {
        "total_assets": total_assets,
        "classified_assets": classified_assets,
        "possible_assets": possible_assets,
        "unknown_assets": unknown_assets,
        "evidence_backed_assets": evidence_backed_assets,
        "contradiction_assets": contradiction_assets,
        "high_confidence_assets": high_confidence_assets,
        "classified_percent": classified_percent,
        "top_classifications": top_classifications,
        "review_queue": review_queue,
    }


def dashboard_count(connection, table, where=None):
    sql = f"SELECT COUNT(*) AS count FROM {table}"

    if where:
        sql += f" WHERE {where}"

    try:
        row = connection.execute(sql).fetchone()
    except Exception:
        return 0

    if row is None:
        return 0

    return int(row["count"])


def dashboard_scopes_payload(connection):
    rows = connection.execute(
        """
        SELECT
            s.network_scope,
            COUNT(*) AS snapshots,
            SUM(CASE WHEN s.quality_status = 'ACCEPTED' THEN 1 ELSE 0 END) AS accepted_snapshots,
            MAX(s.created_at) AS latest_scan_at,
            COALESCE(ev.event_count, 0) AS events,
            COALESCE(al.open_alerts, 0) AS open_alerts
        FROM snapshots s
        LEFT JOIN (
            SELECT
                snap.network_scope AS network_scope,
                COUNT(e.event_id) AS event_count
            FROM delta_events e
            JOIN snapshots snap ON snap.scan_id = e.scan_id
            GROUP BY snap.network_scope
        ) ev ON ev.network_scope = s.network_scope
        LEFT JOIN (
            SELECT
                snap.network_scope AS network_scope,
                COUNT(DISTINCT a.alert_id) AS open_alerts
            FROM alerts a
            JOIN delta_events e ON e.event_id = a.last_event_id
            JOIN snapshots snap ON snap.scan_id = e.scan_id
            WHERE a.status = 'OPEN'
            GROUP BY snap.network_scope
        ) al ON al.network_scope = s.network_scope
        GROUP BY s.network_scope
        ORDER BY latest_scan_at DESC
        """
    ).fetchall()

    return [dict(row) for row in rows]


def dashboard_netsniper_intelligence_summary_payload(connection, limit=10):
    row = latest_netsniper_intelligence_summary(connection)

    if row is None:
        return {
            "available": False,
            "message": "No NetSniper v1.7 intelligence summary has been imported yet.",
        }

    top_device_types = _decode_json_dict(row["top_device_types_json"])
    confidence_bands = _decode_json_dict(row["confidence_band_counts_json"])
    review_queue = _decode_json_list(row["review_queue_json"])
    false_confidence = _decode_json_list(row["false_confidence_candidates_json"])
    unknown_exposed = _decode_json_list(row["unknown_with_exposed_services_json"])

    return {
        "available": True,
        "scan_id": row["scan_id"],
        "host_count": int(row["host_count"] or 0),
        "classified_count": int(row["classified_count"] or 0),
        "possible_or_review_count": int(row["possible_or_review_count"] or 0),
        "unknown_count": int(row["unknown_count"] or 0),
        "contradiction_host_count": int(row["contradiction_host_count"] or 0),
        "false_confidence_candidate_count": int(row["false_confidence_candidate_count"] or 0),
        "unknown_with_exposed_services_count": int(row["unknown_with_exposed_services_count"] or 0),
        "top_device_types": [
            {
                "device_type": device_type,
                "count": count,
            }
            for device_type, count in sorted(
                top_device_types.items(),
                key=lambda item: (-int(item[1] or 0), str(item[0]).lower()),
            )
        ],
        "confidence_band_counts": [
            {
                "band": band,
                "count": count,
            }
            for band, count in sorted(
                confidence_bands.items(),
                key=lambda item: str(item[0]).lower(),
            )
        ],
        "review_queue": review_queue[:limit],
        "false_confidence_candidates": false_confidence[:limit],
        "unknown_with_exposed_services": unknown_exposed[:limit],
    }


def dashboard_summary_payload(connection, scope=None):
    if scope:
        snapshot_count = connection.execute(
            "SELECT COUNT(*) AS count FROM snapshots WHERE network_scope = ?",
            (scope,),
        ).fetchone()["count"]

        event_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM delta_events e
            JOIN snapshots s ON s.scan_id = e.scan_id
            WHERE s.network_scope = ?
            """,
            (scope,),
        ).fetchone()["count"]

        alert_count = connection.execute(
            """
            SELECT COUNT(DISTINCT a.alert_id) AS count
            FROM alerts a
            LEFT JOIN delta_events e ON e.event_id = a.last_event_id
            LEFT JOIN snapshots s ON s.scan_id = e.scan_id
            WHERE s.network_scope = ?
            """,
            (scope,),
        ).fetchone()["count"]

        open_alert_count = connection.execute(
            """
            SELECT COUNT(DISTINCT a.alert_id) AS count
            FROM alerts a
            LEFT JOIN delta_events e ON e.event_id = a.last_event_id
            LEFT JOIN snapshots s ON s.scan_id = e.scan_id
            WHERE a.status = 'OPEN'
              AND s.network_scope = ?
            """,
            (scope,),
        ).fetchone()["count"]

        annotation_count = connection.execute(
            """
            SELECT COUNT(DISTINCT aa.asset_key) AS count
            FROM asset_annotations aa
            JOIN asset_observations ao ON ao.asset_key = aa.asset_key
            JOIN snapshots s ON s.scan_id = ao.scan_id
            WHERE s.network_scope = ?
            """,
            (scope,),
        ).fetchone()["count"]

        alert_rows = dashboard_safe_query(
            connection,
            """
            SELECT a.status, COUNT(DISTINCT a.alert_id) AS count
            FROM alerts a
            LEFT JOIN delta_events e ON e.event_id = a.last_event_id
            LEFT JOIN snapshots s ON s.scan_id = e.scan_id
            WHERE s.network_scope = ?
            GROUP BY a.status
            ORDER BY a.status
            """,
            (scope,),
        )

        event_rows = dashboard_safe_query(
            connection,
            """
            SELECT e.severity, COUNT(*) AS count
            FROM delta_events e
            JOIN snapshots s ON s.scan_id = e.scan_id
            WHERE s.network_scope = ?
            GROUP BY e.severity
            ORDER BY count DESC, e.severity ASC
            """,
            (scope,),
        )
    else:
        snapshot_count = dashboard_count(connection, "snapshots")
        event_count = dashboard_count(connection, "delta_events")
        alert_count = dashboard_count(connection, "alerts")
        open_alert_count = dashboard_count(connection, "alerts", "status = 'OPEN'")
        annotation_count = dashboard_count(connection, "asset_annotations")

        alert_rows = dashboard_safe_query(
            connection,
            """
            SELECT status, COUNT(*) AS count
            FROM alerts
            GROUP BY status
            ORDER BY status
            """,
        )

        event_rows = dashboard_safe_query(
            connection,
            """
            SELECT severity, COUNT(*) AS count
            FROM delta_events
            GROUP BY severity
            ORDER BY count DESC, severity ASC
            """,
        )

    risk_rows = []

    try:
        risk_rows = build_risk_register(connection, 5, scope=scope)
    except Exception:
        risk_rows = []

    return {
        "selected_scope": scope,
        "snapshots": int(snapshot_count or 0),
        "events": int(event_count or 0),
        "alerts": int(alert_count or 0),
        "open_alerts": int(open_alert_count or 0),
        "asset_annotations": int(annotation_count or 0),
        "alert_status_counts": alert_rows,
        "event_severity_counts": event_rows,
        "classification_summary": dashboard_classification_summary_payload(
            connection,
            scope=scope,
        ),
        "netsniper_intelligence_summary": dashboard_netsniper_intelligence_summary_payload(
            connection,
        ),
        "top_risks": risk_rows,
    }

def dashboard_table_columns(connection, table_name):
    try:
        rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    except Exception:
        return set()

    return {row["name"] for row in rows}


def dashboard_snapshot_order_clause(connection):
    columns = dashboard_table_columns(connection, "snapshots")
    order_columns = [
        column for column in ["created_at", "imported_at", "scan_id"]
        if column in columns
    ]

    if not order_columns:
        return "rowid DESC"

    return ", ".join(f"{column} DESC" for column in order_columns)


def dashboard_snapshot_select_columns(connection):
    columns = dashboard_table_columns(connection, "snapshots")

    preferred = [
        "scan_id",
        "created_at",
        "imported_at",
        "source_path",
        "source_file",
        "bundle_path",
        "manifest_path",
        "scanner_version",
        "telemetry_contract",
        "schema_version",
    ]

    selected = [column for column in preferred if column in columns]

    if "scan_id" not in selected and "scan_id" in columns:
        selected.insert(0, "scan_id")

    if not selected:
        selected = ["rowid"]

    return selected


def dashboard_snapshot_rows(connection, limit=2, scope=None):
    selected = dashboard_snapshot_select_columns(connection)
    order_clause = dashboard_snapshot_order_clause(connection)

    where = ""
    params = []

    if scope:
        where = "WHERE network_scope = ?"
        params.append(scope)

    params.append(limit)

    try:
        rows = connection.execute(
            f"""
            SELECT {", ".join(selected)}
            FROM snapshots
            {where}
            ORDER BY {order_clause}
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
    except Exception:
        return []

    return [dict(row) for row in rows]

def dashboard_snapshot_asset_summary(connection, scan_id):
    if not scan_id:
        return {
            "observed_assets": 0,
            "observed_ips": 0,
            "observed_macs": 0,
            "assets_with_ip_and_mac": 0,
        }

    columns = dashboard_table_columns(connection, "asset_observations")

    if not columns:
        return {
            "observed_assets": 0,
            "observed_ips": 0,
            "observed_macs": 0,
            "assets_with_ip_and_mac": 0,
        }

    try:
        observed_assets = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM asset_observations
            WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchone()["count"]
    except Exception:
        observed_assets = 0

    observed_ips = 0
    observed_macs = 0
    assets_with_ip_and_mac = 0

    if "ip_address" in columns:
        try:
            observed_ips = connection.execute(
                """
                SELECT COUNT(DISTINCT ip_address) AS count
                FROM asset_observations
                WHERE scan_id = ?
                  AND ip_address IS NOT NULL
                  AND ip_address != ''
                """,
                (scan_id,),
            ).fetchone()["count"]
        except Exception:
            observed_ips = 0

    if "mac_address" in columns:
        try:
            observed_macs = connection.execute(
                """
                SELECT COUNT(DISTINCT mac_address) AS count
                FROM asset_observations
                WHERE scan_id = ?
                  AND mac_address IS NOT NULL
                  AND mac_address != ''
                """,
                (scan_id,),
            ).fetchone()["count"]
        except Exception:
            observed_macs = 0

    if "ip_address" in columns and "mac_address" in columns:
        try:
            assets_with_ip_and_mac = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM asset_observations
                WHERE scan_id = ?
                  AND ip_address IS NOT NULL
                  AND ip_address != ''
                  AND mac_address IS NOT NULL
                  AND mac_address != ''
                """,
                (scan_id,),
            ).fetchone()["count"]
        except Exception:
            assets_with_ip_and_mac = 0

    return {
        "observed_assets": int(observed_assets or 0),
        "observed_ips": int(observed_ips or 0),
        "observed_macs": int(observed_macs or 0),
        "assets_with_ip_and_mac": int(assets_with_ip_and_mac or 0),
    }


def dashboard_enrich_snapshot(connection, snapshot):
    if snapshot is None:
        return None

    item = dict(snapshot)
    scan_id = item.get("scan_id")
    item["asset_summary"] = dashboard_snapshot_asset_summary(connection, scan_id)

    return item


def dashboard_delta_scan_pairs(connection, limit=10, scope=None):
    where = ""
    params = []

    if scope:
        where = "WHERE snap.network_scope = ?"
        params.append(scope)

    params.append(limit)

    try:
        rows = connection.execute(
            f"""
            SELECT
                e.scan_id,
                e.baseline_scan_id,
                snap.network_scope,
                COUNT(*) AS event_count,
                MAX(e.created_at) AS latest_event_at
            FROM delta_events e
            JOIN snapshots snap ON snap.scan_id = e.scan_id
            {where}
            GROUP BY e.scan_id, e.baseline_scan_id, snap.network_scope
            ORDER BY latest_event_at DESC, event_count DESC
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
    except Exception:
        return []

    return [dict(row) for row in rows]

def dashboard_scan_context_payload(connection, scope=None):
    snapshots = dashboard_snapshot_rows(connection, 2, scope=scope)

    latest_scan = dashboard_enrich_snapshot(
        connection,
        snapshots[0] if len(snapshots) >= 1 else None,
    )

    baseline_scan = dashboard_enrich_snapshot(
        connection,
        snapshots[1] if len(snapshots) >= 2 else None,
    )

    return {
        "selected_scope": scope,
        "latest_scan": latest_scan,
        "baseline_scan": baseline_scan,
        "delta_scan_pairs": dashboard_delta_scan_pairs(connection, 10, scope=scope),
    }


def dashboard_latest_accepted_snapshot(connection, scope=None):
    params = []
    where = "WHERE quality_status = 'ACCEPTED'"

    if scope:
        where += " AND network_scope = ?"
        params.append(scope)

    try:
        row = connection.execute(
            f"""
            SELECT *
            FROM snapshots
            {where}
            ORDER BY imported_at DESC, created_at DESC, scan_id DESC
            LIMIT 1
            """,
            tuple(params),
        ).fetchone()
    except Exception:
        return None

    return dict(row) if row is not None else None


def dashboard_current_state_payload(connection, scope=None):
    snapshot = dashboard_latest_accepted_snapshot(connection, scope=scope)

    if snapshot is None:
        return {
            "available": False,
            "selected_scope": scope,
            "message": "No accepted snapshot is available for the selected scope.",
        }

    scan_id = snapshot["scan_id"]

    asset_row = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM asset_observations
        WHERE scan_id = ?
        """,
        (scan_id,),
    ).fetchone()

    intelligence_row = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM netsniper_intelligence_hosts
        WHERE scan_id = ?
        """,
        (scan_id,),
    ).fetchone()

    service_row = connection.execute(
        """
        SELECT COUNT(DISTINCT asset_key) AS count
        FROM service_observations
        WHERE scan_id = ?
        """,
        (scan_id,),
    ).fetchone()

    summary = connection.execute(
        """
        SELECT
            host_count,
            classified_count,
            possible_or_review_count,
            unknown_count,
            contradiction_host_count,
            false_confidence_candidate_count,
            unknown_with_exposed_services_count
        FROM netsniper_intelligence_summaries
        WHERE scan_id = ?
        """,
        (scan_id,),
    ).fetchone()

    assets = int(asset_row["count"] or 0) if asset_row else 0
    intelligence_hosts = int(intelligence_row["count"] or 0) if intelligence_row else 0
    service_observed_assets = int(service_row["count"] or 0) if service_row else 0
    discovery_only_assets = max(0, assets - service_observed_assets)

    if summary is not None:
        classified = int(summary["classified_count"] or 0)
        possible_or_review = int(summary["possible_or_review_count"] or 0)
        unknown = int(summary["unknown_count"] or 0)
        contradiction_hosts = int(summary["contradiction_host_count"] or 0)
        false_confidence_candidates = int(summary["false_confidence_candidate_count"] or 0)
        unknown_with_exposed_services = int(summary["unknown_with_exposed_services_count"] or 0)
        summary_host_count = int(summary["host_count"] or 0)
    else:
        classified = 0
        possible_or_review = 0
        unknown = 0
        contradiction_hosts = 0
        false_confidence_candidates = 0
        unknown_with_exposed_services = 0
        summary_host_count = 0

    return {
        "available": True,
        "selected_scope": scope,
        "scan_id": scan_id,
        "target": snapshot["target"],
        "network_scope": snapshot.get("network_scope"),
        "created_at": snapshot.get("created_at"),
        "imported_at": snapshot.get("imported_at"),
        "scanner_version": snapshot.get("scanner_version"),
        "scan_profile": snapshot.get("scan_profile"),
        "quality_status": snapshot.get("quality_status"),
        "hosts_up": int(snapshot["hosts_up"] or 0),
        "hosts_total": int(snapshot["hosts_total"] or 0),
        "mac_backed_assets": int(snapshot["mac_backed_assets"] or 0),
        "identity_coverage": float(snapshot["identity_coverage"] or 0.0),
        "assets": assets,
        "intelligence_hosts": intelligence_hosts,
        "service_observed_assets": service_observed_assets,
        "discovery_only_or_no_open_service_assets": discovery_only_assets,
        "summary_host_count": summary_host_count,
        "classified": classified,
        "possible_or_review": possible_or_review,
        "unknown": unknown,
        "contradiction_hosts": contradiction_hosts,
        "false_confidence_candidates": false_confidence_candidates,
        "unknown_with_exposed_services": unknown_with_exposed_services,
        "snapshot": dashboard_enrich_snapshot(connection, snapshot),
    }



def dashboard_assets_payload(connection, limit, scope=None, state=None, identity=None):
    clauses = []
    params = []

    if scope:
        clauses.append("al.network_scope = ?")
        params.append(scope)

    if state:
        clauses.append("al.state = ?")
        params.append(state.upper())

    if identity:
        clauses.append("al.identity_class = ?")
        params.append(identity.upper())

    where = "WHERE " + " AND ".join(clauses) if clauses else ""

    params.append(limit)

    rows = dashboard_safe_query(
        connection,
        f"""
        SELECT
            al.network_scope,
            al.asset_key,
            al.identity_class,
            al.state,
            al.missing_count,
            al.current_ip,
            al.mac_address,
            al.vendor,
            al.hostname,
            al.first_seen_at,
            al.last_seen_at,
            al.removed_at,
            ao.device_type,
            ao.device_type_confidence,
            ao.classification_type,
            ao.classification_primary_type,
            ao.classification_confidence,
            ao.classification_confidence_label,
            ao.classification_decision,
            ao.classification_method,
            ao.classification_evidence_json,
            ao.classification_contradictions_json,
            ao.classification_candidates_json
        FROM asset_lifecycle al
        LEFT JOIN asset_observations ao
          ON ao.scan_id = al.last_seen_scan_id
         AND ao.asset_key = al.asset_key
        {where}
        ORDER BY al.network_scope ASC, al.state ASC, al.current_ip ASC, al.asset_key ASC
        LIMIT ?
        """,
        tuple(params),
    )

    return dashboard_enrich_classification_rows(rows)


def dashboard_netsniper_intelligence_host_payload(connection, identity):
    identity = str(identity or "").strip()

    if not identity:
        return {
            "found": False,
            "error": "missing_identity",
            "message": "Provide identity, host ID, IP, MAC, or hostname.",
        }

    row = get_netsniper_intelligence_host(connection, identity)

    if row is None:
        return {
            "found": False,
            "identity": identity,
            "message": "No matching NetSniper v1.7 intelligence host was found.",
        }

    evidence = _decode_json_list(row["evidence_json"])
    contradictions = _decode_json_list(row["contradictions_json"])
    secondary_candidates = _decode_json_list(row["secondary_candidates_json"])
    observed = _decode_json_dict(row["observed_json"])
    observed_summary = _decode_json_dict(row["observed_summary_json"])
    findings = _decode_json_list(row["findings_json"])

    return {
        "found": True,
        "identity": identity,
        "scan_id": row["scan_id"],
        "host_id": row["host_id"],
        "ip": row["ip"],
        "mac": row["mac"],
        "hostname": row["hostname"],
        "device_type": row["device_type"],
        "device_type_confidence": int(row["device_type_confidence"] or 0),
        "severity": row["severity"],
        "score": int(row["score"] or 0),
        "classification": {
            "primary_type": row["primary_type"],
            "category": row["category"],
            "confidence": int(row["confidence"] or 0),
            "confidence_band": row["confidence_band"],
            "decision": row["decision"],
            "siem_action": row["siem_action"],
            "evidence_count": int(row["evidence_count"] or 0),
            "contradiction_count": int(row["contradiction_count"] or 0),
            "secondary_candidate_count": int(row["secondary_candidate_count"] or 0),
            "explanation": row["explanation"],
        },
        "observed_summary": observed_summary,
        "observed": observed,
        "evidence": evidence,
        "contradictions": contradictions,
        "secondary_candidates": secondary_candidates,
        "findings": findings,
    }


def dashboard_asset_detail_payload(connection, identifier, scope=None, limit=20):
    identifier = str(identifier or "").strip()

    if not identifier:
        return {
            "found": False,
            "error": "missing_identifier",
            "message": "Provide identifier or asset_key.",
        }

    normalized = identifier.lower()

    clauses = [
        """
        (
            LOWER(asset_key) = ?
            OR LOWER(current_ip) = ?
            OR LOWER(COALESCE(mac_address, '')) = ?
        )
        """
    ]

    params = [normalized, normalized, normalized]

    if scope:
        clauses.append("network_scope = ?")
        params.append(scope)

    lifecycle_rows = connection.execute(
        f"""
        SELECT *
        FROM asset_lifecycle
        WHERE {" AND ".join(clauses)}
        ORDER BY network_scope ASC, asset_key ASC
        """,
        tuple(params),
    ).fetchall()

    if not lifecycle_rows:
        return {
            "found": False,
            "identifier": identifier,
            "selected_scope": scope,
            "message": "No asset matched the requested identifier.",
        }

    if len(lifecycle_rows) > 1 and not scope:
        return {
            "found": False,
            "ambiguous": True,
            "identifier": identifier,
            "selected_scope": scope,
            "message": "Multiple assets matched. Re-run with a network scope.",
            "matches": [dict(row) for row in lifecycle_rows],
        }

    asset = dict(lifecycle_rows[0])
    asset_key = asset["asset_key"]
    asset_scope = asset["network_scope"]

    latest_observation = connection.execute(
        """
        SELECT
            ao.*,
            s.network_scope,
            s.scan_id,
            s.created_at AS observed_at
        FROM asset_observations ao
        JOIN snapshots s ON s.scan_id = ao.scan_id
        WHERE ao.asset_key = ?
          AND s.network_scope = ?
        ORDER BY s.created_at DESC, s.imported_at DESC
        LIMIT 1
        """,
        (asset_key, asset_scope),
    ).fetchone()

    latest_observation_dict = (
        dashboard_enrich_classification_payload(dict(latest_observation))
        if latest_observation
        else None
    )
    observation_scan_id = latest_observation["scan_id"] if latest_observation else None

    services = []

    if observation_scan_id:
        services = dashboard_safe_query(
            connection,
            """
            SELECT
                protocol,
                port,
                state,
                service_name,
                product,
                version
            FROM service_observations
            WHERE scan_id = ?
              AND asset_key = ?
            ORDER BY protocol ASC, port ASC
            """,
            (observation_scan_id, asset_key),
        )

    findings = []

    if observation_scan_id:
        findings = dashboard_safe_query(
            connection,
            """
            SELECT
                finding_id,
                name,
                service,
                port,
                score,
                evidence
            FROM finding_observations
            WHERE scan_id = ?
              AND asset_key = ?
            ORDER BY score DESC, finding_id ASC
            """,
            (observation_scan_id, asset_key),
        )

    events = dashboard_safe_query(
        connection,
        """
        SELECT
            e.event_id,
            e.scan_id,
            e.baseline_scan_id,
            e.created_at,
            e.severity,
            e.event_type,
            e.subject_key,
            e.summary
        FROM delta_events e
        JOIN snapshots s ON s.scan_id = e.scan_id
        WHERE e.subject_key = ?
          AND s.network_scope = ?
        ORDER BY e.event_id DESC
        LIMIT ?
        """,
        (asset_key, asset_scope, limit),
    )

    alerts = dashboard_safe_query(
        connection,
        """
        SELECT
            a.alert_id,
            a.status,
            a.severity,
            a.event_type,
            a.subject_key,
            a.summary,
            a.opened_at,
            a.last_seen_at
        FROM alerts a
        JOIN delta_events e ON e.event_id = a.last_event_id
        JOIN snapshots s ON s.scan_id = e.scan_id
        WHERE a.subject_key = ?
          AND s.network_scope = ?
        ORDER BY a.alert_id DESC
        LIMIT ?
        """,
        (asset_key, asset_scope, limit),
    )

    annotation = connection.execute(
        """
        SELECT
            asset_key,
            owner,
            role,
            criticality,
            notes,
            updated_at
        FROM asset_annotations
        WHERE asset_key = ?
        """,
        (asset_key,),
    ).fetchone()

    annotation_dict = dict(annotation) if annotation else None
    persisted_investigation = fetch_asset_investigation(
        connection,
        asset_key,
        asset_scope,
    )

    alert_ids = [
        item.get("alert_id")
        for item in alerts
        if isinstance(item, dict) and item.get("alert_id") is not None
    ]

    alert_notes = []

    if alert_ids:
        placeholders = ",".join("?" for _ in alert_ids)

        alert_notes = dashboard_safe_query(
            connection,
            f"""
            SELECT
                note_id,
                alert_id,
                action,
                reason,
                created_at
            FROM alert_notes
            WHERE alert_id IN ({placeholders})
            ORDER BY created_at DESC, note_id DESC
            LIMIT ?
            """,
            tuple(alert_ids + [limit]),
        )

    observation = latest_observation_dict or {}
    classification_type = (
        observation.get("classification_display_type")
        or observation.get("device_type")
        or "Unknown / Ambiguous"
    )
    classification_decision = str(
        observation.get("classification_display_decision") or "unknown"
    ).lower()
    classification_confidence = dashboard_int(
        observation.get("classification_display_confidence"),
        0,
    )
    evidence_count = dashboard_int(
        observation.get("classification_evidence_count"),
        0,
    )
    contradiction_count = dashboard_int(
        observation.get("classification_contradiction_count"),
        0,
    )

    alert_statuses = {
        str(item.get("status") or "").upper()
        for item in alerts
        if isinstance(item, dict)
    }

    if "OPEN" in alert_statuses:
        inferred_investigation_status = "NEW"
    elif "ACKNOWLEDGED" in alert_statuses:
        inferred_investigation_status = "REVIEWING"
    elif alert_statuses and alert_statuses <= {"SUPPRESSED"}:
        inferred_investigation_status = "FALSE_POSITIVE"
    elif alert_statuses and alert_statuses <= {"RESOLVED"}:
        inferred_investigation_status = "RESOLVED"
    elif not annotation_dict and (alerts or events or services or findings):
        inferred_investigation_status = "NEEDS_OWNER"
    elif annotation_dict:
        inferred_investigation_status = "EXPECTED"
    elif events:
        inferred_investigation_status = "MONITORING"
    else:
        inferred_investigation_status = "NEW"

    if persisted_investigation:
        investigation_status = persisted_investigation["status"]
        investigation_status_source = "persisted"
    else:
        investigation_status = inferred_investigation_status
        investigation_status_source = "inferred"

    recommended_steps = []

    if alerts:
        recommended_steps.append(
            "Review open or recent alerts tied to this asset before closing the investigation."
        )

    if contradiction_count:
        recommended_steps.append(
            "Review NetSniper classification contradictions and verify the asset role manually."
        )

    if (
        classification_decision in {"possible", "weak", "unknown"}
        or classification_confidence < 40
    ):
        recommended_steps.append(
            "Verify the suspected asset role with service evidence, vendor context, or manual annotation."
        )

    if not annotation_dict:
        recommended_steps.append(
            "Add an asset annotation for owner, role, criticality, and notes if this asset is expected."
        )

    if services:
        recommended_steps.append(
            "Confirm exposed services are expected for this asset role and network scope."
        )

    if not recommended_steps:
        recommended_steps.append(
            "Continue monitoring this asset for future service, classification, or alert changes."
        )

    timeline = []

    for item in events:
        timeline.append(
            {
                "kind": "event",
                "id": item.get("event_id"),
                "created_at": item.get("created_at"),
                "severity": item.get("severity"),
                "type": item.get("event_type"),
                "summary": item.get("summary"),
            }
        )

    for item in alerts:
        timeline.append(
            {
                "kind": "alert",
                "id": item.get("alert_id"),
                "created_at": item.get("opened_at") or item.get("last_seen_at"),
                "severity": item.get("severity"),
                "type": item.get("event_type"),
                "summary": item.get("summary"),
            }
        )

    timeline.sort(
        key=lambda item: str(item.get("created_at") or ""),
        reverse=True,
    )

    investigation = {
        "status": investigation_status,
        "inferred_status": inferred_investigation_status,
        "status_source": investigation_status_source,
        "persisted_status": persisted_investigation,
        "recommended_next_steps": recommended_steps,
        "timeline": timeline[:limit],
        "alert_notes": alert_notes,
        "review_context": {
            "classification_type": classification_type,
            "classification_decision": classification_decision,
            "classification_confidence": classification_confidence,
            "classification_evidence_count": evidence_count,
            "classification_contradiction_count": contradiction_count,
            "service_count": len(services),
            "finding_count": len(findings),
            "event_count": len(events),
            "alert_count": len(alerts),
            "alert_note_count": len(alert_notes),
            "has_annotation": bool(annotation_dict),
        },
    }

    return {
        "found": True,
        "identifier": identifier,
        "selected_scope": scope,
        "asset": asset,
        "latest_observation": latest_observation_dict,
        "services": services,
        "findings": findings,
        "events": events,
        "alerts": alerts,
        "annotation": annotation_dict,
        "investigation": investigation,
    }

def dashboard_events_payload(connection, limit, scope=None):
    where = ""
    params = []

    if scope:
        where = "WHERE s.network_scope = ?"
        params.append(scope)

    params.append(limit)

    rows = dashboard_safe_query(
        connection,
        f"""
        SELECT
            e.event_id,
            e.scan_id,
            e.baseline_scan_id,
            s.network_scope,
            e.created_at,
            e.severity,
            e.event_type,
            e.subject_key,
            e.summary
        FROM delta_events e
        JOIN snapshots s ON s.scan_id = e.scan_id
        {where}
        ORDER BY e.event_id DESC
        LIMIT ?
        """,
        tuple(params),
    )

    return dashboard_enrich_subject_rows(connection, rows, scope=scope)

def dashboard_alerts_payload(connection, limit, scope=None):
    where = ""
    params = []

    if scope:
        where = "WHERE s.network_scope = ?"
        params.append(scope)

    params.append(limit)

    rows = dashboard_safe_query(
        connection,
        f"""
        SELECT
            a.alert_id,
            a.status,
            a.severity,
            a.event_type,
            a.subject_key,
            a.summary,
            a.opened_at,
            a.last_seen_at,
            s.network_scope
        FROM alerts a
        LEFT JOIN delta_events e ON e.event_id = a.last_event_id
        LEFT JOIN snapshots s ON s.scan_id = e.scan_id
        {where}
        ORDER BY a.alert_id DESC
        LIMIT ?
        """,
        tuple(params),
    )

    return dashboard_enrich_subject_rows(connection, rows, scope=scope)

def dashboard_annotations_payload(connection, limit, scope=None):
    if scope:
        rows = dashboard_safe_query(
            connection,
            """
            SELECT DISTINCT
                aa.asset_key,
                aa.owner,
                aa.role,
                aa.criticality,
                aa.notes,
                aa.updated_at
            FROM asset_annotations aa
            JOIN asset_observations ao ON ao.asset_key = aa.asset_key
            JOIN snapshots s ON s.scan_id = ao.scan_id
            WHERE s.network_scope = ?
            ORDER BY aa.updated_at DESC, aa.asset_key ASC
            LIMIT ?
            """,
            (scope, limit),
        )
    else:
        rows = dashboard_safe_query(
            connection,
            """
            SELECT
                asset_key,
                owner,
                role,
                criticality,
                notes,
                updated_at
            FROM asset_annotations
            ORDER BY updated_at DESC, asset_key ASC
            LIMIT ?
            """,
            (limit,),
        )

    return dashboard_enrich_subject_rows(
        connection,
        rows,
        subject_field="asset_key",
        scope=scope,
    )



def current_port_behavior_risk_by_asset(connection, scope=None, lookback=5, limit=500):
    rows = mac_port_behavior_rows(
        connection,
        limit=limit,
        scope=scope,
        lookback=lookback,
    )

    by_asset = {}

    for row in rows:
        asset_key = row.get("asset_key")

        if not asset_key:
            continue

        behavior = str(row.get("behavior") or "").upper()

        if behavior not in {"UNEXPECTED_PORT_OPENED", "PORT_FLAPPING"}:
            continue

        by_asset.setdefault(asset_key, []).append(row)

    return by_asset


def port_behavior_risk_points(row):
    behavior = str(row.get("behavior") or "").upper()
    current_state = str(row.get("current_state") or "").upper()

    try:
        port = int(row.get("port") or 0)
    except (TypeError, ValueError):
        port = 0

    if behavior == "UNEXPECTED_PORT_OPENED":
        if port in PORT_BEHAVIOR_HIGH_SIGNAL_PORTS:
            return 20, f"MAC-port behavior detected unexpected high-signal port {row.get('port_key')}: +20"
        if port in PORT_BEHAVIOR_MEDIUM_SIGNAL_PORTS:
            return 10, f"MAC-port behavior detected unexpected monitored port {row.get('port_key')}: +10"
        return 5, f"MAC-port behavior detected unexpected open port {row.get('port_key')}: +5"

    if behavior == "PORT_FLAPPING":
        if current_state == "OPEN" and port in PORT_BEHAVIOR_HIGH_SIGNAL_PORTS:
            return 15, f"MAC-port behavior detected volatile high-signal port {row.get('port_key')}: +15"
        if current_state == "OPEN":
            return 5, f"MAC-port behavior detected volatile open port {row.get('port_key')}: +5"

    return 0, ""


def build_current_risk_register(connection, limit, scope=None):
    snapshot = dashboard_latest_accepted_snapshot(connection, scope=scope)

    if snapshot is None:
        return []

    scan_id = snapshot["scan_id"]

    asset_rows = connection.execute(
        """
        SELECT
            asset_key,
            identity_class,
            identity_confidence,
            identity_source,
            ip_address,
            mac_address,
            vendor,
            hostname,
            device_type,
            severity,
            score,
            classification_primary_type,
            classification_confidence,
            classification_decision,
            classification_siem_action,
            classification_contradiction_count
        FROM asset_observations
        WHERE scan_id = ?
        """,
        (scan_id,),
    ).fetchall()

    services = {}
    for row in connection.execute(
        """
        SELECT asset_key, protocol, port, service_name
        FROM service_observations
        WHERE scan_id = ?
        ORDER BY asset_key, protocol, port
        """,
        (scan_id,),
    ).fetchall():
        services.setdefault(row["asset_key"], []).append(row)

    findings = {}
    for row in connection.execute(
        """
        SELECT asset_key, COUNT(*) AS finding_count, MAX(score) AS max_score
        FROM finding_observations
        WHERE scan_id = ?
        GROUP BY asset_key
        """,
        (scan_id,),
    ).fetchall():
        findings[row["asset_key"]] = row

    open_alert_rows = connection.execute(
        """
        SELECT alert_id, severity, subject_key, summary, last_seen_at
        FROM alerts
        WHERE status = 'OPEN'
        ORDER BY alert_id DESC
        LIMIT 500
        """
    ).fetchall()

    # Ports that should materially raise current risk when exposed.
    high_signal_ports = {
        21, 22, 23, 445, 554, 2375, 2376, 3389, 5000, 5432,
        5555, 5900, 6379, 6443, 7547, 8080, 8081, 8443, 9000,
        9090, 9200, 9300, 9443, 10250, 10255, 27017,
    }

    # Common management/expected service ports. These matter, but should not
    # alone turn ordinary infrastructure into CRITICAL risk.
    baseline_exposure_ports = {
        80, 443, 631, 9100,
    }

    current_severity_points = {
        "CRITICAL": 20,
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3,
        "INFO": 0,
    }

    port_behavior_by_asset = current_port_behavior_risk_by_asset(
        connection,
        scope=scope,
        lookback=5,
        limit=500,
    )

    rows = []

    for asset in asset_rows:
        asset_key = asset["asset_key"]
        record = risk_subject_record(asset_key)

        record["current_scan_id"] = scan_id
        record["risk_scope"] = "current"
        record["ip_address"] = asset["ip_address"]
        record["mac_address"] = asset["mac_address"]
        record["identity_confidence"] = asset["identity_confidence"]
        record["identity_source"] = asset["identity_source"]
        record["identity_class"] = asset["identity_class"]
        record["device_type"] = asset["device_type"]
        record["classification"] = asset["classification_primary_type"]
        record["classification_confidence"] = int(asset["classification_confidence"] or 0)
        record["classification_decision"] = asset["classification_decision"]
        record["classification_siem_action"] = asset["classification_siem_action"]

        score = 0
        asset_services = services.get(asset_key, [])
        asset_findings = findings.get(asset_key)

        severity = str(asset["severity"] or "INFO").upper()
        severity_points = current_severity_points.get(severity, 0)

        if severity_points:
            score += severity_points
            risk_add_reason(
                record["reasons"],
                f"Current asset severity {severity}: +{severity_points}",
            )

        asset_score = safe_int(asset["score"]) or 0

        if asset_score > 0:
            points = min(18, max(1, asset_score // 2))
            score += points
            risk_add_reason(record["reasons"], f"Current NetSniper score {asset_score}: +{points}")

        finding_count = 0
        max_finding_score = 0

        if asset_findings is not None:
            finding_count = int(asset_findings["finding_count"] or 0)
            max_finding_score = safe_int(asset_findings["max_score"]) or 0

            if finding_count:
                points = min(12, finding_count * 2)
                score += points
                risk_add_reason(record["reasons"], f"{finding_count} current finding(s): +{points}")

            if max_finding_score:
                points = min(10, max_finding_score)
                score += points
                risk_add_reason(record["reasons"], f"Max current finding score {max_finding_score}: +{points}")

        open_ports = []
        signal_ports = []
        baseline_ports = []

        for service in asset_services:
            port = int(service["port"] or 0)
            protocol = str(service["protocol"] or "tcp").lower()
            open_ports.append(f"{protocol}/{port}")

            if port in high_signal_ports:
                signal_ports.append(f"{protocol}/{port}")
            elif port in baseline_exposure_ports:
                baseline_ports.append(f"{protocol}/{port}")

        if signal_ports:
            points = min(30, len(signal_ports) * 10)
            score += points
            risk_add_reason(
                record["reasons"],
                f"Current high-signal exposed service(s) {', '.join(signal_ports[:6])}: +{points}",
            )

        if baseline_ports:
            points = min(6, len(baseline_ports))
            score += points
            risk_add_reason(
                record["reasons"],
                f"Current baseline management/printing exposure {', '.join(baseline_ports[:6])}: +{points}",
            )

        port_behavior_rows = port_behavior_by_asset.get(asset_key, [])
        port_behavior_points = 0

        for behavior_row in port_behavior_rows:
            points, reason = port_behavior_risk_points(behavior_row)

            if points <= 0:
                continue

            remaining = max(0, 20 - port_behavior_points)
            applied_points = min(points, remaining)

            if applied_points <= 0:
                break

            port_behavior_points += applied_points

            if applied_points != points:
                reason = reason.rsplit(":+", 1)[0] if ":+ " in reason else reason
                reason = f"MAC-port behavior contribution capped: +{applied_points}"

            risk_add_reason(record["reasons"], reason)

        if port_behavior_points:
            score += port_behavior_points

        record["port_behavior"] = port_behavior_rows[:10]
        record["port_behavior_points"] = port_behavior_points

        classification_action = str(asset["classification_siem_action"] or "").lower()
        classification_decision = str(asset["classification_decision"] or "").lower()
        classification_type = str(asset["classification_primary_type"] or "Unknown")
        contradiction_count = int(asset["classification_contradiction_count"] or 0)

        if classification_action == "alert_eligible":
            score += 5
            risk_add_reason(record["reasons"], "Current classification is alert eligible: +5")
        elif classification_action == "review_queue":
            score += 4
            risk_add_reason(record["reasons"], "Current classification is in review queue: +4")

        if contradiction_count:
            points = min(20, contradiction_count * 10)
            score += points
            risk_add_reason(record["reasons"], f"Current classification contradiction(s): +{points}")

        unknown_with_services = (
            bool(asset_services)
            and classification_type in {"", "Unknown", "Unknown / Ambiguous"}
            and classification_decision in {"", "unknown", "possible"}
        )

        if unknown_with_services:
            score += 8
            risk_add_reason(record["reasons"], "Current unknown asset has exposed service(s): +8")

        asset_ip = str(asset["ip_address"] or "")
        asset_mac = str(asset["mac_address"] or "").lower()

        for alert in open_alert_rows:
            subject = str(alert["subject_key"] or "")
            subject_lower = subject.lower()

            if (
                subject == asset_key
                or subject.startswith(asset_key)
                or (asset_ip and asset_ip in subject)
                or (asset_mac and asset_mac in subject_lower)
            ):
                record["open_alerts"] += 1
                severity = str(alert["severity"] or "INFO").upper()
                risk_add_reason(record["reasons"], f"Open current-context {severity} alert present")

        if record["open_alerts"]:
            points = min(50, record["open_alerts"] * 25)
            score += points
            risk_add_reason(record["reasons"], f"{record['open_alerts']} open alert(s): +{points}")

        annotation_match = fetch_risk_annotation(connection, asset_key)

        if annotation_match is not None:
            annotation, matched_key = annotation_match
            record["annotation_key"] = matched_key
            record["owner"] = annotation["owner"]
            record["role"] = annotation["role"]
            record["criticality"] = annotation["criticality"]
            record["notes"] = annotation["notes"]

            criticality = str(annotation["criticality"] or "").upper()
            criticality_points = RISK_CRITICALITY_POINTS.get(criticality, 0)

            if criticality_points:
                score += criticality_points
                risk_add_reason(
                    record["reasons"],
                    f"Asset criticality {criticality}: +{criticality_points}",
                )

        record["score"] = min(100, score)
        record["level"] = risk_level(record["score"])
        record["open_ports"] = open_ports
        record["current_service_count"] = len(asset_services)
        record["current_finding_count"] = finding_count
        record["high_signal_ports"] = signal_ports
        record["baseline_exposure_ports"] = baseline_ports
        record["recommended_actions"] = risk_role_recommended_actions(record)

        actionable = (
            record["open_alerts"] > 0
            or bool(signal_ports)
            or unknown_with_services
            or contradiction_count > 0
            or classification_action in {"alert_eligible", "review_queue"}
            or finding_count > 0
            or port_behavior_points > 0
        )

        if actionable and record["score"] > 0:
            rows.append(record)

    rows = sorted(
        rows,
        key=lambda row: (
            row["score"],
            row["open_alerts"],
            len(row.get("high_signal_ports", [])),
            row.get("current_finding_count", 0),
            row["subject_key"],
        ),
        reverse=True,
    )

    if limit is not None:
        rows = rows[:limit]

    return rows



def dashboard_port_behavior_payload(connection, limit, scope=None, lookback=5):
    try:
        return mac_port_behavior_rows(
            connection,
            limit=limit,
            scope=scope,
            lookback=lookback,
        )
    except Exception as exc:
        return [
            {
                "behavior": "PORT_BEHAVIOR_ERROR",
                "severity": "INFO",
                "mac_identity": "-",
                "asset_key": "-",
                "ip_address": "-",
                "device_type": "Unknown",
                "port_key": "-",
                "current_state": "UNKNOWN",
                "baseline_state": "UNKNOWN",
                "seen_count": 0,
                "missing_count": 0,
                "transition_count": 0,
                "latest_scan_id": "-",
                "reason": f"MAC-port behavior unavailable: {exc}",
            }
        ]

def dashboard_current_risk_payload(connection, limit, scope=None):
    try:
        return build_current_risk_register(connection, limit, scope=scope)
    except Exception as exc:
        return [
            {
                "subject_key": "current-risk-error",
                "score": 0,
                "level": "INFO",
                "risk_scope": "current",
                "reasons": [f"Current risk unavailable: {exc}"],
            }
        ]




def investigation_center_add_unique(items, value):
    value = str(value or "").strip()

    if value and value not in items:
        items.append(value)


def investigation_center_severity_points(severity):
    severity = str(severity or "INFO").upper()

    return {
        "CRITICAL": 45,
        "HIGH": 30,
        "MEDIUM": 15,
        "LOW": 5,
        "INFO": 0,
    }.get(severity, 0)


def investigation_center_item(subject_key):
    subject_key = str(subject_key or "").strip() or "unknown-subject"

    return {
        "investigation_id": subject_key,
        "subject_key": subject_key,
        "priority_score": 0,
        "priority_level": "INFO",
        "risk_score": 0,
        "risk_level": "INFO",
        "ip_address": None,
        "mac_address": None,
        "hostname": None,
        "vendor": None,
        "device_type": None,
        "classification": None,
        "classification_decision": None,
        "classification_confidence": 0,
        "identity_confidence": None,
        "owner": None,
        "role": None,
        "criticality": None,
        "triggers": [],
        "reasons": [],
        "recommended_actions": [],
        "open_alerts": 0,
        "recent_events": 0,
        "port_behavior_count": 0,
        "current_finding_count": 0,
        "risk": None,
        "port_behavior": [],
        "alerts": [],
        "events": [],
        "primary_reason": None,
        "recommended_action": None,
    }


def investigation_center_merge_identity(item, row):
    mappings = [
        ("ip_address", "ip_address"),
        ("ip", "ip_address"),
        ("identity_ip_address", "ip_address"),
        ("mac_address", "mac_address"),
        ("mac", "mac_address"),
        ("identity_mac_address", "mac_address"),
        ("hostname", "hostname"),
        ("identity_hostname", "hostname"),
        ("vendor", "vendor"),
        ("identity_vendor", "vendor"),
        ("device_type", "device_type"),
        ("classification", "classification"),
        ("classification_primary_type", "classification"),
        ("classification_decision", "classification_decision"),
        ("classification_confidence", "classification_confidence"),
        ("identity_confidence", "identity_confidence"),
        ("owner", "owner"),
        ("role", "role"),
        ("criticality", "criticality"),
    ]

    for source_key, target_key in mappings:
        value = row.get(source_key) if isinstance(row, dict) else None

        if value not in {None, "", "-"} and not item.get(target_key):
            item[target_key] = value


def investigation_center_raise_priority(item, points):
    item["priority_score"] = min(
        100,
        max(
            int(item.get("priority_score") or 0),
            int(points or 0),
        ),
    )


def investigation_center_add_priority(item, points):
    item["priority_score"] = min(
        100,
        int(item.get("priority_score") or 0) + max(0, int(points or 0)),
    )



# v0.18 ticket workflow state model: persistent analyst status for investigation tickets.
TICKET_WORKFLOW_STATUSES = {"OPEN", "IN_REVIEW", "RESOLVED", "SUPPRESSED"}

TICKET_WORKFLOW_SCHEMA_SQL = (
    "CREATE TABLE IF NOT EXISTS investigation_ticket_state ("
    " ticket_key TEXT PRIMARY KEY,"
    " status TEXT NOT NULL DEFAULT 'OPEN',"
    " analyst TEXT,"
    " note TEXT,"
    " created_at TEXT NOT NULL,"
    " updated_at TEXT NOT NULL,"
    " resolved_at TEXT,"
    " suppressed_at TEXT"
    ");"
    " CREATE INDEX IF NOT EXISTS idx_investigation_ticket_state_status"
    " ON investigation_ticket_state(status);"
    " CREATE INDEX IF NOT EXISTS idx_investigation_ticket_state_updated_at"
    " ON investigation_ticket_state(updated_at);"
)


def ensure_investigation_ticket_state_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(TICKET_WORKFLOW_SCHEMA_SQL)


def normalize_ticket_workflow_status(status: str | None) -> str:
    normalized = str(status or "OPEN").strip().upper().replace("-", "_").replace(" ", "_")
    if normalized not in TICKET_WORKFLOW_STATUSES:
        raise DeltaAegisError(
            "invalid ticket status: "
            f"{status!r}. Expected one of: "
            + ", ".join(sorted(TICKET_WORKFLOW_STATUSES))
        )
    return normalized


def stable_ticket_key(subject_key: str | None) -> str:
    key = str(subject_key or "").strip()
    if not key:
        raise DeltaAegisError("ticket subject key is required")
    if key.lower().startswith("mac:"):
        return "mac:" + key[4:].lower()
    if key.lower().startswith("ip:"):
        return "ip:" + key[3:]
    if key.lower().startswith("asset:"):
        return "asset:" + key[6:]
    return key


def ticket_state_default(ticket_key: str) -> dict[str, Any]:
    return {
        "ticket_key": ticket_key,
        "ticket_status": "OPEN",
        "ticket_analyst": None,
        "ticket_note": None,
        "ticket_created_at": None,
        "ticket_updated_at": None,
        "ticket_resolved_at": None,
        "ticket_suppressed_at": None,
    }


def ticket_state_record_from_row(row) -> dict[str, Any]:
    ticket_key = str(row["ticket_key"])
    return {
        "ticket_key": ticket_key,
        "ticket_status": str(row["status"] or "OPEN").upper(),
        "ticket_analyst": row["analyst"],
        "ticket_note": row["note"],
        "ticket_created_at": row["created_at"],
        "ticket_updated_at": row["updated_at"],
        "ticket_resolved_at": row["resolved_at"],
        "ticket_suppressed_at": row["suppressed_at"],
    }


def get_ticket_state(connection: sqlite3.Connection, subject_key: str | None) -> dict[str, Any]:
    ensure_investigation_ticket_state_schema(connection)
    ticket_key = stable_ticket_key(subject_key)
    row = connection.execute(
        "SELECT ticket_key, status, analyst, note, created_at, updated_at, resolved_at, suppressed_at "
        "FROM investigation_ticket_state WHERE ticket_key = ?",
        (ticket_key,),
    ).fetchone()
    if row is None:
        return ticket_state_default(ticket_key)
    return ticket_state_record_from_row(row)



def ticket_history_record_from_row(row) -> dict[str, Any]:
    return {
        "history_id": row["history_id"],
        "ticket_key": row["ticket_key"],
        "previous_status": row["previous_status"],
        "new_status": row["new_status"],
        "analyst": row["analyst"],
        "note": row["note"],
        "created_at": row["created_at"],
    }


def add_ticket_history_event(
    connection: sqlite3.Connection,
    ticket_key: str,
    previous_status: str | None,
    new_status: str,
    analyst: str | None,
    note: str | None,
    created_at: str,
) -> None:
    ensure_investigation_ticket_state_schema(connection)
    connection.execute(
        "INSERT INTO investigation_ticket_history ("
        " ticket_key, previous_status, new_status, analyst, note, created_at"
        ") VALUES (?, ?, ?, ?, ?, ?)",
        (ticket_key, previous_status, new_status, analyst, note, created_at),
    )


def list_ticket_history(
    connection: sqlite3.Connection,
    subject_key: str | None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    ensure_investigation_ticket_state_schema(connection)
    ticket_key = stable_ticket_key(subject_key)
    safe_limit = max(1, int(limit or 20))
    rows = connection.execute(
        "SELECT history_id, ticket_key, previous_status, new_status, analyst, note, created_at "
        "FROM investigation_ticket_history "
        "WHERE ticket_key = ? "
        "ORDER BY created_at DESC, history_id DESC "
        "LIMIT ?",
        (ticket_key, safe_limit),
    ).fetchall()
    return [ticket_history_record_from_row(row) for row in rows]



def set_ticket_state(
    connection: sqlite3.Connection,
    subject_key: str | None,
    status: str,
    analyst: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    ensure_investigation_ticket_state_schema(connection)
    ticket_key = stable_ticket_key(subject_key)
    previous_state = get_ticket_state(connection, ticket_key)
    normalized_status = normalize_ticket_workflow_status(status)
    now = utc_now()
    cleaned_analyst = str(analyst).strip() if analyst is not None and str(analyst).strip() else None
    cleaned_note = str(note).strip() if note is not None and str(note).strip() else None

    if previous_state.get("ticket_status") == normalized_status:
        return previous_state

    resolved_at = now if normalized_status == "RESOLVED" else None
    suppressed_at = now if normalized_status == "SUPPRESSED" else None

    connection.execute(
        "INSERT INTO investigation_ticket_state ("
        " ticket_key, status, analyst, note, created_at, updated_at, resolved_at, suppressed_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(ticket_key) DO UPDATE SET "
        " status = excluded.status,"
        " analyst = COALESCE(excluded.analyst, investigation_ticket_state.analyst),"
        " note = COALESCE(excluded.note, investigation_ticket_state.note),"
        " updated_at = excluded.updated_at,"
        " resolved_at = excluded.resolved_at,"
        " suppressed_at = excluded.suppressed_at",
        (
            ticket_key,
            normalized_status,
            cleaned_analyst,
            cleaned_note,
            now,
            now,
            resolved_at,
            suppressed_at,
        ),
    )
    add_ticket_history_event(
        connection,
        ticket_key,
        previous_state.get("ticket_status"),
        normalized_status,
        cleaned_analyst,
        cleaned_note,
        now,
    )
    connection.commit()
    return get_ticket_state(connection, ticket_key)


def list_ticket_states(
    connection: sqlite3.Connection,
    status: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    ensure_investigation_ticket_state_schema(connection)
    safe_limit = max(1, int(limit or 50))
    params: list[Any] = []
    where = ""

    if status:
        where = "WHERE status = ?"
        params.append(normalize_ticket_workflow_status(status))

    params.append(safe_limit)
    rows = connection.execute(
        f"SELECT ticket_key, status, analyst, note, created_at, updated_at, resolved_at, suppressed_at "
        f"FROM investigation_ticket_state {where} ORDER BY updated_at DESC, ticket_key ASC LIMIT ?",
        params,
    ).fetchall()
    return [ticket_state_record_from_row(row) for row in rows]


def apply_ticket_states_to_rows(
    connection: sqlite3.Connection,
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    ensure_investigation_ticket_state_schema(connection)

    if not rows:
        return rows

    ticket_keys = []
    for row in rows:
        try:
            key = stable_ticket_key(row.get("subject_key"))
        except DeltaAegisError:
            key = ""
        row["ticket_key"] = key
        if key:
            ticket_keys.append(key)

    state_by_key: dict[str, dict[str, Any]] = {}
    if ticket_keys:
        unique_ticket_keys = list(dict.fromkeys(ticket_keys))
        placeholders = ",".join("?" for _ in unique_ticket_keys)
        db_rows = connection.execute(
            f"SELECT ticket_key, status, analyst, note, created_at, updated_at, resolved_at, suppressed_at "
            f"FROM investigation_ticket_state WHERE ticket_key IN ({placeholders})",
            unique_ticket_keys,
        ).fetchall()
        state_by_key = {
            str(db_row["ticket_key"]): ticket_state_record_from_row(db_row)
            for db_row in db_rows
        }

    for row in rows:
        key = str(row.get("ticket_key") or "")
        state = state_by_key.get(key, ticket_state_default(key))
        row.update(state)

    return rows


def investigation_center_rows(connection, limit=25, scope=None):
    current_risk_rows = build_current_risk_register(
        connection,
        limit=50,
        scope=scope,
    )

    port_behavior_rows = mac_port_behavior_rows(
        connection,
        limit=50,
        scope=scope,
        lookback=5,
    )

    alert_rows = dashboard_alerts_payload(
        connection,
        limit=50,
        scope=scope,
    )

    event_rows = dashboard_events_payload(
        connection,
        limit=50,
        scope=scope,
    )

    items = {}

    def ensure(subject_key):
        subject_key = str(subject_key or "").strip()

        if not subject_key:
            return None

        if subject_key not in items:
            items[subject_key] = investigation_center_item(subject_key)

        return items[subject_key]

    for row in current_risk_rows:
        subject_key = row.get("subject_key")
        item = ensure(subject_key)

        if item is None:
            continue

        score = risk_int(row.get("score"), 0)
        investigation_center_raise_priority(item, score)
        investigation_center_add_unique(item["triggers"], "CURRENT_RISK")
        investigation_center_merge_identity(item, row)

        item["risk_score"] = score
        item["risk_level"] = row.get("level") or "INFO"
        item["risk"] = {
            "score": score,
            "level": row.get("level") or "INFO",
            "open_alerts": row.get("open_alerts", 0),
            "current_finding_count": row.get("current_finding_count", 0),
            "high_signal_ports": row.get("high_signal_ports") or [],
            "baseline_exposure_ports": row.get("baseline_exposure_ports") or [],
        }

        item["open_alerts"] = max(
            int(item.get("open_alerts") or 0),
            int(row.get("open_alerts") or 0),
        )
        item["current_finding_count"] = max(
            int(item.get("current_finding_count") or 0),
            int(row.get("current_finding_count") or 0),
        )

        for reason in (row.get("reasons") or [])[:4]:
            investigation_center_add_unique(item["reasons"], reason)

        for action in (row.get("recommended_actions") or [])[:3]:
            investigation_center_add_unique(item["recommended_actions"], action)

    for row in port_behavior_rows:
        subject_key = row.get("asset_key") or row.get("mac_identity")
        item = ensure(subject_key)

        if item is None:
            continue

        severity = str(row.get("severity") or "INFO").upper()
        behavior = str(row.get("behavior") or "PORT_BEHAVIOR").upper()
        points = investigation_center_severity_points(severity)

        if behavior == "UNEXPECTED_PORT_OPENED":
            points += 10
        elif behavior == "PORT_FLAPPING":
            points += 5

        investigation_center_add_priority(item, points)
        investigation_center_add_unique(item["triggers"], "PORT_BEHAVIOR")
        investigation_center_merge_identity(item, row)

        item["port_behavior_count"] += 1
        item["port_behavior"].append(
            {
                "behavior": row.get("behavior"),
                "severity": row.get("severity"),
                "port_key": row.get("port_key"),
                "current_state": row.get("current_state"),
                "seen_count": row.get("seen_count"),
                "missing_count": row.get("missing_count"),
                "transition_count": row.get("transition_count"),
                "reason": row.get("reason"),
            }
        )

        investigation_center_add_unique(
            item["reasons"],
            row.get("reason") or f"MAC-port behavior detected on {row.get('port_key')}.",
        )
        investigation_center_add_unique(
            item["recommended_actions"],
            "Confirm whether the new or volatile MAC-port behavior is expected for this device.",
        )

    for row in alert_rows:
        status = str(row.get("status") or "").upper()

        if status != "OPEN":
            continue

        subject_key = row.get("subject_key")
        item = ensure(subject_key)

        if item is None:
            continue

        severity = str(row.get("severity") or "INFO").upper()
        investigation_center_add_priority(
            item,
            investigation_center_severity_points(severity),
        )
        investigation_center_add_unique(item["triggers"], "OPEN_ALERT")
        investigation_center_merge_identity(item, row)

        item["open_alerts"] += 1
        item["alerts"].append(
            {
                "alert_id": row.get("alert_id"),
                "severity": row.get("severity"),
                "event_type": row.get("event_type"),
                "summary": row.get("summary"),
                "last_seen_at": row.get("last_seen_at"),
            }
        )

        investigation_center_add_unique(
            item["reasons"],
            row.get("summary") or f"Open {severity} alert is present.",
        )
        investigation_center_add_unique(
            item["recommended_actions"],
            "Review the open alert and acknowledge, suppress, or resolve it with a clear reason.",
        )

    for row in event_rows:
        subject_key = row.get("subject_key")
        item = ensure(subject_key)

        if item is None:
            continue

        severity = str(row.get("severity") or "INFO").upper()
        investigation_center_add_priority(
            item,
            max(3, investigation_center_severity_points(severity) // 2),
        )
        investigation_center_add_unique(item["triggers"], "RECENT_EVENT")
        investigation_center_merge_identity(item, row)

        item["recent_events"] += 1

        if len(item["events"]) < 5:
            item["events"].append(
                {
                    "event_id": row.get("event_id"),
                    "severity": row.get("severity"),
                    "event_type": row.get("event_type"),
                    "summary": row.get("summary"),
                    "created_at": row.get("created_at"),
                }
            )

        investigation_center_add_unique(
            item["reasons"],
            row.get("summary") or f"Recent {severity} delta event is present.",
        )

    rows = []

    for item in items.values():
        item["priority_score"] = min(100, int(item.get("priority_score") or 0))
        item["priority_level"] = risk_level(item["priority_score"])
        item["primary_reason"] = (
            item["reasons"][0]
            if item["reasons"]
            else "Review this subject using current risk, alerts, events, and asset context."
        )
        item["recommended_action"] = (
            item["recommended_actions"][0]
            if item["recommended_actions"]
            else "Open the asset detail view and verify the observed network behavior."
        )

        rows.append(item)

    rows.sort(
        key=lambda row: (
            int(row.get("priority_score") or 0),
            int(row.get("open_alerts") or 0),
            int(row.get("port_behavior_count") or 0),
            int(row.get("recent_events") or 0),
            str(row.get("subject_key") or ""),
        ),
        reverse=True,
    )

    return rows[:limit]



# v0.17 ticket signal tuning: separate baseline inventory context from meaningful change.
TICKET_EXPECTED_PRINTER_PORTS = {80, 443, 515, 631, 9100}
TICKET_HIGH_SIGNAL_PORTS = {
    21, 22, 23, 139, 445, 1433, 1521, 2375, 2376, 3306, 3389,
    5000, 5432, 5555, 5900, 5985, 5986, 6379, 6443, 7547, 8000,
    8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 9443, 10250,
    10255, 27017,
}


def ticket_role_text(row):
    values = [
        row.get("device_type"),
        row.get("classification"),
        row.get("role"),
    ]

    return " ".join(str(value or "") for value in values).lower()


def ticket_is_printer_like(row):
    text = ticket_role_text(row)

    return (
        "printer" in text
        or "multifunction" in text
        or "print server" in text
    )


def ticket_port_numbers(row):
    ports = set()

    for item in row.get("open_ports") or []:
        value = str(item or "")

        if "/" in value:
            value = value.rsplit("/", 1)[-1]

        try:
            ports.add(int(value))
        except (TypeError, ValueError):
            continue

    return ports


def ticket_has_meaningful_change(row):
    triggers = {
        str(trigger or "").upper()
        for trigger in row.get("triggers") or []
    }

    if triggers & {"PORT_BEHAVIOR", "RECENT_EVENT"}:
        return True

    if risk_int(row.get("recent_events"), 0) > 0:
        return True

    if risk_int(row.get("port_behavior_count"), 0) > 0:
        return True

    return False


def ticket_has_high_signal_exposure(row):
    ports = ticket_port_numbers(row)

    if ports & TICKET_HIGH_SIGNAL_PORTS:
        return True

    reason_text = " ".join(str(reason or "") for reason in row.get("reasons") or [])
    reason_text += " " + str(row.get("primary_reason") or "")
    reason_text = reason_text.lower()

    return any(
        token in reason_text
        for token in [
            "telnet",
            "smb",
            "rdp",
            "database",
            "docker",
            "kubernetes",
            "container",
            "high-signal",
            "contradict",
        ]
    )


def ticket_expected_printer_baseline(row):
    if not ticket_is_printer_like(row):
        return False

    if ticket_has_meaningful_change(row):
        return False

    if ticket_has_high_signal_exposure(row):
        return False

    ports = ticket_port_numbers(row)

    if ports and not ports.issubset(TICKET_EXPECTED_PRINTER_PORTS):
        return False

    triggers = {
        str(trigger or "").upper()
        for trigger in row.get("triggers") or []
    }

    return not (triggers & {"PORT_BEHAVIOR", "RECENT_EVENT"})


def tune_investigation_center_ticket_signal(row):
    tuned = dict(row)
    original_score = risk_int(tuned.get("priority_score"), 0)
    tuned["raw_priority_score"] = original_score

    if ticket_expected_printer_baseline(tuned):
        new_score = min(original_score, 34)

        tuned["priority_score"] = new_score
        tuned["priority_level"] = risk_level(new_score)
        tuned["ticket_signal_state"] = "BASELINE_CONTEXT"
        tuned["signal_tuned"] = True
        tuned["signal_tuning_reason"] = (
            "Known printer-like asset has only baseline inventory/current-risk context; "
            "no recent event, high-signal exposure, or MAC-port behavior change was detected."
        )
        tuned["primary_reason"] = tuned["signal_tuning_reason"]

        action = (
            "Treat this as inventory context unless ownership, location, or expected "
            "printer services are unknown; investigate only if new services or behavior changes appear."
        )

        tuned["recommended_action"] = action

        triggers = [
            str(trigger or "").upper()
            for trigger in tuned.get("triggers") or []
        ]

        if "BASELINE_CONTEXT" not in triggers:
            triggers.append("BASELINE_CONTEXT")

        tuned["triggers"] = triggers

    elif ticket_is_printer_like(tuned) and ticket_has_meaningful_change(tuned) and not ticket_has_high_signal_exposure(tuned):
        new_score = min(original_score, 74)

        tuned["priority_score"] = new_score
        tuned["priority_level"] = risk_level(new_score)
        tuned["ticket_signal_state"] = "MEANINGFUL_CHANGE"
        tuned["signal_tuned"] = True
        tuned["signal_tuning_reason"] = (
            "Printer-like asset has a behavior/event trigger, but no high-signal remote-access "
            "or file-sharing exposure was detected."
        )

        if not str(tuned.get("primary_reason") or "").strip():
            tuned["primary_reason"] = tuned["signal_tuning_reason"]

    else:
        tuned["ticket_signal_state"] = "ACTIONABLE"
        tuned["signal_tuned"] = False

    return operator_triage_enrich_row(tuned)


def tune_investigation_center_ticket_signals(rows):
    tuned_rows = [
        tune_investigation_center_ticket_signal(row)
        for row in rows or []
    ]

    tuned_rows.sort(
        key=lambda row: (
            risk_int(row.get("priority_score"), 0),
            risk_int(row.get("open_alerts"), 0),
            risk_int(row.get("recent_events"), 0),
            risk_int(row.get("port_behavior_count"), 0),
            str(row.get("subject_key") or ""),
        ),
        reverse=True,
    )

    return tuned_rows



TRIAGE_BUCKETS = [
    "CHANGED_SINCE_REVIEW",
    "NEEDS_REVIEW",
    "NEEDS_CONTEXT",
    "STALE_CLOSED",
    "BASELINE_CONTEXT",
    "MONITOR",
]


def operator_triage_parse_datetime(value):
    if value in (None, ""):
        return None

    from datetime import datetime as _datetime
    from datetime import timezone as _timezone

    if isinstance(value, _datetime):
        parsed = value
    else:
        text = str(value).strip()
        if not text:
            return None
        try:
            parsed = _datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_timezone.utc)

    return parsed.astimezone(_timezone.utc)


def operator_triage_isoformat(value):
    parsed = operator_triage_parse_datetime(value)
    if parsed is None:
        return None
    return parsed.isoformat()


def operator_triage_latest_datetime(row, keys):
    values = []

    for key in keys:
        parsed = operator_triage_parse_datetime(row.get(key))
        if parsed is not None:
            values.append(parsed)

    if not values:
        return None

    return max(values)


def operator_triage_age_hours(value, now=None):
    from datetime import datetime as _datetime
    from datetime import timezone as _timezone

    parsed = operator_triage_parse_datetime(value)
    if parsed is None:
        return None

    current = operator_triage_parse_datetime(now)
    if current is None:
        current = _datetime.now(_timezone.utc)

    seconds = max(0.0, (current - parsed).total_seconds())
    return round(seconds / 3600.0, 2)


def operator_triage_has_value(row, keys):
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            if str(value).strip() not in {"", "-", "UNKNOWN", "None", "none", "null"}:
                return True
    return False


def operator_triage_bool(value):
    return bool(value)


def operator_triage_enrich_row(row, now=None):
    enriched = dict(row or {})

    status = str(enriched.get("ticket_status") or "OPEN").upper()
    signal = str(enriched.get("ticket_signal_state") or enriched.get("ticket_signal") or "ACTIONABLE").upper()

    priority_score = risk_int(
        enriched.get("priority_score", enriched.get("score", 0)),
        0,
    )
    priority_score = max(0, min(100, int(priority_score or 0)))

    evidence_keys = [
        "latest_alert_at",
        "latest_event_at",
        "identity_last_seen_at",
        "last_seen_at",
        "observed_at",
        "created_at",
    ]
    review_keys = [
        "ticket_updated_at",
        "ticket_resolved_at",
        "ticket_suppressed_at",
        "status_updated_at",
        "reviewed_at",
    ]

    last_evidence_at = operator_triage_latest_datetime(enriched, evidence_keys)
    last_review_at = operator_triage_latest_datetime(enriched, review_keys)

    evidence_age_hours = operator_triage_age_hours(last_evidence_at, now=now)
    changed_since_review = (
        last_evidence_at is not None
        and last_review_at is not None
        and last_evidence_at > last_review_at
    )

    missing_owner = not operator_triage_has_value(
        enriched,
        ["owner", "asset_owner", "annotation_owner"],
    )
    missing_context = not (
        operator_triage_has_value(enriched, ["role", "asset_role", "annotation_role"])
        and operator_triage_has_value(enriched, ["criticality", "asset_criticality"])
    )

    urgency_score = priority_score
    reasons = []

    if changed_since_review:
        urgency_score += 25
        reasons.append("Evidence changed after the last recorded ticket review.")

    if signal == "MEANINGFUL_CHANGE":
        urgency_score += 15
        reasons.append("Ticket signal is MEANINGFUL_CHANGE.")
    elif signal == "ACTIONABLE":
        urgency_score += 8
        reasons.append("Ticket signal is ACTIONABLE.")
    elif signal == "BASELINE_CONTEXT":
        reasons.append("Ticket currently appears to be baseline context.")

    if status in {"OPEN", "IN_REVIEW"}:
        urgency_score += 8
        reasons.append(f"Workflow status is {status}.")
    elif status in {"RESOLVED", "SUPPRESSED", "CLOSED"}:
        reasons.append(f"Workflow status is {status}.")

    if missing_owner:
        urgency_score += 5
        reasons.append("Asset owner is missing.")

    if missing_context:
        urgency_score += 5
        reasons.append("Asset role or criticality context is missing.")

    urgency_score = max(0, min(100, int(urgency_score)))

    if urgency_score >= 85:
        urgency_label = "IMMEDIATE"
    elif urgency_score >= 65:
        urgency_label = "HIGH"
    elif urgency_score >= 35:
        urgency_label = "NORMAL"
    else:
        urgency_label = "LOW"

    if changed_since_review:
        bucket = "CHANGED_SINCE_REVIEW"
    elif status in {"OPEN", "IN_REVIEW"} and signal in {"MEANINGFUL_CHANGE", "ACTIONABLE"}:
        bucket = "NEEDS_REVIEW"
    elif status in {"OPEN", "IN_REVIEW"} and (missing_owner or missing_context):
        bucket = "NEEDS_CONTEXT"
    elif status in {"RESOLVED", "SUPPRESSED", "CLOSED"} and evidence_age_hours is not None and evidence_age_hours >= 168:
        bucket = "STALE_CLOSED"
    elif signal == "BASELINE_CONTEXT":
        bucket = "BASELINE_CONTEXT"
    else:
        bucket = "MONITOR"

    enriched["triage_bucket"] = bucket
    enriched["triage_urgency_score"] = urgency_score
    enriched["triage_urgency_label"] = urgency_label
    enriched["triage_missing_owner"] = bool(missing_owner)
    enriched["triage_missing_context"] = bool(missing_context)
    enriched["triage_changed_since_review"] = bool(changed_since_review)
    enriched["triage_last_evidence_at"] = (
        last_evidence_at.isoformat() if last_evidence_at is not None else None
    )
    enriched["triage_last_review_at"] = (
        last_review_at.isoformat() if last_review_at is not None else None
    )
    enriched["triage_evidence_age_hours"] = evidence_age_hours
    enriched["triage_status"] = bucket
    enriched["triage_reasons"] = reasons[:8]

    return enriched


def operator_triage_enrich_rows(rows, now=None):
    return [
        operator_triage_enrich_row(row, now=now)
        for row in list(rows or [])
    ]


def operator_triage_summary(rows):
    summary = {
        "total": 0,
        "changed_since_review": 0,
        "needs_review": 0,
        "needs_context": 0,
        "stale_closed": 0,
        "baseline_context": 0,
        "monitor": 0,
        "missing_owner": 0,
        "missing_context": 0,
        "immediate": 0,
        "high": 0,
        "normal": 0,
        "low": 0,
    }

    for row in list(rows or []):
        triaged = row if row.get("triage_bucket") else operator_triage_enrich_row(row)
        bucket = str(triaged.get("triage_bucket") or "MONITOR").upper()
        label = str(triaged.get("triage_urgency_label") or "LOW").upper()

        summary["total"] += 1

        if bucket == "CHANGED_SINCE_REVIEW":
            summary["changed_since_review"] += 1
        elif bucket == "NEEDS_REVIEW":
            summary["needs_review"] += 1
        elif bucket == "NEEDS_CONTEXT":
            summary["needs_context"] += 1
        elif bucket == "STALE_CLOSED":
            summary["stale_closed"] += 1
        elif bucket == "BASELINE_CONTEXT":
            summary["baseline_context"] += 1
        else:
            summary["monitor"] += 1

        if triaged.get("triage_missing_owner"):
            summary["missing_owner"] += 1

        if triaged.get("triage_missing_context"):
            summary["missing_context"] += 1

        if label == "IMMEDIATE":
            summary["immediate"] += 1
        elif label == "HIGH":
            summary["high"] += 1
        elif label == "NORMAL":
            summary["normal"] += 1
        else:
            summary["low"] += 1

    return summary


TRIAGE_URGENCY_LABELS = [
    "IMMEDIATE",
    "HIGH",
    "NORMAL",
    "LOW",
]


def normalize_triage_bucket_filter(value):
    if value in (None, "", "ALL", "*"):
        return None

    normalized = str(value).strip().upper().replace("-", "_").replace(" ", "_")

    if normalized in set(TRIAGE_BUCKETS):
        return normalized

    return None


def normalize_triage_urgency_filter(value):
    if value in (None, "", "ALL", "*"):
        return None

    normalized = str(value).strip().upper().replace("-", "_").replace(" ", "_")

    if normalized in set(TRIAGE_URGENCY_LABELS):
        return normalized

    return None


def operator_triage_queue_sort_key(row):
    triaged = row if row.get("triage_bucket") else operator_triage_enrich_row(row)

    bucket_order = {
        "CHANGED_SINCE_REVIEW": 0,
        "NEEDS_REVIEW": 1,
        "NEEDS_CONTEXT": 2,
        "STALE_CLOSED": 3,
        "BASELINE_CONTEXT": 4,
        "MONITOR": 5,
    }
    urgency_order = {
        "IMMEDIATE": 0,
        "HIGH": 1,
        "NORMAL": 2,
        "LOW": 3,
    }

    bucket = str(triaged.get("triage_bucket") or "MONITOR").upper()
    urgency = str(triaged.get("triage_urgency_label") or "LOW").upper()

    return (
        bucket_order.get(bucket, 99),
        urgency_order.get(urgency, 99),
        -risk_int(triaged.get("triage_urgency_score"), 0),
        -risk_int(triaged.get("priority_score"), 0),
        str(triaged.get("subject_key") or ""),
    )


def filter_operator_triage_rows(rows, triage_bucket=None, triage_urgency=None):
    bucket_filter = normalize_triage_bucket_filter(triage_bucket)
    urgency_filter = normalize_triage_urgency_filter(triage_urgency)

    filtered = []

    for row in list(rows or []):
        triaged = row if row.get("triage_bucket") else operator_triage_enrich_row(row)
        bucket = str(triaged.get("triage_bucket") or "MONITOR").upper()
        urgency = str(triaged.get("triage_urgency_label") or "LOW").upper()

        if bucket_filter and bucket != bucket_filter:
            continue

        if urgency_filter and urgency != urgency_filter:
            continue

        filtered.append(triaged)

    return filtered


def operator_triage_filter_payload(
    ticket_status=None,
    ticket_signal=None,
    triage_bucket=None,
    triage_urgency=None,
):
    status_filter = normalize_ticket_status_filter(ticket_status)
    signal_filter = normalize_ticket_signal_filter(ticket_signal)
    triage_bucket_filter = normalize_triage_bucket_filter(triage_bucket)
    triage_urgency_filter = normalize_triage_urgency_filter(triage_urgency)
    bucket_filter = normalize_triage_bucket_filter(triage_bucket)
    urgency_filter = normalize_triage_urgency_filter(triage_urgency)

    return {
        "ticket_status": status_filter or "ALL",
        "ticket_signal": signal_filter or "ALL",
        "triage_bucket": triage_bucket_filter or "ALL",
        "triage_urgency": triage_urgency_filter or "ALL",
        "triage_bucket": bucket_filter or "ALL",
        "triage_urgency": urgency_filter or "ALL",
        "ticket_statuses": ["ALL", "OPEN", "IN_REVIEW", "RESOLVED", "SUPPRESSED"],
        "ticket_signals": ["ALL", "ACTIONABLE", "MEANINGFUL_CHANGE", "BASELINE_CONTEXT"],
        "triage_buckets": ["ALL"] + list(TRIAGE_BUCKETS),
        "triage_urgencies": ["ALL"] + list(TRIAGE_URGENCY_LABELS),
    }

def investigation_center_summary(rows):
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "with_open_alerts": 0,
        "with_port_behavior": 0,
        "baseline_context": 0,
        "meaningful_change": 0,
    }

    for row in rows or []:
        level = str(row.get("priority_level") or "INFO").upper()

        if level == "CRITICAL":
            summary["critical"] += 1
        elif level == "HIGH":
            summary["high"] += 1
        elif level == "MEDIUM":
            summary["medium"] += 1
        elif level == "LOW":
            summary["low"] += 1
        else:
            summary["info"] += 1

        if risk_int(row.get("open_alerts"), 0) > 0:
            summary["with_open_alerts"] += 1

        if risk_int(row.get("port_behavior_count"), 0) > 0:
            summary["with_port_behavior"] += 1

        state = str(row.get("ticket_signal_state") or "").upper()

        if state == "BASELINE_CONTEXT":
            summary["baseline_context"] += 1
        elif state == "MEANINGFUL_CHANGE":
            summary["meaningful_change"] += 1

    return summary



def investigation_center_workflow_summary(rows):
    summary = {
        "open": 0,
        "in_review": 0,
        "resolved": 0,
        "suppressed": 0,
    }

    for row in rows or []:
        status = str(row.get("ticket_status") or "OPEN").upper()

        if status == "IN_REVIEW":
            summary["in_review"] += 1
        elif status == "RESOLVED":
            summary["resolved"] += 1
        elif status == "SUPPRESSED":
            summary["suppressed"] += 1
        else:
            summary["open"] += 1

    return summary


def investigation_center_signal_summary(rows):
    summary = {
        "actionable": 0,
        "meaningful_change": 0,
        "baseline_context": 0,
    }

    for row in rows or []:
        state = str(row.get("ticket_signal_state") or "ACTIONABLE").upper()

        if state == "MEANINGFUL_CHANGE":
            summary["meaningful_change"] += 1
        elif state == "BASELINE_CONTEXT":
            summary["baseline_context"] += 1
        else:
            summary["actionable"] += 1

    return summary




TICKET_SIGNAL_FILTER_STATES = {
    "ACTIONABLE",
    "MEANINGFUL_CHANGE",
    "BASELINE_CONTEXT",
}


def normalize_ticket_status_filter(value):
    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    normalized = text.upper().replace("-", "_").replace(" ", "_")

    if normalized in {"ALL", "ANY", "*"}:
        return None

    return normalize_ticket_workflow_status(normalized)


def normalize_ticket_signal_filter(value):
    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    normalized = text.upper().replace("-", "_").replace(" ", "_")

    aliases = {
        "ALL": None,
        "ANY": None,
        "*": None,
        "MEANINGFUL": "MEANINGFUL_CHANGE",
        "MEANINGFUL_CHANGE": "MEANINGFUL_CHANGE",
        "BASELINE": "BASELINE_CONTEXT",
        "BASELINE_CONTEXT": "BASELINE_CONTEXT",
        "ACTION": "ACTIONABLE",
        "ACTIONABLE": "ACTIONABLE",
    }

    normalized = aliases.get(normalized, normalized)

    if normalized is None:
        return None

    if normalized not in TICKET_SIGNAL_FILTER_STATES:
        raise DeltaAegisError(
            "Invalid ticket signal filter. "
            "Use ACTIONABLE, MEANINGFUL_CHANGE, BASELINE_CONTEXT, or ALL."
        )

    return normalized


def filter_investigation_center_rows(
    rows,
    ticket_status=None,
    ticket_signal=None,
):
    status_filter = normalize_ticket_status_filter(ticket_status)
    signal_filter = normalize_ticket_signal_filter(ticket_signal)

    filtered = []

    for row in rows:
        if status_filter:
            row_status = str(row.get("ticket_status") or "OPEN").upper()
            if row_status != status_filter:
                continue

        if signal_filter:
            row_signal = str(row.get("ticket_signal_state") or "ACTIONABLE").upper()
            if row_signal != signal_filter:
                continue

        filtered.append(row)

    return filtered


def investigation_center_filter_payload(
    ticket_status=None,
    ticket_signal=None,
    triage_bucket=None,
    triage_urgency=None,
):
    status_filter = normalize_ticket_status_filter(ticket_status)
    signal_filter = normalize_ticket_signal_filter(ticket_signal)
    triage_bucket_filter = normalize_triage_bucket_filter(triage_bucket)
    triage_urgency_filter = normalize_triage_urgency_filter(triage_urgency)

    return {
        "ticket_status": status_filter or "ALL",
        "ticket_signal": signal_filter or "ALL",
        "triage_bucket": triage_bucket_filter or "ALL",
        "triage_urgency": triage_urgency_filter or "ALL",
        "ticket_statuses": ["ALL", "OPEN", "IN_REVIEW", "RESOLVED", "SUPPRESSED"],
        "ticket_signals": ["ALL", "ACTIONABLE", "MEANINGFUL_CHANGE", "BASELINE_CONTEXT"],
        "triage_buckets": ["ALL"] + list(TRIAGE_BUCKETS),
        "triage_urgencies": ["ALL"] + list(TRIAGE_URGENCY_LABELS),
    }

def dashboard_investigation_center_payload(
    connection,
    limit=25,
    scope=None,
    ticket_status=None,
    ticket_signal=None,
    triage_bucket=None,
    triage_urgency=None,
):
    requested_limit = risk_int(limit, 25)

    if requested_limit <= 0:
        requested_limit = 25

    try:
        filters = investigation_center_filter_payload(
            ticket_status=ticket_status,
            ticket_signal=ticket_signal,
            triage_bucket=triage_bucket,
            triage_urgency=triage_urgency,
        )
        has_filter = (
            filters["ticket_status"] != "ALL"
            or filters["ticket_signal"] != "ALL"
        )
        query_limit = max(requested_limit * (12 if has_filter else 4), 50)
        if has_filter:
            query_limit = max(query_limit, 200)
        rows = investigation_center_rows(
            connection,
            limit=query_limit,
            scope=scope,
        )
        rows = tune_investigation_center_ticket_signals(rows)
        rows = apply_ticket_states_to_rows(connection, rows)

        total_item_count = len(rows)
        workflow_summary = investigation_center_workflow_summary(rows)
        signal_summary = investigation_center_signal_summary(rows)

        rows = filter_investigation_center_rows(
            rows,
            ticket_status=filters["ticket_status"],
            ticket_signal=filters["ticket_signal"],
        )
        rows = filter_operator_triage_rows(
            rows,
            triage_bucket=filters["triage_bucket"],
            triage_urgency=filters["triage_urgency"],
        )
        rows = sorted(rows, key=operator_triage_queue_sort_key)
        rows = rows[:requested_limit]

        return {
            "available": True,
            "selected_scope": scope,
            "filters": filters,
            "item_count": len(rows),
            "total_item_count": total_item_count,
            "summary": investigation_center_summary(rows),
            "workflow_summary": workflow_summary,
            "signal_summary": signal_summary,
            "triage_summary": operator_triage_summary(rows),
            "view_workflow_summary": investigation_center_workflow_summary(rows),
            "view_signal_summary": investigation_center_signal_summary(rows),
            "items": rows,
        }
    except Exception as exc:
        return {
            "available": False,
            "selected_scope": scope,
            "filters": investigation_center_filter_payload(),
            "item_count": 0,
            "total_item_count": 0,
            "summary": investigation_center_summary([]),
            "workflow_summary": investigation_center_workflow_summary([]),
            "signal_summary": investigation_center_signal_summary([]),
            "view_workflow_summary": investigation_center_workflow_summary([]),
            "view_signal_summary": investigation_center_signal_summary([]),
            "items": [],
            "error": str(exc),
        }


def ticket_evidence_row_dict(row):
    if row is None:
        return {}

    if isinstance(row, dict):
        return dict(row)

    try:
        return {key: row[key] for key in row.keys()}
    except Exception:
        try:
            return dict(row)
        except Exception:
            return {}


def ticket_evidence_subject_tokens(subject_key):
    tokens = set()

    def add(value):
        if value is None:
            return

        text = str(value).strip()

        if not text:
            return

        lower = text.lower()
        tokens.add(lower)

        if lower.startswith("mac:"):
            tokens.add(lower[4:])
        elif lower.startswith("ip:"):
            tokens.add(lower[3:])

    add(subject_key)
    add(stable_ticket_key(subject_key))

    return tokens


def ticket_evidence_row_matches_subject(row, subject_key):
    tokens = ticket_evidence_subject_tokens(subject_key)

    if not tokens:
        return False

    row_dict = ticket_evidence_row_dict(row)

    for key in (
        "subject_key",
        "ticket_key",
        "asset_key",
        "identity_key",
        "mac_address",
        "ip_address",
        "ip",
        "mac",
    ):
        value = row_dict.get(key)

        if value is None:
            continue

        text = str(value).strip().lower()

        if text in tokens:
            return True

        if text.startswith("mac:") and text[4:] in tokens:
            return True

        if text.startswith("ip:") and text[3:] in tokens:
            return True

    return False


def ticket_evidence_filter_rows(rows, subject_key, limit=10):
    filtered = []

    for row in rows or []:
        row_dict = ticket_evidence_row_dict(row)

        if ticket_evidence_row_matches_subject(row_dict, subject_key):
            filtered.append(row_dict)

        if len(filtered) >= limit:
            break

    return filtered


def ticket_evidence_timeline_entry(category, source, summary, severity=None, timestamp=None, row=None):
    return {
        "category": category,
        "source": source,
        "severity": severity or "INFO",
        "timestamp": timestamp,
        "summary": summary or "-",
        "row": ticket_evidence_row_dict(row),
    }



def ticket_evidence_timeline_category_order():
    return [
        "current_risk",
        "alert",
        "delta_event",
        "port_behavior",
        "ticket_history",
    ]


def ticket_evidence_timeline_sort_key(item):
    category_rank = {
        category: index
        for index, category in enumerate(ticket_evidence_timeline_category_order())
    }
    severity_rank = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1,
    }

    category = str(item.get("category") or "")
    severity = str(item.get("severity") or "INFO").upper()

    return (
        str(item.get("timestamp") or ""),
        severity_rank.get(severity, 0),
        -category_rank.get(category, len(category_rank)),
        str(item.get("source") or ""),
        str(item.get("summary") or ""),
    )


def ticket_evidence_sort_timeline_entries(entries):
    return sorted(
        list(entries or []),
        key=ticket_evidence_timeline_sort_key,
        reverse=True,
    )


def ticket_evidence_balance_timeline(timeline, limit=25):
    requested_limit = risk_int(limit, 25)

    if requested_limit <= 0:
        return []

    sorted_entries = ticket_evidence_sort_timeline_entries(timeline)
    category_order = ticket_evidence_timeline_category_order()
    by_category = {category: [] for category in category_order}

    for entry in sorted_entries:
        category = entry.get("category")
        if category in by_category:
            by_category[category].append(entry)

    selected = []
    selected_ids = set()

    for category in category_order:
        if len(selected) >= requested_limit:
            break

        category_entries = by_category.get(category) or []
        if not category_entries:
            continue

        entry = category_entries[0]
        selected.append(entry)
        selected_ids.add(id(entry))

    for entry in sorted_entries:
        if len(selected) >= requested_limit:
            break

        if id(entry) in selected_ids:
            continue

        selected.append(entry)
        selected_ids.add(id(entry))

    return selected[:requested_limit]


def ticket_evidence_build_timeline(
    risk_rows,
    alert_rows,
    event_rows,
    port_behavior_rows,
    ticket_history_rows,
    limit=25,
):
    timeline = []

    for row in risk_rows or []:
        reasons = row.get("reasons") or []
        primary_reason = reasons[0] if reasons else "Current risk context is present."
        timeline.append(
            ticket_evidence_timeline_entry(
                "current_risk",
                "risk_register",
                primary_reason,
                severity=row.get("level") or row.get("severity") or "INFO",
                timestamp=row.get("updated_at") or row.get("created_at"),
                row=row,
            )
        )

    for row in alert_rows or []:
        timeline.append(
            ticket_evidence_timeline_entry(
                "alert",
                "alerts",
                row.get("summary") or row.get("event_type") or "Alert context is present.",
                severity=row.get("severity") or "INFO",
                timestamp=row.get("last_seen_at") or row.get("opened_at") or row.get("created_at"),
                row=row,
            )
        )

    for row in event_rows or []:
        timeline.append(
            ticket_evidence_timeline_entry(
                "delta_event",
                "delta_events",
                row.get("summary") or row.get("event_type") or "Delta event context is present.",
                severity=row.get("severity") or "INFO",
                timestamp=row.get("created_at"),
                row=row,
            )
        )

    for row in port_behavior_rows or []:
        protocol = row.get("protocol") or "-"
        port = row.get("port") or "-"
        behavior = row.get("behavior") or row.get("signal") or "PORT_BEHAVIOR"
        timeline.append(
            ticket_evidence_timeline_entry(
                "port_behavior",
                "mac_port_behavior",
                f"{behavior} {protocol}/{port}",
                severity=row.get("severity") or "INFO",
                timestamp=(
                    row.get("last_seen_at")
                    or row.get("observed_at")
                    or row.get("created_at")
                ),
                row=row,
            )
        )

    for row in ticket_history_rows or []:
        previous_status = row.get("previous_status") or "-"
        new_status = row.get("new_status") or row.get("ticket_status") or "-"
        timeline.append(
            ticket_evidence_timeline_entry(
                "ticket_history",
                "investigation_ticket_history",
                f"Ticket workflow changed from {previous_status} to {new_status}.",
                severity="INFO",
                timestamp=row.get("created_at") or row.get("updated_at"),
                row=row,
            )
        )

    return ticket_evidence_balance_timeline(timeline, limit=limit)



def ticket_evidence_why_now_event_types(event_rows):
    interesting = {
        "ASSET_REAPPEARED",
        "MONITORED_SERVICE_OPENED",
        "NETSNIPER_FINDING_ADDED",
        "DEVICE_CLASSIFICATION_CHANGED",
        "CONFIDENCE_CHANGED",
        "CONTRADICTION",
    }

    event_types = []

    for row in event_rows or []:
        event_type = str(row.get("event_type") or row.get("type") or "").upper()

        if event_type in interesting and event_type not in event_types:
            event_types.append(event_type)

    return event_types


def ticket_evidence_why_now_ports(port_behavior_rows):
    ports = []

    for row in port_behavior_rows or []:
        port_key = row.get("port_key")
        protocol = row.get("protocol")
        port = row.get("port")

        if port_key:
            value = str(port_key)
        elif protocol or port:
            value = f"{protocol or '-'}/{port or '-'}"
        else:
            value = ""

        if value and value not in ports:
            ports.append(value)

    return ports


def ticket_evidence_why_now_summary(
    risk_rows,
    alert_rows,
    event_rows,
    port_behavior_rows,
    ticket_history_rows=None,
    ticket_state=None,
    investigation_items=None,
):
    reasons = []
    risk_items = list(risk_rows or [])
    alert_items = list(alert_rows or [])
    port_items = list(port_behavior_rows or [])
    investigation_items = list(investigation_items or [])
    ticket_state = ticket_state or {}

    if investigation_items:
        primary_item = investigation_items[0]
        priority_level = str(
            primary_item.get("priority_level")
            or primary_item.get("level")
            or "INFO"
        ).upper()
        priority_score = primary_item.get("priority_score") or primary_item.get("score")

        if priority_score not in (None, ""):
            reasons.append(
                f"investigation priority is {priority_level} with score {priority_score}"
            )
        else:
            reasons.append(f"investigation priority is {priority_level}")

    if risk_items:
        primary_risk = risk_items[0]
        level = str(
            primary_risk.get("level")
            or primary_risk.get("severity")
            or "INFO"
        ).upper()
        score = primary_risk.get("score")

        if score not in (None, ""):
            reasons.append(f"current risk context is {level} with score {score}")
        else:
            reasons.append(f"current risk context is {level}")

    active_alerts = [
        row for row in alert_items
        if str(row.get("status") or row.get("state") or "OPEN").upper()
        not in {"CLOSED", "RESOLVED", "SUPPRESSED"}
    ]

    if active_alerts:
        severities = []
        for row in active_alerts:
            severity = str(row.get("severity") or "INFO").upper()
            if severity not in severities:
                severities.append(severity)

        reasons.append(
            f"{len(active_alerts)} active alert(s) include "
            f"{', '.join(severities[:3])} severity"
        )

    event_types = ticket_evidence_why_now_event_types(event_rows)
    if event_types:
        reasons.append(
            "recent delta evidence includes "
            + ", ".join(event_types[:3])
        )

    ports = ticket_evidence_why_now_ports(port_items)
    if ports:
        reasons.append(
            "MAC-port behavior changed on "
            + ", ".join(ports[:4])
        )
    elif port_items:
        reasons.append("MAC-port behavior changed")

    ticket_status = str(ticket_state.get("ticket_status") or "OPEN").upper()
    if ticket_status not in {"RESOLVED", "SUPPRESSED", "CLOSED"}:
        reasons.append(f"workflow status is {ticket_status}")

    if reasons:
        return "This ticket matters now because " + "; ".join(reasons[:6]) + "."

    return (
        "This ticket is relevant because DeltaAegis found evidence linked to "
        "this subject in the current investigation context."
    )


def dashboard_ticket_evidence_payload(
    connection,
    subject_key,
    scope=None,
    limit=10,
):
    requested_limit = risk_int(limit, 10)

    if requested_limit <= 0:
        requested_limit = 10

    if not subject_key:
        return {
            "available": False,
            "subject_key": None,
            "error": "subject_key is required",
            "summary": {},
            "ticket_state": {},
            "ticket_history": [],
            "asset_detail": {},
            "risk": [],
            "alerts": [],
            "events": [],
            "port_behavior": [],
            "investigation_items": [],
            "timeline": [],
        }

    stable_subject = stable_ticket_key(subject_key)

    try:
        ticket_state = get_ticket_state(connection, subject_key)
        ticket_history = list_ticket_history(
            connection,
            subject_key,
            limit=max(requested_limit, 10),
        )

        risk_rows = ticket_evidence_filter_rows(
            build_risk_register(
                connection,
                max(requested_limit * 8, 50),
                scope=scope,
            ),
            subject_key,
            limit=requested_limit,
        )

        try:
            asset_detail = dashboard_asset_detail_payload(
                connection,
                subject_key,
                scope=scope,
                limit=requested_limit,
            )
        except Exception as exc:
            asset_detail = {
                "available": False,
                "error": str(exc),
            }

        alert_rows = ticket_evidence_filter_rows(
            dashboard_alerts_payload(
                connection,
                max(requested_limit * 8, 50),
                scope=scope,
            ),
            subject_key,
            limit=requested_limit,
        )

        event_rows = ticket_evidence_filter_rows(
            dashboard_events_payload(
                connection,
                max(requested_limit * 8, 50),
                scope=scope,
            ),
            subject_key,
            limit=requested_limit,
        )

        port_behavior_rows = ticket_evidence_filter_rows(
            dashboard_port_behavior_payload(
                connection,
                max(requested_limit * 8, 50),
                scope=scope,
            ),
            subject_key,
            limit=requested_limit,
        )

        investigation_payload = dashboard_investigation_center_payload(
            connection,
            limit=max(requested_limit * 8, 50),
            scope=scope,
        )
        investigation_items = ticket_evidence_filter_rows(
            investigation_payload.get("items") or [],
            subject_key,
            limit=requested_limit,
        )

        primary_investigation_item = investigation_items[0] if investigation_items else {}
        primary_risk = risk_rows[0] if risk_rows else {}
        primary_reason = (
            primary_investigation_item.get("primary_reason")
            or ((primary_risk.get("reasons") or [None])[0])
            or "No primary evidence reason was found for this ticket."
        )
        recommended_action = (
            primary_investigation_item.get("recommended_action")
            or primary_risk.get("recommended_action")
            or "Review asset identity, risk context, alerts, events, port behavior, and ticket history before closing this ticket."
        )

        timeline = ticket_evidence_build_timeline(
            risk_rows,
            alert_rows,
            event_rows,
            port_behavior_rows,
            ticket_history,
            limit=max(requested_limit * 3, 25),
        )

        why_now = ticket_evidence_why_now_summary(
            risk_rows,
            alert_rows,
            event_rows,
            port_behavior_rows,
            ticket_history,
            ticket_state,
            investigation_items,
        )

        summary = {
            "subject_key": stable_subject,
            "selected_subject": str(subject_key),
            "scope": scope,
            "ticket_status": ticket_state.get("ticket_status") or "OPEN",
            "ticket_signal": primary_investigation_item.get("ticket_signal_state") or "ACTIONABLE",
            "priority_level": (
                primary_investigation_item.get("priority_level")
                or primary_risk.get("level")
                or "INFO"
            ),
            "priority_score": (
                primary_investigation_item.get("priority_score")
                or primary_risk.get("score")
                or 0
            ),
            "risk_count": len(risk_rows),
            "alert_count": len(alert_rows),
            "event_count": len(event_rows),
            "port_behavior_count": len(port_behavior_rows),
            "ticket_history_count": len(ticket_history),
            "timeline_count": len(timeline),
            "primary_reason": primary_reason,
            "recommended_action": recommended_action,
            "why_now": why_now,
        }

        return {
            "available": True,
            "subject_key": stable_subject,
            "selected_subject": str(subject_key),
            "selected_scope": scope,
            "summary": summary,
            "ticket_state": ticket_state,
            "ticket_history": ticket_history,
            "asset_detail": asset_detail,
            "risk": risk_rows[:requested_limit],
            "alerts": alert_rows[:requested_limit],
            "events": event_rows[:requested_limit],
            "port_behavior": port_behavior_rows[:requested_limit],
            "investigation_items": investigation_items[:requested_limit],
            "timeline": timeline,
        }
    except Exception as exc:
        return {
            "available": False,
            "subject_key": stable_subject,
            "selected_subject": str(subject_key),
            "selected_scope": scope,
            "error": str(exc),
            "summary": {
                "subject_key": stable_subject,
                "selected_subject": str(subject_key),
                "scope": scope,
            },
            "ticket_state": {},
            "ticket_history": [],
            "asset_detail": {},
            "risk": [],
            "alerts": [],
            "events": [],
            "port_behavior": [],
            "investigation_items": [],
            "timeline": [],
        }



def print_investigation_center_rows(payload):
    available = bool(payload.get("available", False))
    scope = payload.get("selected_scope")
    rows = list(payload.get("items") or [])

    print("DeltaAegis Investigation Command Center")
    print("=======================================")

    if scope:
        print(f"Network scope: {scope}")

    filters = payload.get("filters") or investigation_center_filter_payload()
    workflow_summary = payload.get("workflow_summary") or investigation_center_workflow_summary(rows)
    signal_summary = payload.get("signal_summary") or investigation_center_signal_summary(rows)
    total_item_count = payload.get("total_item_count", len(rows))

    print(
        "Filters: "
        f"workflow={filters.get('ticket_status', 'ALL')}, "
        f"signal={filters.get('ticket_signal', 'ALL')}"
    )
    print(
        "Visible queue items: "
        f"{len(rows)} of {total_item_count}"
    )
    print(
        "Workflow summary: "
        f"OPEN={workflow_summary.get('open', 0)}, "
        f"IN_REVIEW={workflow_summary.get('in_review', 0)}, "
        f"RESOLVED={workflow_summary.get('resolved', 0)}, "
        f"SUPPRESSED={workflow_summary.get('suppressed', 0)}"
    )
    print(
        "Signal summary: "
        f"ACTIONABLE={signal_summary.get('actionable', 0)}, "
        f"MEANINGFUL_CHANGE={signal_summary.get('meaningful_change', 0)}, "
        f"BASELINE_CONTEXT={signal_summary.get('baseline_context', 0)}"
    )

    print()

    if not available:
        print(payload.get("error") or "Investigation Command Center is unavailable.")
        return

    if not rows:
        print("No investigation queue items matched the selected scope.")
        return

    for index, row in enumerate(rows, start=1):
        print(
            f"{index:>2}. "
            f"{row.get('priority_level', 'INFO'):<8} "
            f"{int(row.get('priority_score') or 0):>3}  "
            f"{row.get('subject_key') or '-'}"
        )
        print(f"    IP:       {row.get('ip_address') or '-'}")
        print(f"    MAC:      {row.get('mac_address') or '-'}")

        device = row.get("device_type") or "Unknown"
        role = row.get("role") or row.get("classification") or "Unknown"
        print(f"    Device:   {device}")
        print(f"    Role:     {role}")

        triggers = row.get("triggers") or []
        print(f"    Triggers: {', '.join(triggers) if triggers else '-'}")
        workflow_status = row.get("ticket_status") or "OPEN"
        workflow_analyst = row.get("ticket_analyst") or "-"
        workflow_updated = row.get("ticket_updated_at") or "-"
        workflow_note = row.get("ticket_note") or ""
        print(f"    Workflow: {workflow_status}")
        triage_bucket = row.get("triage_bucket") or "MONITOR"
        triage_label = row.get("triage_urgency_label") or "LOW"
        triage_score = row.get("triage_urgency_score") or 0
        print(f"    Triage:  {triage_bucket} / {triage_label} ({triage_score})")
        if workflow_analyst != "-" or workflow_updated != "-":
            print(
                "    Analyst:  "
                f"{workflow_analyst} "
                f"(updated={workflow_updated})"
            )
        if workflow_note:
            print(f"    Note:     {workflow_note}")
        print(f"    Why:      {row.get('primary_reason') or '-'}")
        print(f"    Action:   {row.get('recommended_action') or '-'}")
        print(
            "    Counts:   "
            f"alerts={int(row.get('open_alerts') or 0)}, "
            f"events={int(row.get('recent_events') or 0)}, "
            f"ports={int(row.get('port_behavior_count') or 0)}, "
            f"findings={int(row.get('current_finding_count') or 0)}"
        )

        port_behavior = row.get("port_behavior") or []
        if port_behavior:
            first = port_behavior[0]
            print(
                "    Port:     "
                f"{first.get('behavior') or '-'} "
                f"{first.get('port_key') or '-'} "
                f"({first.get('severity') or 'INFO'})"
            )

        alerts = row.get("alerts") or []
        if alerts:
            first = alerts[0]
            print(
                "    Alert:    "
                f"#{first.get('alert_id') or '-'} "
                f"{first.get('severity') or 'INFO'} "
                f"{first.get('event_type') or '-'}"
            )

        print()




def print_ticket_evidence_section(title, rows, fields, limit=5):
    items = list(rows or [])[:limit]

    print()
    print(title)
    print("-" * len(title))

    if not items:
        print("  None.")
        return

    for index, row in enumerate(items, start=1):
        print(f"{index:>2}.")
        for field, label in fields:
            value = row.get(field)

            if isinstance(value, list):
                value = ", ".join(str(item) for item in value[:6])

            if isinstance(value, dict):
                value = ", ".join(f"{key}={item}" for key, item in list(value.items())[:6])

            if value in (None, ""):
                value = "-"

            print(f"    {label:<14} {value}")


def print_ticket_evidence_payload(payload):
    available = bool(payload.get("available", False))
    summary = payload.get("summary") or {}
    ticket_state = payload.get("ticket_state") or {}

    print("DeltaAegis Ticket Evidence")
    print("==========================")

    if not available:
        print(payload.get("error") or "Ticket evidence is unavailable.")
        return

    print(f"Subject:        {payload.get('subject_key') or summary.get('subject_key') or '-'}")
    print(f"Selected:       {payload.get('selected_subject') or '-'}")
    print(f"Scope:          {payload.get('selected_scope') or summary.get('scope') or '-'}")
    print(f"Workflow:       {summary.get('ticket_status') or ticket_state.get('ticket_status') or 'OPEN'}")
    print(f"Signal:         {summary.get('ticket_signal') or 'ACTIONABLE'}")
    print(
        "Priority:       "
        f"{summary.get('priority_level') or 'INFO'} / "
        f"{int(summary.get('priority_score') or 0)}"
    )
    print()
    print(f"Why:            {summary.get('primary_reason') or '-'}")
    print(f"Why now:        {summary.get('why_now') or '-'}")
    print(f"Next action:    {summary.get('recommended_action') or '-'}")
    print()
    print(
        "Evidence counts: "
        f"risk={int(summary.get('risk_count') or 0)}, "
        f"alerts={int(summary.get('alert_count') or 0)}, "
        f"events={int(summary.get('event_count') or 0)}, "
        f"ports={int(summary.get('port_behavior_count') or 0)}, "
        f"history={int(summary.get('ticket_history_count') or 0)}, "
        f"timeline={int(summary.get('timeline_count') or 0)}"
    )

    print_ticket_evidence_section(
        "Evidence Timeline",
        payload.get("timeline") or [],
        [
            ("timestamp", "Time"),
            ("category", "Category"),
            ("severity", "Severity"),
            ("source", "Source"),
            ("summary", "Summary"),
        ],
        limit=10,
    )

    print_ticket_evidence_section(
        "Current Risk Evidence",
        payload.get("risk") or [],
        [
            ("level", "Level"),
            ("score", "Score"),
            ("subject_key", "Subject"),
            ("reasons", "Reasons"),
        ],
        limit=5,
    )

    print_ticket_evidence_section(
        "Alerts",
        payload.get("alerts") or [],
        [
            ("alert_id", "Alert"),
            ("status", "Status"),
            ("severity", "Severity"),
            ("event_type", "Type"),
            ("summary", "Summary"),
        ],
        limit=5,
    )

    print_ticket_evidence_section(
        "Delta Events",
        payload.get("events") or [],
        [
            ("event_id", "Event"),
            ("created_at", "Time"),
            ("severity", "Severity"),
            ("event_type", "Type"),
            ("summary", "Summary"),
        ],
        limit=5,
    )

    print_ticket_evidence_section(
        "MAC-Port Behavior",
        payload.get("port_behavior") or [],
        [
            ("severity", "Severity"),
            ("behavior", "Behavior"),
            ("protocol", "Protocol"),
            ("port", "Port"),
            ("reason", "Reason"),
        ],
        limit=5,
    )

    print_ticket_evidence_section(
        "Ticket History",
        payload.get("ticket_history") or [],
        [
            ("created_at", "Time"),
            ("previous_status", "Previous"),
            ("new_status", "New"),
            ("analyst", "Analyst"),
            ("note", "Note"),
        ],
        limit=10,
    )


def command_ticket_evidence(args: argparse.Namespace) -> int:
    connection = connect(args.db)
    scope = optional_network_scope(getattr(args, "scope", None))

    try:
        payload = dashboard_ticket_evidence_payload(
            connection,
            subject_key=args.subject_key,
            scope=scope,
            limit=getattr(args, "limit", 10),
        )
    finally:
        connection.close()

    print_ticket_evidence_payload(payload)

    return 0 if payload.get("available", False) else 1



def command_ticket_status(args: argparse.Namespace) -> int:
    connection = connect(args.db)

    if getattr(args, "status", None):
        state = set_ticket_state(
            connection,
            args.subject_key,
            args.status,
            analyst=getattr(args, "analyst", None),
            note=getattr(args, "note", None),
        )
        print(f"Ticket {state['ticket_key']} marked {state['ticket_status']}.")
    else:
        state = get_ticket_state(connection, args.subject_key)

    print(f"Ticket:     {state['ticket_key']}")
    print(f"Status:     {state['ticket_status']}")
    print(f"Analyst:    {state['ticket_analyst'] or '-'}")
    print(f"Note:       {state['ticket_note'] or '-'}")
    print(f"Created:    {state['ticket_created_at'] or '-'}")
    print(f"Updated:    {state['ticket_updated_at'] or '-'}")
    print(f"Resolved:   {state['ticket_resolved_at'] or '-'}")
    print(f"Suppressed: {state['ticket_suppressed_at'] or '-'}")
    return 0



def command_ticket_history(args: argparse.Namespace) -> int:
    connection = connect(args.db)
    ticket_key = stable_ticket_key(args.subject_key)
    rows = list_ticket_history(
        connection,
        args.subject_key,
        limit=getattr(args, "limit", 20),
    )

    print(f"Ticket: {ticket_key}")
    if not rows:
        print("No ticket workflow history found.")
        return 0

    for row in rows:
        previous_status = row["previous_status"] or "-"
        analyst = row["analyst"] or "-"
        note = row["note"] or "-"
        print(
            f"{row['created_at']}  "
            f"{previous_status} -> {row['new_status']}  "
            f"analyst={analyst}"
        )
        if note != "-":
            print(f"  Note: {note}")
    return 0


def command_ticket_list(args: argparse.Namespace) -> int:
    connection = connect(args.db)
    rows = list_ticket_states(
        connection,
        status=getattr(args, "status", None),
        limit=getattr(args, "limit", 50),
    )

    if not rows:
        print("No persisted ticket workflow states found.")
        return 0

    for row in rows:
        print(
            f"{row['ticket_status']:<11} "
            f"{row['ticket_key']:<40} "
            f"analyst={row['ticket_analyst'] or '-'} "
            f"updated={row['ticket_updated_at'] or '-'}"
        )
        if row["ticket_note"]:
            print(f"  Note: {row['ticket_note']}")
    return 0


def command_investigation_center(args):
    connection = connect(args.db)
    scope = optional_network_scope(getattr(args, "scope", None))

    try:
        payload = dashboard_investigation_center_payload(
            connection,
            limit=args.limit,
            scope=scope,
            ticket_status=args.ticket_status,
            ticket_signal=args.ticket_signal,
            triage_bucket=getattr(args, "triage_bucket", "ALL"),
            triage_urgency=getattr(args, "triage_urgency", "ALL"),
        )
    finally:
        connection.close()

    print_investigation_center_rows(payload)

    return 0 if payload.get("available", False) else 1



def dashboard_risk_payload(connection, limit, scope=None):
    try:
        return build_risk_register(connection, limit, scope=scope)
    except Exception as exc:
        return [
            {
                "subject_key": "risk-error",
                "score": 0,
                "level": "INFO",
                "reasons": [f"Risk register unavailable: {exc}"],
            }
        ]

def dashboard_index_html():
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>DeltaAegis Executive SIEM Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      --bg: #0b1020;
      --panel: #121a2e;
      --panel2: #18233c;
      --text: #e7eefc;
      --muted: #94a3b8;
      --line: #26344f;
      --accent: #60a5fa;
      --high: #f97316;
      --critical: #ef4444;
      --medium: #eab308;
      --low: #22c55e;
    }

    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    header {
      padding: 24px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(135deg, #0f172a, #111827);
    }

    header h1 {
      margin: 0;
      font-size: 28px;
      letter-spacing: 0.02em;
    }

    header p {
      margin: 8px 0 0;
      color: var(--muted);
    }

    main {
      padding: 24px;
      display: grid;
      gap: 20px;
    }

    .grid {
      display: grid;
      gap: 16px;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    }

    .scan-grid {
      display: grid;
      gap: 16px;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    }

    .scope-links {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 12px;
    }

    .scope-links a {
      color: var(--text);
      text-decoration: none;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 8px 12px;
      background: var(--panel2);
      font-size: 13px;
      font-weight: 700;
    }

    .scope-links a.active {
      border-color: var(--accent);
      color: #bfdbfe;
    }

    .dashboard-tabs {
      position: sticky;
      top: 0;
      z-index: 20;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(18, 26, 46, 0.96);
      backdrop-filter: blur(8px);
    }

    .tab-button {
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--panel2);
      color: var(--muted);
      cursor: pointer;
      padding: 9px 14px;
      font-size: 13px;
      font-weight: 700;
    }

    .tab-button:hover {
      border-color: var(--accent);
      color: #bfdbfe;
    }

    .tab-button.active {
      border-color: var(--accent);
      background: #1d4ed8;
      color: #eff6ff;
    }

    [data-tab-panel][hidden] {
      display: none !important;
    }

    .asset-link {
      background: none;
      border: 0;
      color: #bfdbfe;
      cursor: pointer;
      font: inherit;
      padding: 0;
      text-align: left;
    }

    .asset-link:hover {
      text-decoration: underline;
    }

    .detail-grid {
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      margin-bottom: 16px;
    }

    .detail-box {
      border: 1px solid var(--line);
      border-radius: 14px;
      background: var(--panel2);
      padding: 12px;
    }

    .detail-box .label {
      margin-bottom: 4px;
    }

    .card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      margin-bottom: 12px;
    }

    .card-header h2 {
      margin: 0;
    }

    .asset-detail-controls button {
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--panel2);
      color: var(--text);
      cursor: pointer;
      padding: 7px 12px;
      font-size: 12px;
    }

    .asset-detail-controls button:hover {
      border-color: var(--accent);
      color: #bfdbfe;
    }

    .card-body.collapsed {
      display: none;
    }

    .asset-detail-controls {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 10px;
      margin-bottom: 14px;
    }

    .asset-detail-controls select {
      min-width: 320px;
      max-width: 100%;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: var(--panel2);
      color: var(--text);
      padding: 8px 10px;
    }

    .kv {
      display: grid;
      gap: 8px;
      margin-top: 10px;
    }

    .kv div {
      display: grid;
      grid-template-columns: 130px 1fr;
      gap: 10px;
      border-bottom: 1px solid var(--line);
      padding-bottom: 6px;
    }

    .kv span:first-child {
      color: var(--muted);
    }

    .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 16px;
      box-shadow: 0 12px 30px rgba(0,0,0,0.25);
    }

    .metric {
      font-size: 32px;
      font-weight: 700;
      margin-top: 8px;
    }

    .label {
      color: var(--muted);
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }

    h2 {
      margin: 0 0 12px;
      font-size: 20px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      overflow: hidden;
    }

    th, td {
      border-bottom: 1px solid var(--line);
      padding: 10px;
      text-align: left;
      vertical-align: top;
      font-size: 14px;
    }

    th {
      color: var(--muted);
      font-weight: 600;
      background: var(--panel2);
    }

    code {
      color: #bfdbfe;
    }

    .pill {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 999px;
      background: var(--panel2);
      border: 1px solid var(--line);
      font-size: 12px;
      font-weight: 700;
    }

    .CRITICAL { color: var(--critical); }
    .HIGH { color: var(--high); }
    .MEDIUM { color: var(--medium); }
    .LOW { color: var(--low); }
    .INFO { color: var(--muted); }

    .muted {
      color: var(--muted);
    }

    .error {
      color: #fecaca;
      background: #450a0a;
      border: 1px solid #7f1d1d;
      padding: 12px;
      border-radius: 10px;
      display: none;
    }

    .explain {
      background: linear-gradient(135deg, rgba(96,165,250,0.12), rgba(34,197,94,0.08));
    }

    .callout {
      border-left: 4px solid var(--accent);
      padding: 10px 12px;
      background: rgba(96,165,250,0.08);
      border-radius: 8px;
      color: var(--text);
      margin-top: 10px;
    }

    .legend-grid {
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    }

    .legend-list {
      margin: 0;
      padding-left: 20px;
      color: var(--muted);
    }

    .legend-list li {
      margin: 6px 0;
    }

    .steps {
      margin: 0;
      padding-left: 22px;
    }

    .steps li {
      margin: 8px 0;
    }

    .status {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 999px;
      border: 1px solid var(--line);
      font-size: 12px;
      font-weight: 700;
    }

    .status-current {
      color: #bbf7d0;
      background: rgba(34,197,94,0.12);
      border-color: rgba(34,197,94,0.35);
    }

    .status-stale {
      color: #fed7aa;
      background: rgba(249,115,22,0.12);
      border-color: rgba(249,115,22,0.35);
    }

    .status-unknown {
      color: #cbd5e1;
      background: rgba(148,163,184,0.12);
      border-color: rgba(148,163,184,0.35);
    }

    .identity-strong {
      color: #bbf7d0;
    }

    .identity-partial {
      color: #fde68a;
    }

    .identity-unknown {
      color: #fecaca;
    }

    /* Severity and risk-level coloring used by dashboard tables. */
    .severity-critical,
    td.severity-critical {
      color: #ff4d4d;
      font-weight: 800;
    }

    .severity-high,
    td.severity-high {
      color: #ff9f1c;
      font-weight: 800;
    }

    .severity-medium,
    td.severity-medium {
      color: #ffe45e;
      font-weight: 800;
    }

    .severity-low,
    td.severity-low {
      color: #4ade80;
      font-weight: 800;
    }

    .severity-info,
    td.severity-info {
      color: #93c5fd;
      font-weight: 800;
    }

    .severity-unknown,
    td.severity-unknown {
      color: #cbd5e1;
      font-weight: 700;
    }


    .risk-explanation summary {
      cursor: pointer;
      color: #bfdbfe;
      font-weight: 700;
    }

    .risk-explanation ul {
      margin: 8px 0 0;
      padding-left: 18px;
      color: var(--muted);
    }

    .risk-explanation li {
      margin: 4px 0;
    }

    .risk-explanation .risk-action {
      margin-top: 8px;
      color: #bbf7d0;
    }

    .command-center-trigger {
      display: inline-block;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 2px 8px;
      margin: 2px;
      background: var(--panel2);
      color: #bfdbfe;
      font-size: 12px;
      font-weight: 700;
      white-space: nowrap;
    }

    .command-center-reason {
      max-width: 520px;
      color: var(--text);
    }

    .command-center-action {
      max-width: 520px;
      color: #bbf7d0;
    }

    /* v0.17 Executive SIEM Dashboard Refresh */
    .dashboard-shell-refresh-v017 {
      min-height: 100vh;
      background:
        radial-gradient(circle at 18% -10%, rgba(59, 130, 246, 0.22), transparent 34%),
        radial-gradient(circle at 82% 0%, rgba(168, 85, 247, 0.16), transparent 32%),
        linear-gradient(180deg, #020617 0%, #07111f 44%, #0b1020 100%);
      color: var(--text);
    }

    .dashboard-shell-refresh-v017 .executive-header {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 22px;
      align-items: center;
      padding: 28px 32px;
      border-bottom: 1px solid rgba(148, 163, 184, 0.22);
      background:
        linear-gradient(135deg, rgba(15, 23, 42, 0.96), rgba(17, 24, 39, 0.86)),
        radial-gradient(circle at top right, rgba(96, 165, 250, 0.2), transparent 35%);
      box-shadow: 0 20px 55px rgba(0, 0, 0, 0.38);
    }

    .executive-kicker {
      color: #67e8f9;
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0.16em;
      text-transform: uppercase;
    }

    .dashboard-shell-refresh-v017 header h1 {
      margin-top: 6px;
      font-size: clamp(30px, 4vw, 46px);
      line-height: 1.02;
      letter-spacing: -0.04em;
    }

    .dashboard-shell-refresh-v017 header p {
      max-width: 820px;
      color: #cbd5e1;
      font-size: 15px;
      line-height: 1.65;
    }

    .executive-status-grid {
      display: grid;
      gap: 10px;
      min-width: 280px;
    }

    .executive-status-pill {
      display: flex;
      justify-content: space-between;
      gap: 18px;
      border: 1px solid rgba(148, 163, 184, 0.22);
      border-radius: 16px;
      background: rgba(15, 23, 42, 0.64);
      padding: 10px 12px;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
    }

    .executive-status-pill span:first-child {
      color: #94a3b8;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }

    .executive-status-pill span:last-child {
      color: #e0f2fe;
      font-size: 12px;
      font-weight: 800;
      text-align: right;
    }

    .dashboard-shell-refresh-v017 .dashboard-main {
      width: min(1540px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 22px 0 36px;
      gap: 22px;
    }

    .executive-overview {
      border: 1px solid rgba(96, 165, 250, 0.24);
      border-radius: 24px;
      background:
        linear-gradient(135deg, rgba(30, 41, 59, 0.92), rgba(15, 23, 42, 0.92)),
        radial-gradient(circle at 90% 12%, rgba(34, 211, 238, 0.14), transparent 32%);
      padding: 22px;
      box-shadow: 0 24px 70px rgba(0, 0, 0, 0.28);
    }

    .executive-overview h2 {
      margin: 6px 0 8px;
      font-size: 26px;
      letter-spacing: -0.03em;
    }

    .executive-overview p {
      max-width: 860px;
      color: #cbd5e1;
      line-height: 1.65;
    }

    .executive-objectives {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 12px;
      margin-top: 16px;
    }

    .executive-objective {
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 18px;
      background: rgba(2, 6, 23, 0.34);
      padding: 14px;
    }

    .executive-objective strong {
      display: block;
      margin-bottom: 6px;
      color: #e0f2fe;
    }

    .executive-objective span {
      color: #94a3b8;
      font-size: 13px;
      line-height: 1.55;
    }

    .dashboard-shell-refresh-v017 .executive-tabs {
      top: 10px;
      border-color: rgba(148, 163, 184, 0.22);
      background: rgba(2, 6, 23, 0.72);
      box-shadow: 0 16px 50px rgba(0, 0, 0, 0.3);
    }

    .dashboard-shell-refresh-v017 .tab-button {
      background: rgba(15, 23, 42, 0.82);
      border-color: rgba(148, 163, 184, 0.2);
      color: #cbd5e1;
      transition: transform 120ms ease, border-color 120ms ease, background 120ms ease;
    }

    .dashboard-shell-refresh-v017 .tab-button:hover {
      transform: translateY(-1px);
      background: rgba(30, 41, 59, 0.95);
    }

    .dashboard-shell-refresh-v017 .tab-button.active {
      border-color: rgba(34, 211, 238, 0.7);
      background: linear-gradient(135deg, #1d4ed8, #0891b2);
      box-shadow: 0 10px 28px rgba(8, 145, 178, 0.28);
    }

    .dashboard-shell-refresh-v017 .card {
      border-color: rgba(148, 163, 184, 0.18);
      border-radius: 20px;
      background:
        linear-gradient(180deg, rgba(15, 23, 42, 0.96), rgba(15, 23, 42, 0.84));
      box-shadow: 0 16px 44px rgba(0, 0, 0, 0.26);
      overflow-x: auto;
    }

    .dashboard-shell-refresh-v017 .card h2 {
      color: #f8fafc;
      letter-spacing: -0.02em;
    }

    .metric-card {
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 20px;
      background:
        linear-gradient(180deg, rgba(30, 41, 59, 0.94), rgba(15, 23, 42, 0.9));
      padding: 16px;
      box-shadow: 0 14px 38px rgba(0, 0, 0, 0.24);
      min-height: 96px;
    }

    .metric-value {
      margin-top: 8px;
      color: #f8fafc;
      font-size: 34px;
      font-weight: 850;
      letter-spacing: -0.05em;
    }

    .dashboard-shell-refresh-v017 .metric {
      color: #f8fafc;
      font-weight: 850;
      letter-spacing: -0.05em;
    }

    .dashboard-shell-refresh-v017 table {
      border-collapse: separate;
      border-spacing: 0;
    }

    .dashboard-shell-refresh-v017 th {
      position: sticky;
      top: 0;
      z-index: 1;
      background: rgba(15, 23, 42, 0.96);
      color: #cbd5e1;
      border-bottom: 1px solid rgba(148, 163, 184, 0.2);
    }

    .dashboard-shell-refresh-v017 td {
      border-bottom-color: rgba(148, 163, 184, 0.14);
    }

    .dashboard-shell-refresh-v017 tbody tr:hover {
      background: rgba(96, 165, 250, 0.06);
    }

    .dashboard-shell-refresh-v017 .command-center-trigger {
      border-color: rgba(34, 211, 238, 0.32);
      background: rgba(8, 145, 178, 0.16);
      color: #a5f3fc;
    }

    .dashboard-shell-refresh-v017 .severity-critical,
    .dashboard-shell-refresh-v017 .CRITICAL {
      color: #fecaca;
      text-shadow: 0 0 14px rgba(239, 68, 68, 0.28);
    }

    .dashboard-shell-refresh-v017 .severity-high,
    .dashboard-shell-refresh-v017 .HIGH {
      color: #fed7aa;
    }

    .dashboard-shell-refresh-v017 .severity-medium,
    .dashboard-shell-refresh-v017 .MEDIUM {
      color: #fde68a;
    }

    .dashboard-shell-refresh-v017 .severity-low,
    .dashboard-shell-refresh-v017 .LOW {
      color: #bbf7d0;
    }

    @media (max-width: 860px) {
      .dashboard-shell-refresh-v017 .executive-header {
        grid-template-columns: 1fr;
      }

      .executive-status-grid {
        min-width: 0;
      }

      .dashboard-shell-refresh-v017 .dashboard-main {
        width: min(100vw - 18px, 1540px);
      }
    }

    /* v0.17 SIEM-style executive chart panels */
    .siem-analytics-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 16px;
    }

    .siem-chart-panel {
      min-height: 300px;
    }

    .siem-chart-panel h3 {
      margin: 0 0 4px;
      font-size: 15px;
      letter-spacing: 0.02em;
      text-transform: uppercase;
      color: #e2e8f0;
    }

    .siem-chart-subtitle {
      margin: 0 0 16px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.45;
    }

    .siem-bar-list {
      display: grid;
      gap: 10px;
    }

    .siem-bar-row {
      display: grid;
      grid-template-columns: minmax(110px, 180px) minmax(0, 1fr) 48px;
      gap: 10px;
      align-items: center;
      font-size: 13px;
    }

    .siem-bar-label {
      color: #dbeafe;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .siem-bar-track {
      height: 12px;
      overflow: hidden;
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.86);
    }

    .siem-bar-fill {
      height: 100%;
      min-width: 4px;
      border-radius: 999px;
      background: linear-gradient(90deg, #22d3ee, #3b82f6);
      box-shadow: 0 0 18px rgba(34, 211, 238, 0.24);
    }

    .siem-bar-value {
      color: #f8fafc;
      text-align: right;
      font-variant-numeric: tabular-nums;
      font-weight: 800;
    }

    .siem-donut-wrap {
      display: grid;
      grid-template-columns: 150px minmax(0, 1fr);
      gap: 18px;
      align-items: center;
    }

    .siem-donut {
      width: 150px;
      height: 150px;
      border-radius: 50%;
      display: grid;
      place-items: center;
      background: conic-gradient(#22d3ee 0deg, #22d3ee 120deg, #3b82f6 120deg, #3b82f6 210deg, #a855f7 210deg, #a855f7 290deg, #f59e0b 290deg, #f59e0b 360deg);
      box-shadow: 0 0 30px rgba(34, 211, 238, 0.12);
    }

    .siem-donut::after {
      content: "";
      width: 82px;
      height: 82px;
      border-radius: 50%;
      background: #0f172a;
      border: 1px solid rgba(148, 163, 184, 0.2);
    }

    .siem-legend {
      display: grid;
      gap: 8px;
      font-size: 13px;
    }

    .siem-legend-row {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      color: #cbd5e1;
    }

    .siem-legend-row strong {
      color: #f8fafc;
      font-variant-numeric: tabular-nums;
    }

    @media (max-width: 1100px) {
      .siem-analytics-grid {
        grid-template-columns: 1fr;
      }

      .siem-donut-wrap {
        grid-template-columns: 1fr;
      }
    }

    /* v0.17 SIEM-style ticket queue */
    .ticket-cards-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
      gap: 14px;
      margin: 18px 0;
    }

    .siem-ticket-card {
      position: relative;
      overflow: hidden;
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 20px;
      background:
        linear-gradient(180deg, rgba(15, 23, 42, 0.98), rgba(2, 6, 23, 0.88));
      padding: 16px;
      box-shadow: 0 18px 42px rgba(0, 0, 0, 0.22);
    }

    .siem-ticket-card::before {
      content: "";
      position: absolute;
      inset: 0 auto 0 0;
      width: 4px;
      background: #64748b;
    }

    .siem-ticket-card.ticket-critical::before { background: #ef4444; }
    .siem-ticket-card.ticket-high::before { background: #f97316; }
    .siem-ticket-card.ticket-medium::before { background: #eab308; }
    .siem-ticket-card.ticket-low::before { background: #22c55e; }

    .evidence-drilldown-panel {
      margin: 16px 0 22px;
      border: 1px solid rgba(96, 165, 250, 0.22);
      border-radius: 20px;
      background:
        linear-gradient(180deg, rgba(15, 23, 42, 0.98), rgba(2, 6, 23, 0.92));
      padding: 16px;
      box-shadow: 0 18px 42px rgba(0, 0, 0, 0.22);
    }

    .evidence-drilldown-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 12px;
    }

    .evidence-drilldown-header h3 {
      margin: 0;
    }

    .ticket-evidence-action {
      border-color: rgba(96, 165, 250, 0.65);
    }

    .ticket-evidence-why-now {
      border: 1px solid rgba(34, 211, 238, 0.22);
      background: rgba(8, 145, 178, 0.10);
      border-radius: 14px;
      padding: 12px;
      margin: 10px 0 14px;
    }


    .triage-summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(155px, 1fr));
      gap: 10px;
      margin: 10px 0 14px;
    }

    .triage-summary-card {
      border: 1px solid rgba(34, 211, 238, 0.2);
      border-radius: 16px;
      background:
        linear-gradient(135deg, rgba(15, 23, 42, 0.92), rgba(30, 41, 59, 0.72)),
        radial-gradient(circle at top right, rgba(34, 211, 238, 0.10), transparent 45%);
      padding: 12px;
      min-height: 84px;
    }

    .triage-summary-card .label {
      color: #94a3b8;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }

    .triage-summary-card .value {
      color: #f8fafc;
      display: block;
      font-size: 24px;
      font-weight: 850;
      letter-spacing: -0.03em;
      margin-top: 4px;
    }

    .triage-summary-card .hint {
      color: #94a3b8;
      display: block;
      font-size: 12px;
      line-height: 1.45;
      margin-top: 4px;
    }

    .ticket-triage-badge {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 3px 9px;
      margin-left: 6px;
      font-size: 0.72rem;
      font-weight: 800;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      border: 1px solid rgba(148, 163, 184, 0.24);
      background: rgba(148, 163, 184, 0.12);
      color: #cbd5e1;
      white-space: nowrap;
    }

    .ticket-triage-immediate {
      background: rgba(248, 113, 113, 0.14);
      border-color: rgba(248, 113, 113, 0.34);
      color: #fecaca;
    }

    .ticket-triage-high {
      background: rgba(251, 191, 36, 0.14);
      border-color: rgba(251, 191, 36, 0.34);
      color: #fde68a;
    }

    .ticket-triage-normal {
      background: rgba(96, 165, 250, 0.14);
      border-color: rgba(96, 165, 250, 0.34);
      color: #bfdbfe;
    }

    .ticket-triage-low {
      background: rgba(148, 163, 184, 0.12);
      border-color: rgba(148, 163, 184, 0.22);
      color: #cbd5e1;
    }

    .ticket-evidence-why-now .label {
      color: #a5f3fc;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      font-size: 0.75rem;
      margin-bottom: 6px;
    }

    .ticket-evidence-category {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 0.72rem;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      background: rgba(148, 163, 184, 0.12);
      color: #cbd5e1;
    }

    .ticket-evidence-category-current-risk {
      background: rgba(248, 113, 113, 0.14);
      color: #fecaca;
    }

    .ticket-evidence-category-alert {
      background: rgba(251, 191, 36, 0.14);
      color: #fde68a;
    }

    .ticket-evidence-category-delta-event {
      background: rgba(96, 165, 250, 0.14);
      color: #bfdbfe;
    }

    .ticket-evidence-category-port-behavior {
      background: rgba(45, 212, 191, 0.14);
      color: #99f6e4;
    }

    .ticket-evidence-category-ticket-history {
      background: rgba(167, 139, 250, 0.14);
      color: #ddd6fe;
    }

    .ticket-evidence-timeline {
      display: grid;
      gap: 10px;
      margin-top: 12px;
    }

    .ticket-evidence-event {
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 14px;
      padding: 10px 12px;
      background: rgba(15, 23, 42, 0.72);
    }

    .ticket-evidence-event .event-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      color: #94a3b8;
      font-size: 12px;
      margin-bottom: 4px;
    }

    .siem-ticket-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 12px;
    }

    .siem-ticket-title {
      display: grid;
      gap: 5px;
      min-width: 0;
    }

    .siem-ticket-title strong {
      color: #f8fafc;
      font-size: 15px;
    }

    .siem-ticket-subject {
      color: #bfdbfe;
      font-size: 13px;
      overflow-wrap: anywhere;
    }

    .siem-priority-badge {
      border: 1px solid rgba(148, 163, 184, 0.22);
      border-radius: 16px;
      background: rgba(15, 23, 42, 0.78);
      padding: 8px 10px;
      text-align: right;
      min-width: 92px;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
    }

    .siem-priority-badge .level {
      display: block;
      font-size: 12px;
      font-weight: 900;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    .siem-priority-badge .score {
      display: block;
      margin-top: 2px;
      color: #f8fafc;
      font-size: 24px;
      font-weight: 900;
      letter-spacing: -0.05em;
    }

    .siem-ticket-meta {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
      margin: 12px 0;
    }

    .siem-ticket-meta div {
      border: 1px solid rgba(148, 163, 184, 0.12);
      border-radius: 14px;
      background: rgba(15, 23, 42, 0.5);
      padding: 8px;
      min-width: 0;
    }

    .siem-ticket-meta span {
      display: block;
      color: #94a3b8;
      font-size: 10px;
      font-weight: 900;
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }

    .siem-ticket-meta code,
    .siem-ticket-meta strong {
      display: block;
      margin-top: 4px;
      overflow-wrap: anywhere;
    }

    .siem-ticket-section {
      margin-top: 12px;
    }

    .siem-ticket-section .label {
      margin-bottom: 6px;
    }

    .siem-ticket-reason {
      color: #e2e8f0;
      line-height: 1.55;
    }

    .siem-ticket-action {
      color: #bbf7d0;
      line-height: 1.55;
    }

    .siem-ticket-counts {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 12px;
    }

    .siem-count-pill {
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.72);
      color: #dbeafe;
      padding: 5px 9px;
      font-size: 12px;
      font-weight: 800;
    }

    .siem-ticket-empty {
      border: 1px dashed rgba(148, 163, 184, 0.25);
      border-radius: 18px;
      padding: 18px;
      color: var(--muted);
      background: rgba(15, 23, 42, 0.42);
    }

    .siem-ticket-table-note {
      margin-top: 14px;
      margin-bottom: 8px;
    }

    @media (max-width: 760px) {
      .ticket-cards-grid {
        grid-template-columns: 1fr;
      }

      .siem-ticket-meta {
        grid-template-columns: 1fr;
      }
    }

    /* v0.17 ticket signal state labels */

    /* v0.18 investigation workflow visibility */
    .ticket-workflow-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.2rem 0.55rem;
      border-radius: 999px;
      font-size: 0.72rem;
      font-weight: 800;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      border: 1px solid rgba(148, 163, 184, 0.24);
      background: rgba(15, 23, 42, 0.42);
      color: #dbeafe;
      width: fit-content;
    }

    .ticket-workflow-open { color: #e2e8f0; }
    .ticket-workflow-in-review { color: #fde68a; }
    .ticket-workflow-resolved { color: #bbf7d0; }
    .ticket-workflow-suppressed { color: #cbd5e1; }
    .ticket-workflow-unknown { color: #c4b5fd; }


    .ticket-filter-panel {
      align-items: end;
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      margin: 1rem 0;
      padding: 0.85rem;
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 16px;
      background: rgba(15, 23, 42, 0.35);
    }

    .ticket-filter-panel label {
      color: var(--muted);
      display: flex;
      flex-direction: column;
      font-size: 0.78rem;
      font-weight: 800;
      gap: 0.35rem;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }

    .ticket-filter-panel select {
      min-width: 190px;
      border: 1px solid rgba(148, 163, 184, 0.24);
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.82);
      color: var(--text);
      font-size: 0.82rem;
      font-weight: 750;
      padding: 0.44rem 0.7rem;
    }

    .ticket-action-buttons {
      display: flex;
      flex-wrap: wrap;
      gap: 0.45rem;
      margin-top: 0.35rem;
    }

    .small-action-button {
      border: 1px solid rgba(148, 163, 184, 0.24);
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.52);
      color: var(--text);
      cursor: pointer;
      font-size: 0.75rem;
      font-weight: 800;
      padding: 0.28rem 0.62rem;
    }

    .small-action-button:hover {
      border-color: rgba(96, 165, 250, 0.72);
    }

    .small-action-button:disabled {
      cursor: not-allowed;
      opacity: 0.45;
    }

    .ticket-workflow-note {
      color: var(--muted);
      font-size: 0.82rem;
      margin-top: 0.25rem;
    }

    .ticket-signal-badge {
      display: inline-flex;
      align-items: center;
      width: fit-content;
      border: 1px solid rgba(148, 163, 184, 0.22);
      border-radius: 999px;
      padding: 4px 9px;
      font-size: 11px;
      font-weight: 900;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      white-space: nowrap;
    }

    .ticket-signal-actionable {
      border-color: rgba(248, 113, 113, 0.38);
      background: rgba(127, 29, 29, 0.22);
      color: #fecaca;
    }

    .ticket-signal-meaningful-change {
      border-color: rgba(34, 211, 238, 0.38);
      background: rgba(8, 145, 178, 0.18);
      color: #a5f3fc;
    }

    .ticket-signal-baseline-context {
      border-color: rgba(148, 163, 184, 0.28);
      background: rgba(51, 65, 85, 0.24);
      color: #cbd5e1;
    }

    .ticket-signal-unknown {
      border-color: rgba(148, 163, 184, 0.2);
      background: rgba(15, 23, 42, 0.55);
      color: #94a3b8;
    }

  </style>
</head>
<body class="dashboard-shell-refresh-v017">
  <header class="executive-header">
    <div>
      <div class="executive-kicker">DeltaAegis SIEM Console</div>
      <h1>Executive Security Overview</h1>
      <p>Analyst-focused network-state monitoring for current exposure, investigation priority, NetSniper intelligence, MAC-port behavior, alerts, and scan orchestration.</p>
    </div>
    <div class="executive-status-grid" aria-label="Dashboard status">
      <div class="executive-status-pill"><span>Mode</span><span>Local Dashboard</span></div>
      <div class="executive-status-pill"><span>Primary View</span><span>Command Center</span></div>
      <div class="executive-status-pill"><span>Release</span><span>v0.19 Filters</span></div>
    </div>
  </header>

  <main class="dashboard-main">
    <div id="error" class="error"></div>

    <nav class="dashboard-tabs executive-tabs" aria-label="DeltaAegis dashboard sections">
      <button type="button" class="tab-button" data-tab-target="overview">Executive</button>
      <button type="button" class="tab-button" data-tab-target="command-center">Tickets</button>
      <button type="button" class="tab-button" data-tab-target="investigations">Investigations</button>
      <button type="button" class="tab-button" data-tab-target="risk">Risk Analysis</button>
      <button type="button" class="tab-button" data-tab-target="port-behavior">Network Activity</button>
      <button type="button" class="tab-button" data-tab-target="assets">Taxonomy</button>
      <button type="button" class="tab-button" data-tab-target="intelligence">Intelligence</button>
      <button type="button" class="tab-button" data-tab-target="events">Security Events</button>
      <button type="button" class="tab-button" data-tab-target="alerts">Alarms</button>
      <button type="button" class="tab-button" data-tab-target="scan-jobs">Data Sources</button>
    </nav>

    <section class="executive-overview" data-tab-panel="overview">
      <div class="executive-kicker">Executive Overview</div>
      <h2>Network Investigation at a Glance</h2>
      <p>
        Start with the Command Center queue, then drill into risk, MAC-port behavior,
        asset intelligence, alerts, events, and scan jobs without leaving the dashboard.
      </p>
      <div class="executive-objectives">
        <div class="executive-objective">
          <strong>Prioritize</strong>
          <span>Identify the highest-impact subjects using current risk and open alert context.</span>
        </div>
        <div class="executive-objective">
          <strong>Explain</strong>
          <span>Show why a device matters through evidence, classification, and behavior changes.</span>
        </div>
        <div class="executive-objective">
          <strong>Act</strong>
          <span>Surface recommended next steps while preserving dashboard safety.</span>
        </div>
      </div>
    </section>

    <section class="card" data-tab-panel="command-center">
      <h2>Tickets: Investigation Queue</h2>
      <p class="muted">
        Prioritized analyst queue combining current risk, MAC-port behavior, open alerts,
        recent delta events, asset identity, classification, and recommended next action.
      </p>
      <div id="investigation-center-filters" class="ticket-filter-panel">
        <label>
          Workflow
          <select id="ticket-status-filter">
            <option value="ALL">All workflow states</option>
            <option value="OPEN">Open</option>
            <option value="IN_REVIEW">In Review</option>
            <option value="RESOLVED">Resolved</option>
            <option value="SUPPRESSED">Suppressed</option>
          </select>
        </label>
        <label>
          Signal
          <select id="ticket-signal-filter">
            <option value="ALL">All signal labels</option>
            <option value="ACTIONABLE">Actionable</option>
            <option value="MEANINGFUL_CHANGE">Meaningful change</option>
            <option value="BASELINE_CONTEXT">Baseline context</option>
          </select>
        </label>
        <label>
          Triage Bucket
          <select id="triage-bucket-filter">
            <option value="ALL">All buckets</option>
          </select>
        </label>
        <label>
          Triage Urgency
          <select id="triage-urgency-filter">
            <option value="ALL">All urgencies</option>
          </select>
        </label>
        <button id="apply-ticket-filters" class="small-action-button">Apply filters</button>
        <button id="clear-ticket-filters" class="small-action-button">Clear filters</button>
      </div>
      <div id="investigation-center-summary" class="grid"></div>
      <div id="investigation-triage-summary" class="triage-summary-grid"></div>
      <div id="ticket-evidence-panel" class="evidence-drilldown-panel">
        <div class="evidence-drilldown-header">
          <div>
            <h3>Ticket Evidence Drilldown</h3>
            <p class="muted">Select View Evidence on an Investigation Center ticket to inspect risk reasons, alerts, events, port behavior, ticket history, and recommended action context.</p>
          </div>
        </div>
      </div>
      <div id="investigation-ticket-cards" class="ticket-cards-grid"></div>
      <p class="muted siem-ticket-table-note">Detailed queue table for sorting, copy/paste review, and compatibility with earlier DeltaAegis dashboard workflows.</p>
      <table class="siem-ticket-table">
        <thead>
          <tr>
            <th>Priority</th>
            <th>Signal</th>
              <th>Workflow</th>
            <th>Subject</th>
            <th>IP</th>
            <th>MAC</th>
            <th>Device / Role</th>
            <th>Triggers</th>
            <th>Why Review?</th>
            <th>Recommended Action</th>
            <th>Counts</th>
          </tr>
        </thead>
        <tbody id="investigation-center-body"></tbody>
      </table>
    </section>

    <section class="card explain" data-tab-panel="overview">
      <h2>What am I looking at?</h2>
      <p>
        DeltaAegis compares NetSniper scans over time. The latest scan represents the current observed network state.
        The baseline scan is the previous known state used for comparison.
      </p>
      <div class="callout">
        A <strong>delta</strong> means something changed between scans, such as a new asset, missing asset,
        opened service, closed service, or new NetSniper finding.
      </div>
    </section>

    <section class="grid" id="metrics" data-tab-panel="overview"></section>

    <section class="siem-analytics-grid" data-tab-panel="overview">
      <div class="card siem-chart-panel">
        <h3>Security Events: Top Categories</h3>
        <p class="siem-chart-subtitle">Recent delta-event categories in the selected dashboard scope.</p>
        <div id="chart-event-categories"></div>
      </div>

      <div class="card siem-chart-panel">
        <h3>Risk Analysis: Priority Distribution</h3>
        <p class="siem-chart-subtitle">Current-risk level distribution from the latest accepted snapshot.</p>
        <div id="chart-risk-levels"></div>
      </div>

      <div class="card siem-chart-panel">
        <h3>Taxonomy: Asset Classification Mix</h3>
        <p class="siem-chart-subtitle">Top observed device classifications from the current asset inventory.</p>
        <div id="chart-classification-mix"></div>
      </div>

      <div class="card siem-chart-panel">
        <h3>Network Activity: MAC-Port Behavior</h3>
        <p class="siem-chart-subtitle">MAC-backed port behavior changes across accepted scans.</p>
        <div id="chart-port-behavior"></div>
      </div>
    </section>

    <section class="card" data-tab-panel="overview">
      <h2>Network Scopes</h2>
      <p class="muted">Choose which subnet scope the dashboard should display. Deltas are only meaningful inside the same network scope.</p>
      <div id="selected-scope" class="callout">Viewing all network scopes.</div>
      <div id="scope-links" class="scope-links"></div>
    </section>

    <section class="card" data-tab-panel="overview">
      <h2>Current Network State</h2>
      <p class="muted">Latest accepted snapshot for the selected scope. These cards are current-state inventory and intelligence numbers, not historical totals.</p>
      <div id="current-state"></div>
    </section>

    <section class="card" data-tab-panel="overview">
      <h2>NetSniper Scan Context</h2>
      <p class="muted">Shows the latest NetSniper scan, the baseline scan used for delta comparison, and identity coverage for MAC/IP tracking.</p>
      <div class="scan-grid" id="scan-context"></div>
    </section>


    <section class="card" data-tab-panel="scan-jobs">
      <h2>Data Sources: Scan Jobs</h2>
      <p class="muted">
        Read-only NetSniper scan orchestration history. Start scans from the CLI with
        <code>deltaaegis scan-start --target &lt;private-cidr&gt;</code>.
      </p>
      <table>
        <thead>
          <tr>
            <th>Status</th>
            <th>Job</th>
            <th>Target</th>
            <th>Created</th>
            <th>Updated</th>
            <th>Bundle</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody id="scan-jobs-body"></tbody>
      </table>
    </section>

    <section class="card" data-tab-panel="assets">
      <h2>Taxonomy: Asset Inventory</h2>
      <p class="muted">Current scoped asset lifecycle view. Use the scope selector above to isolate a subnet.</p>
      <table>
        <thead>
          <tr>
            <th>Scope</th>
            <th>State</th>
            <th>Identity</th>
            <th>IP</th>
            <th>MAC</th>
            <th>Classification</th>
            <th>Decision</th>
            <th>Confidence</th>
            <th>Evidence</th>
            <th>Contradictions</th>
            <th>Asset</th>
            <th>Last Seen</th>
          </tr>
        </thead>
        <tbody id="asset-inventory-body"></tbody>
      </table>
    </section>

    <section class="card" id="asset-detail-card" data-tab-panel="investigations">
      <h2>Asset Detail</h2>
      <p class="muted">Click an asset in the inventory table to view lifecycle state, observations, events, alerts, services, findings, and annotation context.</p>
      <div class="asset-detail-controls">
        <select id="asset-detail-select">
          <option value="">Select an asset from the current dashboard scope...</option>
        </select>
        <button type="button" id="asset-detail-load">Load Asset</button>
      </div>
      <div id="asset-detail-body" class="callout">No asset selected.</div>
    </section>

    <section class="card" data-tab-panel="risk">
      <h2>Current Risk Subjects</h2>
      <p class="muted">Current risk is limited to assets present in the latest accepted snapshot for the selected scope.</p>
      <table>
        <thead>
          <tr><th>Level</th><th>Score</th><th>Subject</th><th>IP</th><th>MAC</th><th>Identity</th><th>Owner</th><th>Role</th><th>Open Alerts</th><th>Current Findings</th><th>Why This Level?</th></tr>
        </thead>
        <tbody id="risk-body"></tbody>
      </table>

      <h3>Historical Risk Context</h3>
      <p class="muted">Historical context is based on past delta events and alerts. It may include assets that are not present in the latest accepted snapshot.</p>
      <table>
        <thead>
          <tr><th>Level</th><th>Score</th><th>Subject</th><th>IP</th><th>MAC</th><th>Identity</th><th>Owner</th><th>Role</th><th>Open Alerts</th><th>Events</th><th>Why This Level?</th></tr>
        </thead>
        <tbody id="historical-risk-body"></tbody>
      </table>
    </section>


    <section class="card" data-tab-panel="port-behavior">
      <h2>MAC-Port Behavior</h2>
      <p class="muted">
        Correlates MAC-backed device identity with open-port history across accepted scans.
        Use this to spot ports that appeared unexpectedly or changed open/not-observed state over time.
      </p>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Behavior</th>
            <th>MAC</th>
            <th>IP</th>
            <th>Device</th>
            <th>Port</th>
            <th>Current</th>
            <th>Seen</th>
            <th>Missing</th>
            <th>Transitions</th>
            <th>Reason</th>
          </tr>
        </thead>
        <tbody id="port-behavior-body"></tbody>
      </table>
    </section>

    <section class="card" data-tab-panel="events">
      <h2>Security Events</h2>
      <table>
        <thead>
          <tr><th>ID</th><th>Scan</th><th>Baseline</th><th>Severity</th><th>Type</th><th>Subject</th><th>IP</th><th>MAC</th><th>Identity</th><th>Created</th><th>Summary</th></tr>
        </thead>
        <tbody id="events-body"></tbody>
      </table>
    </section>

    <section class="card" data-tab-panel="alerts">
      <h2>Alarms</h2>
      <table>
        <thead>
          <tr><th>ID</th><th>Status</th><th>Severity</th><th>Subject</th><th>Type</th><th>IP</th><th>MAC</th><th>Identity</th><th>Summary</th></tr>
        </thead>
        <tbody id="alerts-body"></tbody>
      </table>
    </section>

    <section class="card" data-tab-panel="assets">
      <h2>Asset Annotations</h2>
      <table>
        <thead>
          <tr>
            <th>Asset</th>
            <th>IP</th>
            <th>MAC</th>
            <th>Identity</th>
            <th>Owner</th>
            <th>Role</th>
            <th>Criticality</th>
            <th>Notes</th>
          </tr>
        </thead>
        <tbody id="annotations"></tbody>
      </table>
    </section>

    <section class="card" data-tab-panel="overview">
      <h2>Risk and Identity Legend</h2>
      <div class="legend-grid">
        <div>
          <div class="label">Risk score</div>
          <ul class="legend-list">
            <li><strong class="CRITICAL">85–100 Critical</strong> — review immediately.</li>
            <li><strong class="HIGH">65–84 High</strong> — prioritize after critical items.</li>
            <li><strong class="MEDIUM">35–64 Medium</strong> — review when higher-risk items are understood.</li>
            <li><strong class="LOW">15–34 Low</strong> — track but usually not urgent.</li>
            <li><strong class="INFO">0–14 Info</strong> — informational or context-only.</li>
          </ul>
        </div>
        <div>
          <div class="label">Identity confidence</div>
          <ul class="legend-list">
            <li><strong class="identity-strong">Strong identity</strong> — MAC and IP were both observed.</li>
            <li><strong class="identity-partial">Partial identity</strong> — only MAC or only IP was observed.</li>
            <li><strong class="identity-unknown">Unknown identity</strong> — no MAC/IP mapping was found.</li>
          </ul>
        </div>
        <div>
          <div class="label">How risk is calculated</div>
          <ul class="legend-list">
            <li>Event severity</li>
            <li>Open or acknowledged alerts</li>
            <li>Repeated recent activity</li>
            <li>Asset criticality</li>
            <li>Missing owner or asset context</li>
            <li>NetSniper role classification, contradictions, and exposed services</li>
            <li>Current findings on assets present in the latest accepted snapshot</li>
          </ul>
        </div>
      </div>
    </section>

    <section class="card" data-tab-panel="overview">
      <h2>Recommended Next Steps</h2>
      <ol class="steps" id="recommendations"></ol>
    </section>
  </main>

  <script>
    function esc(value) {
      if (value === null || value === undefined || value === "") return "-";
      return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;");
    }

    const DASHBOARD_TABS = [
      "overview",
      "command-center",
      "investigations",
      "risk",
      "port-behavior",
      "assets",
      "intelligence",
      "events",
      "alerts",
      "scan-jobs"
    ];

    let activeDashboardTab = null;

    function applyDashboardTabState() {
      const selected = DASHBOARD_TABS.includes(activeDashboardTab)
        ? activeDashboardTab
        : "overview";

      document.querySelectorAll("[data-tab-target]").forEach(button => {
        const isActive = button.dataset.tabTarget === selected;
        button.classList.toggle("active", isActive);
        button.setAttribute("aria-selected", isActive ? "true" : "false");
      });

      document.querySelectorAll("[data-tab-panel]").forEach(panel => {
        panel.hidden = panel.dataset.tabPanel !== selected;
      });
    }

    function activateDashboardTab(tabName) {
      activeDashboardTab = DASHBOARD_TABS.includes(tabName) ? tabName : "overview";

      try {
        window.localStorage.setItem("deltaaegis-dashboard-tab", activeDashboardTab);
      } catch (error) {
        // localStorage may be unavailable in hardened browser profiles.
      }

      applyDashboardTabState();
    }

    function setupDashboardTabs() {
      document.querySelectorAll("[data-tab-target]").forEach(button => {
        if (button.dataset.bound === "true") return;

        button.addEventListener("click", () => {
          activateDashboardTab(button.dataset.tabTarget);
        });

        button.dataset.bound = "true";
      });

      if (!activeDashboardTab) {
        let saved = "overview";

        try {
          saved = window.localStorage.getItem("deltaaegis-dashboard-tab") || "overview";
        } catch (error) {
          saved = "overview";
        }

        activateDashboardTab(saved);
      } else {
        applyDashboardTabState();
      }
    }


    async function api(path) {
      const response = await fetch(path, {cache: "no-store"});

      if (!response.ok) {
        throw new Error(path + " returned HTTP " + response.status);
      }

      return await response.json();
    }


    function identityClass(value) {
      const text = String(value || "").toLowerCase();

      if (text.includes("strong")) return "identity-strong";
      if (text.includes("partial")) return "identity-partial";
      return "identity-unknown";
    }

    function identityBadge(value) {
      const label = value || "Unknown identity";
      return `<span class="${identityClass(label)}">${esc(label)}</span>`;
    }

    function parseScanTime(value) {
      if (!value) return null;

      let parsed = Date.parse(value);

      if (Number.isNaN(parsed) && String(value).indexOf(" ") > -1) {
        parsed = Date.parse(String(value).replace(" ", "T"));
      }

      if (Number.isNaN(parsed)) return null;

      return new Date(parsed);
    }

    function scanTimestamp(scan) {
      if (!scan) return null;
      return scan.created_at || scan.imported_at || scan.last_seen_at || null;
    }

    function scanFreshness(scan) {
      const timestamp = scanTimestamp(scan);
      const parsed = parseScanTime(timestamp);

      if (!parsed) {
        return {
          label: "Unknown",
          detail: "No scan timestamp was found.",
          className: "status-unknown",
          stale: false
        };
      }

      const ageMs = Date.now() - parsed.getTime();
      const ageHours = ageMs / (1000 * 60 * 60);
      const ageDays = ageHours / 24;

      let ageLabel = "";

      if (ageHours < 1) {
        ageLabel = Math.max(0, Math.round(ageMs / (1000 * 60))) + " minutes old";
      } else if (ageHours < 48) {
        ageLabel = Math.round(ageHours) + " hours old";
      } else {
        ageLabel = Math.round(ageDays) + " days old";
      }

      if (ageHours > 24) {
        return {
          label: "Stale",
          detail: ageLabel + " — run a new NetSniper scan before relying on this view.",
          className: "status-stale",
          stale: true
        };
      }

      return {
        label: "Current",
        detail: ageLabel,
        className: "status-current",
        stale: false
      };
    }

    function identityCoverage(summary) {
      summary = summary || {};
      const total = Number(summary.observed_assets || 0);
      const both = Number(summary.assets_with_ip_and_mac || 0);

      if (!total) return "No observed assets";

      const percent = Math.round((both / total) * 100);
      return `${percent}% strong identity coverage`;
    }


    function metric(label, value) {
      return `<div class="metric-card"><div class="label">${esc(label)}</div><div class="metric-value">${esc(value)}</div></div>`;
    }

    function formatPercent(value) {
      const number = Number(value || 0);
      if (!Number.isFinite(number)) return "0%";
      return `${Math.round(number * 100)}%`;
    }


    function countBy(items, keyFn) {
      const counts = new Map();

      (Array.isArray(items) ? items : []).forEach(item => {
        const key = keyFn(item) || "Unknown";
        counts.set(key, (counts.get(key) || 0) + 1);
      });

      return Array.from(counts.entries())
        .map(([label, value]) => ({label, value}))
        .sort((a, b) => b.value - a.value || String(a.label).localeCompare(String(b.label)));
    }

    function renderHorizontalBars(targetId, rows, emptyMessage, limit = 8) {
      const target = document.getElementById(targetId);
      if (!target) return;

      const items = (Array.isArray(rows) ? rows : [])
        .filter(row => Number(row.value || 0) > 0)
        .slice(0, limit);

      if (!items.length) {
        target.innerHTML = `<p class="muted">${esc(emptyMessage || "No chart data available.")}</p>`;
        return;
      }

      const maxValue = Math.max(...items.map(row => Number(row.value || 0)), 1);

      target.innerHTML = `
        <div class="siem-bar-list">
          ${items.map(row => {
            const value = Number(row.value || 0);
            const width = Math.max(4, Math.round((value / maxValue) * 100));
            return `
              <div class="siem-bar-row">
                <div class="siem-bar-label" title="${esc(row.label)}">${esc(row.label)}</div>
                <div class="siem-bar-track">
                  <div class="siem-bar-fill" style="width: ${width}%"></div>
                </div>
                <div class="siem-bar-value">${esc(value)}</div>
              </div>
            `;
          }).join("")}
        </div>
      `;
    }

    function renderDistributionPanel(targetId, rows, emptyMessage) {
      const target = document.getElementById(targetId);
      if (!target) return;

      const items = (Array.isArray(rows) ? rows : [])
        .filter(row => Number(row.value || 0) > 0)
        .slice(0, 6);

      if (!items.length) {
        target.innerHTML = `<p class="muted">${esc(emptyMessage || "No distribution data available.")}</p>`;
        return;
      }

      const total = items.reduce((sum, row) => sum + Number(row.value || 0), 0);

      target.innerHTML = `
        <div class="siem-donut-wrap">
          <div class="siem-donut" aria-hidden="true"></div>
          <div class="siem-legend">
            ${items.map(row => {
              const value = Number(row.value || 0);
              const percent = total ? Math.round((value / total) * 100) : 0;
              return `
                <div class="siem-legend-row">
                  <span>${esc(row.label)}</span>
                  <strong>${esc(value)} · ${esc(percent)}%</strong>
                </div>
              `;
            }).join("")}
          </div>
        </div>
      `;
    }

    function renderExecutiveCharts(summary, currentRisk, portBehavior, investigationCenter, assets, events, alerts) {
      const eventRows = countBy(events, row => row.event_type || row.type || row.severity || "Unknown event");
      const riskRows = countBy(currentRisk, row => row.level || "INFO");
      const classificationRows = countBy(assets, row =>
        row.classification_display_type ||
        row.classification ||
        row.device_type ||
        "Unknown"
      );
      const portRows = countBy(portBehavior, row => row.behavior || row.severity || "No port behavior");

      renderHorizontalBars(
        "chart-event-categories",
        eventRows,
        "No recent security events matched this scope.",
        8
      );

      renderDistributionPanel(
        "chart-risk-levels",
        riskRows,
        "No current-risk subjects are available for this scope."
      );

      renderHorizontalBars(
        "chart-classification-mix",
        classificationRows,
        "No asset classification data is available for this scope.",
        8
      );

      renderHorizontalBars(
        "chart-port-behavior",
        portRows,
        "No MAC-port behavior changes were detected for this scope.",
        8
      );
    }


    function renderCurrentState(state) {
      const target = document.getElementById("current-state");

      if (!target) return;

      if (!state || !state.available) {
        target.innerHTML = `<p class="muted">${esc((state && state.message) || "No accepted current-state snapshot is available for this scope.")}</p>`;
        return;
      }

      target.innerHTML = `
        <div class="cards">
          <div class="card">
            <div class="label">Current Assets</div>
            <div class="metric">${esc(state.assets || 0)}</div>
          </div>
          <div class="card">
            <div class="label">Intelligence Hosts</div>
            <div class="metric">${esc(state.intelligence_hosts || 0)}</div>
          </div>
          <div class="card">
            <div class="label">Service-Observed Assets</div>
            <div class="metric">${esc(state.service_observed_assets || 0)}</div>
          </div>
          <div class="card">
            <div class="label">Discovery / No Open Service</div>
            <div class="metric">${esc(state.discovery_only_or_no_open_service_assets || 0)}</div>
          </div>
          <div class="card">
            <div class="label">Classified</div>
            <div class="metric">${esc(state.classified || 0)}</div>
          </div>
          <div class="card">
            <div class="label">Review / Possible</div>
            <div class="metric">${esc(state.possible_or_review || 0)}</div>
          </div>
          <div class="card">
            <div class="label">Unknown</div>
            <div class="metric">${esc(state.unknown || 0)}</div>
          </div>
          <div class="card">
            <div class="label">False Confidence</div>
            <div class="metric">${esc(state.false_confidence_candidates || 0)}</div>
          </div>
          <div class="card">
            <div class="label">MAC Identity</div>
            <div class="metric">${esc(formatPercent(state.identity_coverage))}</div>
          </div>
        </div>

        <div class="detail-box">
          <div><span>Latest Scan</span><span><code>${esc(state.scan_id || "-")}</code></span></div>
          <div><span>Scope</span><span><code>${esc(state.network_scope || state.selected_scope || "-")}</code></span></div>
          <div><span>Target</span><span><code>${esc(state.target || "-")}</code></span></div>
          <div><span>Scanner</span><span>${esc(state.scanner_version || "-")}</span></div>
          <div><span>Quality</span><span>${esc(state.quality_status || "-")}</span></div>
          <div><span>Imported</span><span>${esc(state.imported_at || "-")}</span></div>
        </div>
      `;
    }


    function renderMetrics(summary) {
      document.getElementById("metrics").innerHTML = [
        metric("Snapshots", summary.snapshots),
        metric("Events", summary.events),
        metric("Alerts", summary.alerts),
        metric("Open Alerts", summary.open_alerts),
        metric("Annotations", summary.asset_annotations)
      ].join("");
    }



    function selectedScope() {
      return new URLSearchParams(window.location.search).get("scope") || "";
    }

    function scopedPath(path) {
      const scope = selectedScope();

      if (!scope) return path;

      const separator = path.includes("?") ? "&" : "?";
      return path + separator + "scope=" + encodeURIComponent(scope);
    }

    function renderScopes(scopes) {
      const selected = selectedScope();
      const links = [];

      links.push(`<a class="${selected ? "" : "active"}" href="/">All scopes</a>`);

      for (const scope of scopes) {
        const name = scope.network_scope || "";
        const active = selected === name ? "active" : "";
        links.push(
          `<a class="${active}" href="/?scope=${encodeURIComponent(name)}">${esc(name)} · ${esc(scope.snapshots)} scans · ${esc(scope.open_alerts)} open alerts</a>`
        );
      }

      const scopeLinks = document.getElementById("scope-links");
      const selectedScopeBox = document.getElementById("selected-scope");

      if (scopeLinks) {
        scopeLinks.innerHTML = links.join("");
      }

      if (selectedScopeBox) {
        selectedScopeBox.innerHTML = selected
          ? `Viewing scope: <strong>${esc(selected)}</strong>`
          : "Viewing all network scopes.";
      }
    }


    function scanCard(title, scan) {
      if (!scan) {
        return `<div class="card">
          <div class="label">${esc(title)}</div>
          <p class="muted">No scan data found.</p>
        </div>`;
      }

      const summary = scan.asset_summary || {};
      const freshness = scanFreshness(scan);

      return `<div class="card">
        <div class="label">${esc(title)}</div>
        <div class="kv">
          <div><span>Status</span><span class="status ${freshness.className}">${esc(freshness.label)}</span></div>
          <div><span>Scan age</span><span>${esc(freshness.detail)}</span></div>
          <div><span>Scan ID</span><code>${esc(scan.scan_id)}</code></div>
          <div><span>Created</span><span>${esc(scan.created_at)}</span></div>
          <div><span>Imported</span><span>${esc(scan.imported_at)}</span></div>
          <div><span>Scanner</span><span>${esc(scan.scanner_version)}</span></div>
          <div><span>Contract</span><span>${esc(scan.telemetry_contract)}</span></div>
          <div><span>Observed Assets</span><span>${esc(summary.observed_assets)}</span></div>
          <div><span>Observed IPs</span><span>${esc(summary.observed_ips)}</span></div>
          <div><span>Observed MACs</span><span>${esc(summary.observed_macs)}</span></div>
          <div><span>IP + MAC Assets</span><span>${esc(summary.assets_with_ip_and_mac)}</span></div>
          <div><span>Identity Coverage</span><span>${esc(identityCoverage(summary))}</span></div>
          <div><span>Source</span><code>${esc(scan.source_path || scan.source_file || scan.bundle_path || scan.manifest_path)}</code></div>
        </div>
      </div>`;
    }

    function scanJobStatusClass(status) {
      const value = String(status || "").toUpperCase();

      if (value === "COMPLETED") return "status-current";
      if (value === "RUNNING" || value === "QUEUED") return "status-stale";
      if (value === "FAILED") return "severity-critical";

      return "status-unknown";
    }

    function renderScanJobs(jobs) {
      const tbody = document.getElementById("scan-jobs-body");

      if (!tbody) return;

      const rows = Array.isArray(jobs) ? jobs : [];

      if (!rows.length) {
        tbody.innerHTML = `<tr><td colspan="7" class="muted">No scan jobs found for the current dashboard scope.</td></tr>`;
        return;
      }

      tbody.innerHTML = rows.map(job => {
        const status = String(job.status || "UNKNOWN").toUpperCase();
        const bundle = job.bundle_path
          ? `<code>${esc(job.bundle_path)}</code>`
          : `<span class="muted">-</span>`;

        const message = job.message
          ? esc(job.message)
          : `<span class="muted">-</span>`;

        return `
          <tr>
            <td><span class="status ${scanJobStatusClass(status)}">${esc(status)}</span></td>
            <td><code>${esc(job.job_id || "-")}</code></td>
            <td><code>${esc(job.target || "-")}</code></td>
            <td>${esc(job.created_at || "-")}</td>
            <td>${esc(job.updated_at || "-")}</td>
            <td>${bundle}</td>
            <td>${message}</td>
          </tr>
        `;
      }).join("");
    }



    function renderScanContext(context) {
      const pairs = context.delta_scan_pairs || [];
      const pairRows = pairs.map(pair => `
        <tr>
          <td><code>${esc(pair.scan_id)}</code></td>
          <td><code>${esc(pair.baseline_scan_id)}</code></td>
          <td>${esc(pair.event_count)}</td>
          <td>${esc(pair.latest_event_at)}</td>
        </tr>
      `).join("") || `<tr><td colspan="4" class="muted">No delta scan pairs found.</td></tr>`;

      document.getElementById("scan-context").innerHTML = `
        ${scanCard("Latest NetSniper Scan", context.latest_scan)}
        ${scanCard("Baseline Scan", context.baseline_scan)}
        <div class="card">
          <div class="label">Delta Comparisons</div>
          <table>
            <thead>
              <tr>
                <th>Scan</th>
                <th>Baseline</th>
                <th>Events</th>
                <th>Latest Event</th>
              </tr>
            </thead>
            <tbody>${pairRows}</tbody>
          </table>
        </div>
      `;
    }





    function setupCollapsibleCards_DISABLED_BY_TABS() {
      document.querySelectorAll("section.card").forEach((card, index) => {
        if (card.dataset.collapsibleReady === "true") return;

        const title = card.querySelector("h2");
        if (!title) return;

        const body = document.createElement("div");
        body.className = "card-body";

        let node = title.nextSibling;
        while (node) {
          const next = node.nextSibling;
          body.appendChild(node);
          node = next;
        }

        const header = document.createElement("div");
        header.className = "card-header";

        const toggle = document.createElement("button");
        toggle.type = "button";
        toggle.className = "card-toggle";

        card.insertBefore(header, title);
        header.appendChild(title);
        header.appendChild(toggle);
        card.appendChild(body);

        const defaultCollapsed = index >= 4;

        if (defaultCollapsed) {
          body.classList.add("collapsed");
          toggle.textContent = "Expand";
        } else {
          toggle.textContent = "Collapse";
        }

        toggle.addEventListener("click", () => {
          body.classList.toggle("collapsed");
          toggle.textContent = body.classList.contains("collapsed") ? "Expand" : "Collapse";
        });

        card.dataset.collapsibleReady = "true";
      });
    }

    function detailTable(title, rows, columns) {
      if (!rows || !rows.length) {
        return `<h3>${esc(title)}</h3><p class="muted">No ${esc(title).toLowerCase()} recorded.</p>`;
      }

      const header = columns.map(col => `<th>${esc(col.label)}</th>`).join("");

      const body = rows.map(row => `
        <tr>
          ${columns.map(col => `<td>${col.code ? `<code>${esc(row[col.key])}</code>` : esc(row[col.key])}</td>`).join("")}
        </tr>
      `).join("");

      return `
        <h3>${esc(title)}</h3>
        <table>
          <thead><tr>${header}</tr></thead>
          <tbody>${body}</tbody>
        </table>
      `;
    }


    function renderAssetSelector(rows) {
      const select = document.getElementById("asset-detail-select");
      const button = document.getElementById("asset-detail-load");

      if (!select || !button) return;

      if (!rows || !rows.length) {
        select.innerHTML = `<option value="">No assets available in this scope</option>`;
        return;
      }

      select.innerHTML = `
        <option value="">Select an asset from the current dashboard scope...</option>
        ${rows.map(row => `
          <option value="${esc(row.asset_key)}">
            ${esc(row.current_ip)} | ${esc(row.mac_address)} | ${esc(row.asset_key)}
          </option>
        `).join("")}
      `;

      if (button.dataset.bound !== "true") {
        button.addEventListener("click", () => {
          if (select.value) {
            loadAssetDetail(select.value);
          }
        });

        select.addEventListener("change", () => {
          if (select.value) {
            loadAssetDetail(select.value);
          }
        });

        button.dataset.bound = "true";
      }
    }

    function renderAssetDetail(payload) {
      const box = document.getElementById("asset-detail-body");

      if (!box) return;

      if (!payload || !payload.found) {
        if (payload && payload.ambiguous && payload.matches && payload.matches.length) {
          box.innerHTML = `
            <p><strong>Multiple assets matched.</strong> Choose a network scope to disambiguate this identifier.</p>
            ${detailTable("Matches", payload.matches, [
              {key: "network_scope", label: "Scope", code: true},
              {key: "current_ip", label: "IP", code: true},
              {key: "mac_address", label: "MAC", code: true},
              {key: "asset_key", label: "Asset", code: true}
            ])}
          `;
          return;
        }

        box.innerHTML = `<p>${esc(payload && payload.message ? payload.message : "No asset selected.")}</p>`;
        return;
      }

      const asset = payload.asset || {};
      const observation = payload.latest_observation || {};
      const annotation = payload.annotation || {};
      const investigation = payload.investigation || {};
      const reviewContext = investigation.review_context || {};
      const persistedStatus = investigation.persisted_status || {};
      const investigationStatuses = [
        "NEW",
        "REVIEWING",
        "NEEDS_OWNER",
        "EXPECTED",
        "FALSE_POSITIVE",
        "MONITORING",
        "RESOLVED"
      ];
      const investigationStatusOptions = investigationStatuses
        .map(status => `
          <option value="${esc(status)}" ${status === investigation.status ? "selected" : ""}>
            ${esc(status)}
          </option>
        `)
        .join("");
      const recommendedSteps = (investigation.recommended_next_steps || [])
        .map(item => `<li>${esc(item)}</li>`)
        .join("");

      box.innerHTML = `
        <div class="detail-grid">
          <div class="detail-box"><div class="label">Asset</div><code>${esc(asset.asset_key)}</code></div>
          <div class="detail-box"><div class="label">Scope</div><code>${esc(asset.network_scope)}</code></div>
          <div class="detail-box"><div class="label">Current IP</div><code>${esc(asset.current_ip)}</code></div>
          <div class="detail-box"><div class="label">MAC</div><code>${esc(asset.mac_address)}</code></div>
          <div class="detail-box"><div class="label">State</div>${esc(asset.state)}</div>
          <div class="detail-box"><div class="label">Identity</div>${esc(asset.identity_class)}</div>
          <div class="detail-box"><div class="label">First Seen</div>${esc(asset.first_seen_at)}</div>
          <div class="detail-box"><div class="label">Last Seen</div>${esc(asset.last_seen_at)}</div>
        </div>

        <h3>Latest Observation</h3>
        <div class="detail-grid">
          <div class="detail-box"><div class="label">Scan</div><code>${esc(observation.scan_id)}</code></div>
          <div class="detail-box"><div class="label">Device Type</div>${esc(observation.device_type)}</div>
          <div class="detail-box"><div class="label">Severity</div>${esc(observation.severity)}</div>
          <div class="detail-box"><div class="label">Identity Source</div>${esc(observation.identity_source)}</div>
        </div>

        <h3>NetSniper Intelligence</h3>
        <div class="detail-grid">
          <div class="detail-box"><div class="label">Classification</div>${esc(observation.classification_display_type || observation.device_type || "Unknown")}</div>
          <div class="detail-box"><div class="label">Decision</div>${esc(observation.classification_display_decision || "unknown")}</div>
          <div class="detail-box"><div class="label">Confidence</div>${esc(observation.classification_display_confidence)}</div>
          <div class="detail-box"><div class="label">Confidence Label</div>${esc(observation.classification_confidence_label)}</div>
          <div class="detail-box"><div class="label">Method</div>${esc(observation.classification_method)}</div>
          <div class="detail-box"><div class="label">Evidence Count</div>${esc(observation.classification_evidence_count || 0)}</div>
          <div class="detail-box"><div class="label">Contradictions</div>${esc(observation.classification_contradiction_count || 0)}</div>
          <div class="detail-box"><div class="label">Candidates</div>${esc(observation.classification_candidate_count || 0)}</div>
        </div>

        ${detailTable("Classification Evidence", observation.classification_evidence || [], [
          {key: "candidate", label: "Candidate"},
          {key: "source", label: "Source"},
          {key: "value", label: "Value"},
          {key: "points", label: "Points"},
          {key: "reason", label: "Reason"}
        ])}

        ${detailTable("Classification Contradictions", observation.classification_contradictions || [], [
          {key: "id", label: "ID"},
          {key: "reason", label: "Reason"}
        ])}

        <h3>Annotation</h3>
        <div class="detail-grid">
          <div class="detail-box"><div class="label">Owner</div>${esc(annotation.owner)}</div>
          <div class="detail-box"><div class="label">Role</div>${esc(annotation.role)}</div>
          <div class="detail-box"><div class="label">Criticality</div>${esc(annotation.criticality)}</div>
          <div class="detail-box"><div class="label">Notes</div>${esc(annotation.notes)}</div>
        </div>

        <h3>Investigation Summary</h3>
        <div class="detail-grid">
          <div class="detail-box"><div class="label">Status</div>${esc(investigation.status || "NEW")}</div>
          <div class="detail-box"><div class="label">Status Source</div>${esc(investigation.status_source || "inferred")}</div>
          <div class="detail-box"><div class="label">Inferred Status</div>${esc(investigation.inferred_status || "NEW")}</div>
          <div class="detail-box"><div class="label">Classification</div>${esc(reviewContext.classification_type || "Unknown / Ambiguous")}</div>
          <div class="detail-box"><div class="label">Decision</div>${esc(reviewContext.classification_decision || "unknown")}</div>
          <div class="detail-box"><div class="label">Confidence</div>${esc(reviewContext.classification_confidence || 0)}</div>
          <div class="detail-box"><div class="label">Alerts</div>${esc(reviewContext.alert_count || 0)}</div>
          <div class="detail-box"><div class="label">Notes</div>${esc(reviewContext.alert_note_count || 0)}</div>
        </div>

        <h4>Recommended Next Steps</h4>
        <ul class="muted">
          ${recommendedSteps || "<li>Continue monitoring this asset for future changes.</li>"}
        </ul>

        <h4>Update Investigation Status</h4>
        <div class="detail-grid">
          <div class="detail-box">
            <label class="label" for="investigation-status-select">Status</label>
            <select id="investigation-status-select">
              ${investigationStatusOptions}
            </select>
          </div>
          <div class="detail-box">
            <label class="label" for="investigation-reason-input">Reason</label>
            <input
              id="investigation-reason-input"
              type="text"
              value="${esc(persistedStatus.reason || "")}"
              placeholder="Reason for this investigation status"
            />
          </div>
        </div>
        <button
          id="save-investigation-status"
          data-asset-identifier="${esc(asset.asset_key)}"
          data-network-scope="${esc(asset.network_scope)}"
        >
          Save Investigation Status
        </button>
        <p id="investigation-status-message" class="muted"></p>

        ${detailTable("Investigation Timeline", investigation.timeline || [], [
          {key: "kind", label: "Kind"},
          {key: "id", label: "ID"},
          {key: "created_at", label: "Time"},
          {key: "severity", label: "Severity"},
          {key: "type", label: "Type"},
          {key: "summary", label: "Summary"}
        ])}

        ${detailTable("Alert Review Notes", investigation.alert_notes || [], [
          {key: "note_id", label: "Note"},
          {key: "alert_id", label: "Alert"},
          {key: "action", label: "Action"},
          {key: "reason", label: "Reason"},
          {key: "created_at", label: "Time"}
        ])}

        ${detailTable("Open/Recent Alerts", payload.alerts, [
          {key: "alert_id", label: "ID"},
          {key: "status", label: "Status"},
          {key: "severity", label: "Severity"},
          {key: "event_type", label: "Type"},
          {key: "summary", label: "Summary"}
        ])}

        ${detailTable("Recent Events", payload.events, [
          {key: "event_id", label: "ID"},
          {key: "severity", label: "Severity"},
          {key: "event_type", label: "Type"},
          {key: "scan_id", label: "Scan", code: true},
          {key: "summary", label: "Summary"}
        ])}

        ${detailTable("Services", payload.services, [
          {key: "protocol", label: "Proto"},
          {key: "port", label: "Port"},
          {key: "state", label: "State"},
          {key: "service_name", label: "Service"},
          {key: "product", label: "Product"},
          {key: "version", label: "Version"}
        ])}

        ${detailTable("Findings", payload.findings, [
          {key: "finding_id", label: "ID"},
          {key: "name", label: "Name"},
          {key: "service", label: "Service"},
          {key: "port", label: "Port"},
          {key: "score", label: "Score"},
          {key: "evidence", label: "Evidence"}
        ])}
      `;

      bindInvestigationStatusForm(box);
    }

    function bindInvestigationStatusForm(root) {
      if (!root) return;

      const button = root.querySelector("#save-investigation-status");
      const statusInput = root.querySelector("#investigation-status-select");
      const reasonInput = root.querySelector("#investigation-reason-input");
      const message = root.querySelector("#investigation-status-message");

      if (!button || !statusInput || !reasonInput) return;
      if (button.dataset.bound === "true") return;

      button.addEventListener("click", async () => {
        const status = statusInput.value;
        const reason = reasonInput.value.trim();
        const identifier = button.dataset.assetIdentifier;
        const scope = button.dataset.networkScope;

        if (!reason) {
          if (message) message.textContent = "Provide a reason before saving investigation status.";
          return;
        }

        button.disabled = true;

        if (message) message.textContent = "Saving investigation status...";

        try {
          const response = await fetch(scopedPath("/api/investigate-asset"), {
            method: "POST",
            headers: {
              "Content-Type": "application/json"
            },
            body: JSON.stringify({
              identifier,
              scope,
              status,
              reason
            })
          });

          const payload = await response.json();

          if (!response.ok || !payload.ok) {
            throw new Error(payload.message || payload.error || "Failed to save investigation status.");
          }

          renderAssetDetail(payload.asset_detail);

          const nextMessage = document.getElementById("investigation-status-message");

          if (nextMessage) {
            nextMessage.textContent = `Saved investigation status: ${status}`;
          }
        } catch (error) {
          if (message) {
            message.textContent = error && error.message ? error.message : String(error);
          }
        } finally {
          button.disabled = false;
        }
      });

      button.dataset.bound = "true";
    }



    function objectDetailRows(obj) {
      if (!obj) return [];

      return Object.keys(obj).sort().map(key => {
        const value = obj[key];

        return {
          key,
          value: Array.isArray(value)
            ? (value.length ? value.join(", ") : "-")
            : value
        };
      });
    }

    function renderIntelligenceHostDetail(payload) {
      const box = document.getElementById("intelligence-host-detail");

      if (!box) return;

      if (!payload || !payload.found) {
        box.innerHTML = `<p class="muted">${esc((payload && payload.message) || "Select a NetSniper v1.7 review queue host to inspect its evidence.")}</p>`;
        return;
      }

      const classification = payload.classification || {};
      const observedRows = objectDetailRows(payload.observed || {});
      const observedSummaryRows = objectDetailRows(payload.observed_summary || {});

      box.innerHTML = `
        <div class="detail-grid">
          <div class="detail-box"><div class="label">Host</div><code>${esc(payload.host_id || "-")}</code></div>
          <div class="detail-box"><div class="label">IP</div><code>${esc(payload.ip || "-")}</code></div>
          <div class="detail-box"><div class="label">MAC</div><code>${esc(payload.mac || "-")}</code></div>
          <div class="detail-box"><div class="label">Hostname</div>${esc(payload.hostname || "-")}</div>
          <div class="detail-box"><div class="label">Primary Type</div>${esc(classification.primary_type || "Unknown")}</div>
          <div class="detail-box"><div class="label">Category</div>${esc(classification.category || "-")}</div>
          <div class="detail-box"><div class="label">Confidence</div>${esc(classification.confidence || 0)} (${esc(classification.confidence_band || "-")})</div>
          <div class="detail-box"><div class="label">Decision</div>${esc(classification.decision || "-")}</div>
          <div class="detail-box"><div class="label">SIEM Action</div>${esc(classification.siem_action || "-")}</div>
          <div class="detail-box"><div class="label">Severity / Score</div>${esc(payload.severity || "-")} / ${esc(payload.score || 0)}</div>
        </div>

        <h4>Explanation</h4>
        <p class="muted">${esc(classification.explanation || "No explanation recorded.")}</p>

        ${detailTable("Observed Summary", observedSummaryRows, [
          {key: "key", label: "Metric"},
          {key: "value", label: "Value"}
        ])}

        ${detailTable("Observed Hints", observedRows, [
          {key: "key", label: "Hint Type"},
          {key: "value", label: "Values"}
        ])}

        ${detailTable("Evidence", payload.evidence || [], [
          {key: "id", label: "ID"},
          {key: "source", label: "Source"},
          {key: "value", label: "Value"},
          {key: "matched_value", label: "Matched"},
          {key: "points", label: "Points"},
          {key: "reliability", label: "Reliability"},
          {key: "reason", label: "Reason"}
        ])}

        ${detailTable("Contradictions", payload.contradictions || [], [
          {key: "id", label: "ID"},
          {key: "reason", label: "Reason"}
        ])}

        ${detailTable("Secondary Candidates", payload.secondary_candidates || [], [
          {key: "primary_type", label: "Candidate"},
          {key: "confidence", label: "Confidence"},
          {key: "confidence_band", label: "Band"},
          {key: "reason", label: "Reason"}
        ])}

        ${detailTable("Findings", payload.findings || [], [
          {key: "id", label: "ID"},
          {key: "name", label: "Name"},
          {key: "service", label: "Service"},
          {key: "port", label: "Port"},
          {key: "score", label: "Score"},
          {key: "evidence", label: "Evidence"}
        ])}
      `;
    }

    async function loadIntelligenceHostDetail(identity) {
      const box = document.getElementById("intelligence-host-detail");

      if (box) {
        box.innerHTML = `<p class="muted">Loading NetSniper v1.7 host evidence for <code>${esc(identity)}</code>...</p>`;
      }

      try {
        const payload = await api(`/api/intelligence-host?identity=${encodeURIComponent(identity)}`);
        renderIntelligenceHostDetail(payload);
      } catch (error) {
        renderIntelligenceHostDetail({
          found: false,
          message: `Failed to load NetSniper v1.7 host evidence: ${error.message || error}`
        });
      }
    }

    function bindIntelligenceHostLinks(root) {
      const scope = root || document;

      scope.querySelectorAll("[data-intelligence-host]").forEach(button => {
        if (button.dataset.boundIntelligenceHost === "1") return;

        button.dataset.boundIntelligenceHost = "1";

        button.addEventListener("click", event => {
          event.preventDefault();

          const identity = button.dataset.intelligenceHost;

          if (identity) {
            loadIntelligenceHostDetail(identity);
          }
        });
      });
    }


    async function loadAssetDetail(identifier) {
      activateDashboardTab("investigations");

      const detail = await api(scopedPath(`/api/asset?identifier=${encodeURIComponent(identifier)}`));

      renderAssetDetail(detail);

      const card = document.getElementById("asset-detail-card");

      if (card) {
        card.scrollIntoView({behavior: "smooth", block: "start"});
      }
    }


    function subjectToAssetIdentifier(subject) {
      const value = String(subject || "");

      const macMatch = value.match(/mac:[0-9a-f]{2}(:[0-9a-f]{2}){5}/i);
      if (macMatch) return macMatch[0].toLowerCase();

      const bareMacMatch = value.match(/[0-9a-f]{2}(:[0-9a-f]{2}){5}/i);
      if (bareMacMatch) return bareMacMatch[0].toLowerCase();

      const ipMatch = value.match(/\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b/);
      if (ipMatch) return ipMatch[0];

      return value;
    }

    function subjectButton(subject) {
      const identifier = subjectToAssetIdentifier(subject);
      return `
        <button class="asset-link" data-asset-identifier="${esc(identifier)}">
          <code>${esc(subject)}</code>
        </button>
      `;
    }

    function bindSubjectLinks(root) {
      if (!root) return;

      root.querySelectorAll("[data-asset-identifier]").forEach(button => {
        if (button.dataset.bound === "true") return;

        button.addEventListener("click", () => {
          loadAssetDetail(button.dataset.assetIdentifier);
        });

        button.dataset.bound = "true";
      });
    }

    function renderAssets(rows) {
      const tbody = document.getElementById("asset-inventory-body");

      renderAssetSelector(rows);

      if (!tbody) return;

      if (!rows.length) {
        tbody.innerHTML = `<tr><td colspan="12">No assets matched the current dashboard scope.</td></tr>`;
        return;
      }

      tbody.innerHTML = rows.map(row => `
        <tr>
          <td><code>${esc(row.network_scope)}</code></td>
          <td>${esc(row.state)}</td>
          <td>${esc(row.identity_class)}</td>
          <td><code>${esc(row.current_ip)}</code></td>
          <td><code>${esc(row.mac_address)}</code></td>
          <td>${esc(row.classification_display_type || row.device_type || "Unknown")}</td>
          <td>${esc(row.classification_display_decision || "unknown")}</td>
          <td>${esc(row.classification_display_confidence)}</td>
          <td>${esc(row.classification_evidence_count || 0)}</td>
          <td>${esc(row.classification_contradiction_count || 0)}</td>
          <td>
            <button class="asset-link" data-asset-identifier="${esc(row.asset_key)}">
              <code>${esc(row.asset_key)}</code>
            </button>
          </td>
          <td>${esc(row.last_seen_at)}</td>
        </tr>
      `).join("");

      tbody.querySelectorAll("[data-asset-identifier]").forEach(button => {
        button.addEventListener("click", () => {
          loadAssetDetail(button.dataset.assetIdentifier);
        });
      });
    }

    function riskLevelDescription(level) {
      const value = String(level || "").toUpperCase();

      if (value === "CRITICAL") return "score 85–100, review immediately";
      if (value === "HIGH") return "score 65–84, prioritize after critical items";
      if (value === "MEDIUM") return "score 35–64, review after higher-risk items";
      if (value === "LOW") return "score 15–34, track but usually not urgent";
      if (value === "INFO") return "score 0–14, informational or context-only";

      return "score band unavailable";
    }

    function riskExplanationHtml(row) {
      const reasons = Array.isArray(row.reasons)
        ? row.reasons.filter(reason => reason)
        : [];

      const actions = Array.isArray(row.recommended_actions)
        ? row.recommended_actions.filter(action => action)
        : [];

      const level = String(row.level || "UNKNOWN").toUpperCase();
      const score = row.score ?? "-";
      const primaryReason = reasons.length ? reasons[0] : "No risk reason recorded.";

      const visibleReasons = reasons.slice(0, 6);
      const hiddenCount = reasons.length - visibleReasons.length;

      const reasonItems = visibleReasons
        .map(reason => `<li>${esc(reason)}</li>`)
        .join("");

      const moreReasons = hiddenCount > 0
        ? `<li>${esc(hiddenCount)} additional scoring reason(s) not shown.</li>`
        : "";

      const actionItems = actions.slice(0, 2)
        .map(action => `<li>${esc(action)}</li>`)
        .join("");

      const actionBlock = actionItems
        ? `<div class="risk-action"><strong>Suggested follow-up:</strong><ul>${actionItems}</ul></div>`
        : "";

      return `
        <details class="risk-explanation">
          <summary>${esc(level)} ${esc(score)} — ${esc(primaryReason)}</summary>
          <ul>
            <li><strong>Risk band:</strong> ${esc(riskLevelDescription(level))}</li>
            ${reasonItems}
            ${moreReasons}
          </ul>
          ${actionBlock}
        </details>
      `;
    }


    function riskRowsHtml(rows, emptyMessage, currentMode) {
      if (!rows || !rows.length) {
        return `<tr><td colspan="11">${esc(emptyMessage)}</td></tr>`;
      }

      return rows.map(row => {
        const countColumn = currentMode
          ? (row.current_finding_count ?? 0)
          : (row.event_count ?? 0);

        return `
          <tr>
            <td class="severity-${esc(row.level || "").toLowerCase()}">${esc(row.level || "-")}</td>
            <td>${esc(row.score ?? "-")}</td>
            <td>${subjectButton(row.subject_key || "-")}</td>
            <td>${esc(row.ip_address || row.ip || "-")}</td>
            <td>${esc(row.mac_address || row.mac || "-")}</td>
            <td>${esc(row.identity_confidence || row.identity_state || "-")}</td>
            <td>${esc(row.owner || "-")}</td>
            <td>${esc(row.role || row.classification || "-")}</td>
            <td>${esc(row.open_alerts ?? 0)}</td>
            <td>${esc(countColumn)}</td>
            <td>${riskExplanationHtml(row)}</td>
          </tr>
        `;
      }).join("");
    }

    function portBehaviorSeverityClass(severity) {
      const value = String(severity || "").toLowerCase();
      if (["critical", "high", "medium", "low", "info"].includes(value)) {
        return `severity-${value}`;
      }
      return "severity-unknown";
    }

    function renderPortBehavior(rows) {
      const tbody = document.getElementById("port-behavior-body");

      if (!tbody) return;

      const items = Array.isArray(rows) ? rows : [];

      if (!items.length) {
        tbody.innerHTML = `<tr><td colspan="11" class="muted">No MAC-port behavior changes were detected for the selected scope.</td></tr>`;
        return;
      }

      tbody.innerHTML = items.map(row => `
        <tr>
          <td class="${portBehaviorSeverityClass(row.severity)}">${esc(row.severity || "-")}</td>
          <td>${esc(row.behavior || "-")}</td>
          <td><code>${esc(row.mac_identity || "-")}</code></td>
          <td><code>${esc(row.ip_address || "-")}</code></td>
          <td>${esc(row.device_type || "Unknown")}</td>
          <td><code>${esc(row.port_key || "-")}</code></td>
          <td>${esc(row.current_state || "-")}</td>
          <td>${esc(row.seen_count ?? 0)}</td>
          <td>${esc(row.missing_count ?? 0)}</td>
          <td>${esc(row.transition_count ?? 0)}</td>
          <td>${esc(row.reason || "-")}</td>
        </tr>
      `).join("");
    }




    function ticketSignalLabel(row) {
      const state = String((row && row.ticket_signal_state) || "ACTIONABLE").toUpperCase();

      if (state === "BASELINE_CONTEXT") return "Baseline context";
      if (state === "MEANINGFUL_CHANGE") return "Meaningful change";
      if (state === "ACTIONABLE") return "Actionable";

      return "Unclassified";
    }

    function ticketSignalClass(row) {
      const state = String((row && row.ticket_signal_state) || "ACTIONABLE").toUpperCase();

      if (state === "BASELINE_CONTEXT") return "ticket-signal-baseline-context";
      if (state === "MEANINGFUL_CHANGE") return "ticket-signal-meaningful-change";
      if (state === "ACTIONABLE") return "ticket-signal-actionable";

      return "ticket-signal-unknown";
    }

    function ticketSignalBadge(row) {
      return `<span class="ticket-signal-badge ${ticketSignalClass(row)}">${esc(ticketSignalLabel(row))}</span>`;
    }


    function triageBucketLabel(value) {
      const bucket = String(value || "MONITOR").toUpperCase();

      const labels = {
        "CHANGED_SINCE_REVIEW": "Changed Since Review",
        "NEEDS_REVIEW": "Needs Review",
        "NEEDS_CONTEXT": "Needs Context",
        "STALE_CLOSED": "Stale Closed",
        "BASELINE_CONTEXT": "Baseline Context",
        "MONITOR": "Monitor",
        "ALL": "All Buckets",
      };

      return labels[bucket] || bucket.replaceAll("_", " ");
    }

    function triageUrgencyLabel(value) {
      const urgency = String(value || "LOW").toUpperCase();

      const labels = {
        "IMMEDIATE": "Immediate",
        "HIGH": "High",
        "NORMAL": "Normal",
        "LOW": "Low",
        "ALL": "All Urgencies",
      };

      return labels[urgency] || urgency.replaceAll("_", " ");
    }

    function ticketTriageClass(row) {
      const urgency = String((row && row.triage_urgency_label) || "LOW")
        .toLowerCase()
        .replace(/[^a-z0-9-]/g, "");

      if (["immediate", "high", "normal", "low"].includes(urgency)) {
        return `ticket-triage-${urgency}`;
      }

      return "ticket-triage-low";
    }

    function ticketTriageBadge(row) {
      const bucket = triageBucketLabel(row && row.triage_bucket);
      const urgency = triageUrgencyLabel(row && row.triage_urgency_label);
      const score = row && row.triage_urgency_score !== undefined
        ? row.triage_urgency_score
        : 0;

      return `<span class="ticket-triage-badge ${ticketTriageClass(row)}">${esc(bucket)} / ${esc(urgency)} (${esc(score)})</span>`;
    }

    function triageSummaryCard(label, value, hint) {
      return `
        <div class="triage-summary-card">
          <span class="label">${esc(label)}</span>
          <span class="value">${esc(value ?? 0)}</span>
          <span class="hint">${esc(hint || "")}</span>
        </div>
      `;
    }

    function renderTriageSummaryPanel(payload) {
      const root = document.getElementById("investigation-triage-summary");

      if (!root) return;

      const summary = payload && payload.triage_summary ? payload.triage_summary : {};
      const filters = payload && payload.filters ? payload.filters : {};

      root.innerHTML = `
        ${triageSummaryCard("Needs Review", summary.needs_review || 0, "Actionable or meaningful-change tickets")}
        ${triageSummaryCard("Changed", summary.changed_since_review || 0, "New evidence after review")}
        ${triageSummaryCard("Needs Context", summary.needs_context || 0, "Missing owner, role, or criticality")}
        ${triageSummaryCard("Immediate", summary.immediate || 0, "Highest urgency queue items")}
        ${triageSummaryCard("High", summary.high || 0, "High urgency queue items")}
        ${triageSummaryCard("Selected Bucket", filters.triage_bucket || "ALL", "Current triage bucket filter")}
      `;
    }

    function populateTriageSelect(id, values, selected) {
      const element = document.getElementById(id);

      if (!element) return;

      const options = Array.isArray(values) && values.length ? values : ["ALL"];
      const current = String(selected || element.value || "ALL").toUpperCase();

      element.innerHTML = options.map(value => {
        const raw = String(value || "ALL").toUpperCase();
        const label = id === "triage-urgency-filter"
          ? triageUrgencyLabel(raw)
          : triageBucketLabel(raw);

        return `<option value="${esc(raw)}" ${raw === current ? "selected" : ""}>${esc(label)}</option>`;
      }).join("");
    }

    function renderTriageFilterOptions(payload) {
      const filters = payload && payload.filters ? payload.filters : {};

      populateTriageSelect(
        "triage-bucket-filter",
        filters.triage_buckets || ["ALL", "CHANGED_SINCE_REVIEW", "NEEDS_REVIEW", "NEEDS_CONTEXT", "STALE_CLOSED", "BASELINE_CONTEXT", "MONITOR"],
        filters.triage_bucket || "ALL"
      );

      populateTriageSelect(
        "triage-urgency-filter",
        filters.triage_urgencies || ["ALL", "IMMEDIATE", "HIGH", "NORMAL", "LOW"],
        filters.triage_urgency || "ALL"
      );
    }

    function ticketEvidenceCategoryLabel(category) {
      const value = String(category || "").toLowerCase();

      const labels = {
        "current_risk": "Current Risk",
        "alert": "Alert",
        "delta_event": "Delta Event",
        "port_behavior": "Port Behavior",
        "ticket_history": "Workflow History",
      };

      return labels[value] || value.replaceAll("_", " ") || "Evidence";
    }

    function ticketEvidenceCategoryClass(category) {
      const value = String(category || "unknown")
        .toLowerCase()
        .replaceAll("_", "-")
        .replace(/[^a-z0-9-]/g, "");

      return `ticket-evidence-category-${value || "unknown"}`;
    }

    function ticketEvidenceTimelineHtml(timeline) {
      const items = Array.isArray(timeline) ? timeline : [];

      if (!items.length) {
        return `<p class="muted">No evidence timeline entries were found for this ticket.</p>`;
      }

      return `
        <div class="ticket-evidence-timeline">
          ${items.slice(0, 12).map((item, index) => `
            <div class="ticket-evidence-event">
              <div class="event-meta">
                <span>#${esc(index + 1)}</span>
                <span class="ticket-evidence-category ${ticketEvidenceCategoryClass(item.category)}">
                  ${esc(ticketEvidenceCategoryLabel(item.category))}
                </span>
                <span>${esc(item.severity || "INFO")}</span>
                <span>${esc(item.timestamp || "time unavailable")}</span>
                <span>${esc(item.source || "-")}</span>
              </div>
              <div class="event-summary">${esc(item.summary || "-")}</div>
            </div>
          `).join("")}
        </div>
      `;
    }

    function renderTicketEvidence(payload) {
      const panel = document.getElementById("ticket-evidence-panel");

      if (!panel) return;

      if (!payload || payload.available === false) {
        panel.innerHTML = `
          <div class="evidence-drilldown-header">
            <div>
              <h3>Ticket Evidence Drilldown</h3>
              <p class="muted">${esc((payload && payload.error) || "Ticket evidence is unavailable.")}</p>
            </div>
          </div>
        `;
        return;
      }

      const summary = payload.summary || {};
      const ticketState = payload.ticket_state || {};

      panel.innerHTML = `
        <div class="evidence-drilldown-header">
          <div>
            <h3>Ticket Evidence Drilldown</h3>
            <p class="muted">Evidence package for <code>${esc(payload.subject_key || summary.subject_key || "-")}</code></p>
          </div>
          <div>
            ${ticketWorkflowBadge({ticket_status: summary.ticket_status || ticketState.ticket_status || "OPEN"})}
            ${ticketSignalBadge({ticket_signal_state: summary.ticket_signal || "ACTIONABLE"})}
          </div>
        </div>

        <div class="detail-grid">
          <div class="detail-box"><div class="label">Priority</div>${esc(summary.priority_level || "INFO")} / ${esc(summary.priority_score || 0)}</div>
          <div class="detail-box"><div class="label">Workflow</div>${esc(summary.ticket_status || ticketState.ticket_status || "OPEN")}</div>
          <div class="detail-box"><div class="label">Risk Records</div>${esc(summary.risk_count || 0)}</div>
          <div class="detail-box"><div class="label">Alerts</div>${esc(summary.alert_count || 0)}</div>
          <div class="detail-box"><div class="label">Events</div>${esc(summary.event_count || 0)}</div>
          <div class="detail-box"><div class="label">Port Behavior</div>${esc(summary.port_behavior_count || 0)}</div>
          <div class="detail-box"><div class="label">Ticket History</div>${esc(summary.ticket_history_count || 0)}</div>
          <div class="detail-box"><div class="label">Timeline Entries</div>${esc(summary.timeline_count || 0)}</div>
        </div>

        <h4>Why this ticket exists</h4>
        <p class="muted">${esc(summary.primary_reason || "No primary reason was recorded.")}</p>
        <div class="ticket-evidence-why-now">
          <div class="label">Why Now</div>
          <p class="muted">${esc(summary.why_now || "No why-now summary was generated for this ticket.")}</p>
        </div>

        <h4>Recommended next action</h4>
        <p class="muted">${esc(summary.recommended_action || "Review the evidence package before changing workflow state.")}</p>

        <h4>Evidence Timeline</h4>
        ${ticketEvidenceTimelineHtml(payload.timeline || [])}

        ${detailTable("Current Risk Evidence", payload.risk || [], [
          {key: "level", label: "Level"},
          {key: "score", label: "Score"},
          {key: "subject_key", label: "Subject", code: true},
          {key: "primary_reason", label: "Primary Reason"},
          {key: "reasons", label: "Reasons"}
        ])}

        ${detailTable("Alerts", payload.alerts || [], [
          {key: "alert_id", label: "ID"},
          {key: "status", label: "Status"},
          {key: "severity", label: "Severity"},
          {key: "event_type", label: "Type"},
          {key: "summary", label: "Summary"}
        ])}

        ${detailTable("Delta Events", payload.events || [], [
          {key: "event_id", label: "ID"},
          {key: "created_at", label: "Time"},
          {key: "severity", label: "Severity"},
          {key: "event_type", label: "Type"},
          {key: "summary", label: "Summary"}
        ])}

        ${detailTable("MAC-Port Behavior", payload.port_behavior || [], [
          {key: "severity", label: "Severity"},
          {key: "behavior", label: "Behavior"},
          {key: "protocol", label: "Protocol"},
          {key: "port", label: "Port"},
          {key: "reason", label: "Reason"}
        ])}

        ${detailTable("Ticket History", payload.ticket_history || [], [
          {key: "created_at", label: "Time"},
          {key: "previous_status", label: "Previous"},
          {key: "new_status", label: "New"},
          {key: "analyst", label: "Analyst"},
          {key: "note", label: "Note"}
        ])}
      `;
    }

    async function loadTicketEvidence(subject) {
      const panel = document.getElementById("ticket-evidence-panel");

      if (panel) {
        panel.innerHTML = `
          <div class="evidence-drilldown-header">
            <div>
              <h3>Ticket Evidence Drilldown</h3>
              <p class="muted">Loading evidence for <code>${esc(subject || "-")}</code>...</p>
            </div>
          </div>
        `;
      }

      try {
        const payload = await api(scopedPath(`/api/ticket-evidence?subject_key=${encodeURIComponent(subject)}&limit=10`));
        renderTicketEvidence(payload);

        if (panel) {
          panel.scrollIntoView({behavior: "smooth", block: "start"});
        }
      } catch (error) {
        renderTicketEvidence({
          available: false,
          error: error && error.message ? error.message : String(error)
        });
      }
    }

    function bindTicketEvidenceButtons(root) {
      if (!root) return;

      root.querySelectorAll("[data-ticket-evidence-subject]").forEach(button => {
        if (button.dataset.boundTicketEvidence === "true") return;

        button.addEventListener("click", event => {
          event.preventDefault();

          const subject = button.dataset.ticketEvidenceSubject;

          if (subject) {
            loadTicketEvidence(subject);
          }
        });

        button.dataset.boundTicketEvidence = "true";
      });
    }



    function ticketWorkflowLabel(row) {
      const status = String((row && row.ticket_status) || "OPEN").toUpperCase();

      if (status === "IN_REVIEW") return "In Review";
      if (status === "RESOLVED") return "Resolved";
      if (status === "SUPPRESSED") return "Suppressed";
      if (status === "OPEN") return "Open";

      return status || "Open";
    }

    function ticketWorkflowClass(row) {
      const status = String((row && row.ticket_status) || "OPEN").toUpperCase();

      if (status === "IN_REVIEW") return "in-review";
      if (status === "RESOLVED") return "resolved";
      if (status === "SUPPRESSED") return "suppressed";
      if (status === "OPEN") return "open";

      return "unknown";
    }

    function ticketWorkflowBadge(row) {
      return `<span class="ticket-workflow-badge ticket-workflow-${esc(ticketWorkflowClass(row))}">${esc(ticketWorkflowLabel(row))}</span>`;
    }

    function ticketWorkflowMeta(row) {
      const analyst = (row && row.ticket_analyst) || "-";
      const updated = (row && row.ticket_updated_at) || "-";
      const note = (row && row.ticket_note) || "";

      return `
        <div><span>Workflow</span><strong>${ticketWorkflowBadge(row)}</strong></div>
        <div><span>Analyst</span><strong>${esc(analyst)}</strong></div>
        <div><span>Workflow updated</span><strong>${esc(updated)}</strong></div>
        ${note ? `<div><span>Workflow note</span><strong>${esc(note)}</strong></div>` : ""}
      `;
    }


    function ticketWorkflowActions(row) {
      const subject = row && row.subject_key ? row.subject_key : "";
      const current = String((row && row.ticket_status) || "OPEN").toUpperCase();

      const actions = [
        ["OPEN", "Open"],
        ["IN_REVIEW", "In Review"],
        ["RESOLVED", "Resolve"],
        ["SUPPRESSED", "Suppress"]
      ];

      return `
        <div class="siem-ticket-section ticket-workflow-actions">
          <div class="label">Workflow actions</div>
          <div class="ticket-action-buttons">
            <button
              type="button"
              class="ticket-evidence-action"
              data-ticket-evidence-subject="${esc(subject)}"
            >View Evidence</button>
            ${actions.map(([status, label]) => `
              <button
                class="small-action-button"
                data-ticket-subject="${esc(subject)}"
                data-ticket-status="${esc(status)}"
                ${status === current ? "disabled" : ""}
              >${esc(label)}</button>
            `).join("")}
          </div>
          <div class="ticket-workflow-note">${esc(row.ticket_note || "")}</div>
        </div>
      `;
    }

    async function updateTicketWorkflow(button) {
      const subject = button.dataset.ticketSubject || "";
      const status = button.dataset.ticketStatus || "";

      if (!subject || !status) return;

      button.disabled = true;

      try {
        const response = await fetch(scopedPath("/api/ticket-status"), {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            subject_key: subject,
            status,
            analyst: "dashboard",
            note: `Dashboard workflow action: ${status}`
          })
        });

        const payload = await response.json();

        if (!response.ok || !payload.ok) {
          throw new Error(payload.message || payload.error || "Failed to update ticket workflow.");
        }

        await refreshInvestigationCenter();
      } catch (error) {
        alert(error && error.message ? error.message : String(error));
      } finally {
        button.disabled = false;
      }
    }

    function bindTicketWorkflowActions(root) {
      if (!root) return;

      root.querySelectorAll("[data-ticket-subject][data-ticket-status]").forEach(button => {
        if (button.dataset.boundTicketWorkflow === "true") return;

        button.addEventListener("click", event => {
          event.preventDefault();
          updateTicketWorkflow(button);
        });

        button.dataset.boundTicketWorkflow = "true";
      });
    }

    function investigationCenterFilterValue(id) {
      const element = document.getElementById(id);
      const value = element ? String(element.value || "ALL").toUpperCase() : "ALL";

      return value || "ALL";
    }

    function investigationCenterFilterPath() {
      const params = new URLSearchParams();
      const status = investigationCenterFilterValue("ticket-status-filter");
      const signal = investigationCenterFilterValue("ticket-signal-filter");
      const triageBucket = investigationCenterFilterValue("triage-bucket-filter");
      const triageUrgency = investigationCenterFilterValue("triage-urgency-filter");

      params.set("limit", "25");

      if (status && status !== "ALL") {
        params.set("ticket_status", status);
      }

      if (signal && signal !== "ALL") {
        params.set("ticket_signal", signal);
      }
      if (triageBucket && triageBucket !== "ALL") {
        params.set("triage_bucket", triageBucket);
      }
      if (triageUrgency && triageUrgency !== "ALL") {
        params.set("triage_urgency", triageUrgency);
      }

      return scopedPath(`/api/investigation-center?${params.toString()}`);
    }

    function syncInvestigationCenterFilters(payload) {
      const filters = payload && payload.filters ? payload.filters : {};
      const status = String(filters.ticket_status || "ALL").toUpperCase();
      const signal = String(filters.ticket_signal || "ALL").toUpperCase();
      const statusElement = document.getElementById("ticket-status-filter");
      const signalElement = document.getElementById("ticket-signal-filter");

      if (statusElement && statusElement.value !== status) {
        statusElement.value = status;
      }

      if (signalElement && signalElement.value !== signal) {
        signalElement.value = signal;
      }
    }

    async function refreshInvestigationCenter() {
      const payload = await api(investigationCenterFilterPath());
      renderInvestigationCenter(payload);
      renderTriageFilterOptions(payload);
      renderTriageSummaryPanel(payload);
    }

    function bindInvestigationCenterFilters() {
      const applyButton = document.getElementById("apply-ticket-filters");
      const clearButton = document.getElementById("clear-ticket-filters");

      if (applyButton && applyButton.dataset.boundTicketFilters !== "true") {
        applyButton.addEventListener("click", event => {
          event.preventDefault();
          refreshInvestigationCenter();
        });
        applyButton.dataset.boundTicketFilters = "true";
      }

      if (clearButton && clearButton.dataset.boundTicketFilters !== "true") {
        clearButton.addEventListener("click", event => {
          event.preventDefault();

          const statusElement = document.getElementById("ticket-status-filter");
          const signalElement = document.getElementById("ticket-signal-filter");
          const triageBucketElement = document.getElementById("triage-bucket-filter");
          const triageUrgencyElement = document.getElementById("triage-urgency-filter");

          if (statusElement) statusElement.value = "ALL";
          if (signalElement) signalElement.value = "ALL";
          if (triageBucketElement) triageBucketElement.value = "ALL";
          if (triageUrgencyElement) triageUrgencyElement.value = "ALL";

          refreshInvestigationCenter();
        });
        clearButton.dataset.boundTicketFilters = "true";
      }
    }

    function renderInvestigationCenter(payload) {
      syncInvestigationCenterFilters(payload);

      const summaryBox = document.getElementById("investigation-center-summary");
      const tbody = document.getElementById("investigation-center-body");
      const ticketCards = document.getElementById("investigation-ticket-cards");
      const items = payload && Array.isArray(payload.items) ? payload.items : [];
      const summary = payload && payload.summary ? payload.summary : {};
      const workflowSummary = payload && payload.workflow_summary
        ? payload.workflow_summary
        : {open: 0, in_review: 0, resolved: 0, suppressed: 0};
      const signalSummary = payload && payload.signal_summary
        ? payload.signal_summary
        : {actionable: 0, meaningful_change: 0, baseline_context: 0};

      if (summaryBox) {
        summaryBox.innerHTML = [
          ["Visible Items", payload && payload.item_count !== undefined ? payload.item_count : items.length],
          ["Total Queue", payload && payload.total_item_count !== undefined ? payload.total_item_count : items.length],
          ["Critical in View", summary.critical || 0],
          ["High in View", summary.high || 0],
          ["Workflow Open", workflowSummary.open || 0],
          ["In Review", workflowSummary.in_review || 0],
          ["Resolved", workflowSummary.resolved || 0],
          ["Suppressed", workflowSummary.suppressed || 0],
          ["Actionable", signalSummary.actionable || 0],
          ["Meaningful Change", signalSummary.meaningful_change || 0],
          ["Baseline Context", signalSummary.baseline_context || 0]
        ].map(([label, value]) => `
          <div class="metric-card command-center-kpi">
            <div class="label">${esc(label)}</div>
            <div class="metric-value">${esc(value)}</div>
          </div>
        `).join("");
      }

      if (!items.length) {
        const message = payload && payload.available === false
          ? (payload.error || "Investigation Command Center is unavailable.")
          : "No investigation queue items matched the selected scope.";

        if (ticketCards) {
          ticketCards.innerHTML = `<div class="siem-ticket-empty">${esc(message)}</div>`;
        }

        if (tbody) {
          tbody.innerHTML = `<tr><td colspan="11" class="muted">${esc(message)}</td></tr>`;
        }

        return;
      }

      if (ticketCards) {
        ticketCards.innerHTML = items.slice(0, 6).map(row => {
          const level = String(row.priority_level || "INFO").toUpperCase();
          const levelClass = level.toLowerCase().replace(/[^a-z0-9-]/g, "");
          const triggers = Array.isArray(row.triggers) && row.triggers.length
            ? row.triggers.map(trigger => `<span class="command-center-trigger">${esc(trigger)}</span>`).join(" ")
            : `<span class="muted">No trigger context</span>`;

          return `
            <article class="siem-ticket-card ticket-${esc(levelClass)}">
              <div class="siem-ticket-header">
                <div class="siem-ticket-title">
                  <strong>${esc(row.device_type || row.classification || row.role || "Unknown asset")}</strong>
                  <div class="siem-ticket-subject">${subjectButton(row.subject_key || "-")}</div>
                  ${ticketSignalBadge(row)}
                  ${ticketTriageBadge(row)}
                </div>
                <div class="siem-priority-badge severity-${esc(levelClass)}">
                  <span class="level">${esc(level)}</span>
                  <span class="score">${esc(row.priority_score || 0)}</span>
                </div>
              </div>

              <div class="siem-ticket-meta">
                <div><span>IP address</span><code>${esc(row.ip_address || "-")}</code></div>
                <div><span>MAC address</span><code>${esc(row.mac_address || "-")}</code></div>
                <div><span>Role</span><strong>${esc(row.role || row.classification || "Unknown")}</strong></div>
                <div><span>Identity</span><strong>${esc(row.identity_confidence || "Unknown")}</strong></div>
                ${ticketWorkflowMeta(row)}
              </div>

              <div class="siem-ticket-section">
                <div class="label">Triggers</div>
                <div>${triggers}</div>
              </div>

              <div class="siem-ticket-section">
                <div class="label">Why review?</div>
                <div class="siem-ticket-reason">${esc(row.primary_reason || "-")}</div>
              </div>

              <div class="siem-ticket-section">
                <div class="label">Recommended action</div>
                <div class="siem-ticket-action">${esc(row.recommended_action || "-")}</div>
              </div>

              ${ticketWorkflowActions(row)}

              <div class="siem-ticket-counts">
                <span class="siem-count-pill">Alerts ${esc(row.open_alerts || 0)}</span>
                <span class="siem-count-pill">Events ${esc(row.recent_events || 0)}</span>
                <span class="siem-count-pill">Ports ${esc(row.port_behavior_count || 0)}</span>
                <span class="siem-count-pill">Findings ${esc(row.current_finding_count || 0)}</span>
              </div>
            </article>
          `;
        }).join("");

        bindSubjectLinks(ticketCards);
        bindTicketWorkflowActions(ticketCards);
          bindTicketEvidenceButtons(ticketCards);
      }

      if (!tbody) return;

      tbody.innerHTML = items.map(row => {
        const triggers = Array.isArray(row.triggers) && row.triggers.length
          ? row.triggers.map(trigger => `<span class="command-center-trigger">${esc(trigger)}</span>`).join(" ")
          : "-";

        const counts = [
          `alerts=${esc(row.open_alerts || 0)}`,
          `events=${esc(row.recent_events || 0)}`,
          `ports=${esc(row.port_behavior_count || 0)}`,
          `findings=${esc(row.current_finding_count || 0)}`
        ].join(" ");

        const role = row.role || row.classification || row.device_type || "Unknown";
        const device = row.device_type && row.device_type !== role
          ? `${esc(row.device_type)} / ${esc(role)}`
          : esc(role);

        return `
          <tr>
            <td class="severity-${esc(String(row.priority_level || "info").toLowerCase())}">
              ${esc(row.priority_level || "INFO")}<br>
              <span class="muted">${esc(row.priority_score || 0)}</span>
            </td>
            <td>${ticketSignalBadge(row)}</td>
            <td>${ticketWorkflowBadge(row)}</td>
            <td>${subjectButton(row.subject_key || "-")}</td>
            <td><code>${esc(row.ip_address || "-")}</code></td>
            <td><code>${esc(row.mac_address || "-")}</code></td>
            <td>${device}</td>
            <td>${triggers}</td>
            <td class="command-center-reason">${esc(row.primary_reason || "-")}</td>
            <td class="command-center-action">${esc(row.recommended_action || "-")}</td>
            <td><code>${counts}</code></td>
          </tr>
        `;
      }).join("");

      bindSubjectLinks(tbody);
          bindTicketEvidenceButtons(tbody);
    }


    function renderRisk(rows) {
      const tbody = document.getElementById("risk-body");

      if (!tbody) return;

      tbody.innerHTML = riskRowsHtml(
        rows,
        "No current risk subjects calculated for the latest accepted snapshot.",
        true
      );

      bindSubjectLinks(tbody);
    }

    function renderHistoricalRisk(rows) {
      const tbody = document.getElementById("historical-risk-body");

      if (!tbody) return;

      tbody.innerHTML = riskRowsHtml(
        rows,
        "No historical risk context matched the current dashboard scope.",
        false
      );

      bindSubjectLinks(tbody);
    }

    function renderEvents(rows) {
  const tbody = document.getElementById("events-body");

  if (!tbody) return;

  if (!rows || !rows.length) {
    tbody.innerHTML = `<tr><td colspan="11">No recent delta events matched the current dashboard scope.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map(row => `
    <tr>
      <td>${esc(row.event_id || row.id || "-")}</td>
      <td>${esc(row.scan_id || "-")}</td>
      <td>${esc(row.baseline_scan_id || "-")}</td>
      <td class="severity-${esc(row.severity || "").toLowerCase()}">${esc(row.severity || "-")}</td>
      <td>${esc(row.event_type || row.type || "-")}</td>
      <td>${subjectButton(row.subject_key || "-")}</td>
      <td>${esc(row.ip_address || row.ip || "-")}</td>
      <td>${esc(row.mac_address || row.mac || "-")}</td>
      <td>${esc(row.identity_confidence || row.identity_state || "-")}</td>
      <td>${esc(row.created_at || "-")}</td>
      <td>${esc(row.summary || "-")}</td>
    </tr>
  `).join("");

  bindSubjectLinks(tbody);
}

    function renderAlerts(rows) {
  const tbody = document.getElementById("alerts-body");

  if (!tbody) return;

  if (!rows || !rows.length) {
    tbody.innerHTML = `<tr><td colspan="9">No recent alerts matched the current dashboard scope.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map(row => `
    <tr>
      <td>${esc(row.alert_id || row.id || "-")}</td>
      <td>${esc(row.status || "-")}</td>
      <td class="severity-${esc(row.severity || "").toLowerCase()}">${esc(row.severity || "-")}</td>
      <td>${subjectButton(row.subject_key || "-")}</td>
      <td>${esc(row.event_type || row.type || "-")}</td>
      <td>${esc(row.ip_address || row.ip || "-")}</td>
      <td>${esc(row.mac_address || row.mac || "-")}</td>
      <td>${esc(row.identity_confidence || row.identity_state || "-")}</td>
      <td>${esc(row.summary || "-")}</td>
    </tr>
  `).join("");

  bindSubjectLinks(tbody);
}

    function renderAnnotations(rows) {
      document.getElementById("annotations").innerHTML = rows.map(row => `
        <tr>
          <td><code>${esc(row.asset_key)}</code></td>
          <td><code>${esc(row.identity_ip_address)}</code></td>
          <td><code>${esc(row.identity_mac_address)}</code></td>
          <td>${identityBadge(row.identity_confidence)}</td>
          <td>${esc(row.owner)}</td>
          <td>${esc(row.role)}</td>
          <td>${esc(row.criticality)}</td>
          <td>${esc(row.notes)}</td>
        </tr>
      `).join("") || `<tr><td colspan="8" class="muted">No annotations found.</td></tr>`;
    }

    function renderClassificationSummary(summary) {
      const intel = (summary && summary.classification_summary) || {};
      const v17Intel = (summary && summary.netsniper_intelligence_summary) || {};

      let section = document.getElementById("classification-summary-section");

      if (!section) {
        const assetBody = document.getElementById("asset-inventory-body");
        const assetSection = assetBody ? assetBody.closest("section") : null;

        section = document.createElement("section");
        section.id = "classification-summary-section";

        if (assetSection && assetSection.parentNode) {
          assetSection.parentNode.insertBefore(section, assetSection);
        } else {
          document.body.appendChild(section);
        }
      }

      section.dataset.tabPanel = "intelligence";

      const topClassifications = intel.top_classifications || [];
      const reviewQueue = intel.review_queue || [];
      const v17TopTypes = v17Intel.top_device_types || [];
      const v17ReviewQueue = v17Intel.review_queue || [];
      const v17ConfidenceBands = v17Intel.confidence_band_counts || [];
      let v17Block = "";
      v17Block = "";

      const topRows = topClassifications.length
        ? topClassifications.map(row => `
            <tr>
              <td>${esc(row.classification)}</td>
              <td>${esc(row.count)}</td>
            </tr>
          `).join("")
        : `<tr><td colspan="2">No classification summary is available yet.</td></tr>`;

      const reviewRows = reviewQueue.length
        ? reviewQueue.map(row => `
            <tr>
              <td>${subjectButton(row.asset_key)}</td>
              <td><code>${esc(row.ip_address)}</code></td>
              <td>${esc(row.classification)}</td>
              <td>${esc(row.decision)}</td>
              <td>${esc(row.confidence)}</td>
              <td>${esc(row.evidence_count)}</td>
              <td>${esc(row.contradiction_count)}</td>
              <td>${esc(row.reason)}</td>
            </tr>
          `).join("")
        : `<tr><td colspan="8">No weak, unknown, or contradictory classifications require review.</td></tr>`;


      const v17TopRows = v17TopTypes.length
        ? v17TopTypes.map(row => `
            <tr>
              <td>${esc(row.device_type)}</td>
              <td>${esc(row.count)}</td>
            </tr>
          `).join("")
        : `<tr><td colspan="2">No NetSniper v1.7 device-type summary is available yet.</td></tr>`;

      const v17BandRows = v17ConfidenceBands.length
        ? v17ConfidenceBands.map(row => `
            <tr>
              <td>${esc(row.band)}</td>
              <td>${esc(row.count)}</td>
            </tr>
          `).join("")
        : `<tr><td colspan="2">No NetSniper v1.7 confidence-band summary is available yet.</td></tr>`;

      const v17ReviewRows = v17ReviewQueue.length
        ? v17ReviewQueue.map(row => `
            <tr>
              <td>
                <button
                  type="button"
                  class="link-button"
                  data-intelligence-host="${esc(row.identity || row.ip || row.host_id || "")}"
                >
                  <code>${esc(row.identity || row.ip || row.host_id || "-")}</code>
                </button>
              </td>
              <td>${esc(row.primary_type || row.classification || "Unknown")}</td>
              <td>${esc(row.confidence || 0)}</td>
              <td>${esc(row.decision || "unknown")}</td>
              <td>${esc(row.siem_action || row.reason || "review")}</td>
            </tr>
          `).join("")
        : `<tr><td colspan="5">No NetSniper v1.7 review queue items are available.</td></tr>`;

      v17Block = v17Intel.available ? `
        <h3>NetSniper v1.7 Bundle Intelligence</h3>
        <p class="muted">Run-level quality summary imported from NetSniper v1.7 manifest-addressable artifacts. Latest scan: <code>${esc(v17Intel.scan_id || "-")}</code>.</p>

        <div class="cards">
          <div class="card">
            <div class="label">v1.7 Hosts</div>
            <strong>${esc(v17Intel.host_count || 0)}</strong>
          </div>
          <div class="card">
            <div class="label">v1.7 Classified</div>
            <strong>${esc(v17Intel.classified_count || 0)}</strong>
          </div>
          <div class="card">
            <div class="label">v1.7 Review</div>
            <strong>${esc(v17Intel.possible_or_review_count || 0)}</strong>
          </div>
          <div class="card">
            <div class="label">v1.7 Unknown</div>
            <strong>${esc(v17Intel.unknown_count || 0)}</strong>
          </div>
          <div class="card">
            <div class="label">False Confidence</div>
            <strong>${esc(v17Intel.false_confidence_candidate_count || 0)}</strong>
          </div>
          <div class="card">
            <div class="label">Unknown Exposed</div>
            <strong>${esc(v17Intel.unknown_with_exposed_services_count || 0)}</strong>
          </div>
        </div>

        ${v17Block}

        <div class="grid two-col">
          <div>
            <h3>v1.7 Top Device Types</h3>
            <table>
              <thead>
                <tr>
                  <th>Device Type</th>
                  <th>Hosts</th>
                </tr>
              </thead>
              <tbody>${v17TopRows}</tbody>
            </table>
          </div>

          <div>
            <h3>v1.7 Confidence Bands</h3>
            <table>
              <thead>
                <tr>
                  <th>Band</th>
                  <th>Hosts</th>
                </tr>
              </thead>
              <tbody>${v17BandRows}</tbody>
            </table>
          </div>
        </div>

        <h3>v1.7 Review Queue Sample</h3>
        <table>
          <thead>
            <tr>
              <th>Identity</th>
              <th>Classification</th>
              <th>Confidence</th>
              <th>Decision</th>
              <th>SIEM Action</th>
            </tr>
          </thead>
          <tbody>${v17ReviewRows}</tbody>
        </table>

        <h3>v1.7 Host Evidence Drilldown</h3>
        <div id="intelligence-host-detail" class="detail-box">
          <p class="muted">Select a NetSniper v1.7 review queue host to inspect its evidence, observed hints, findings, contradictions, and secondary candidates.</p>
        </div>
      ` : `
        <h3>NetSniper v1.7 Bundle Intelligence</h3>
        <p class="muted">${esc(v17Intel.message || "No NetSniper v1.7 intelligence summary has been imported yet.")}</p>
      `;

      section.innerHTML = `
        <h2>NetSniper Intelligence Summary</h2>
        <p class="muted">Classification overview for the current dashboard scope, based on the latest asset observations.</p>

        <div class="cards">
          <div class="card">
            <div class="label">Classified Assets</div>
            <strong>${esc(intel.classified_assets || 0)}</strong>
          </div>
          <div class="card">
            <div class="label">Possible / Weak</div>
            <strong>${esc(intel.possible_assets || 0)}</strong>
          </div>
          <div class="card">
            <div class="label">Unknown Assets</div>
            <strong>${esc(intel.unknown_assets || 0)}</strong>
          </div>
          <div class="card">
            <div class="label">Evidence-backed</div>
            <strong>${esc(intel.evidence_backed_assets || 0)}</strong>
          </div>
          <div class="card">
            <div class="label">Contradictions</div>
            <strong>${esc(intel.contradiction_assets || 0)}</strong>
          </div>
          <div class="card">
            <div class="label">Classified %</div>
            <strong>${esc(intel.classified_percent || 0)}%</strong>
          </div>
        </div>

        <div class="grid two-col">
          <div>
            <h3>Top Classifications</h3>
            <table>
              <thead>
                <tr>
                  <th>Classification</th>
                  <th>Assets</th>
                </tr>
              </thead>
              <tbody>${topRows}</tbody>
            </table>
          </div>

          <div>
            <h3>Classification Review Queue</h3>
            <table>
              <thead>
                <tr>
                  <th>Asset</th>
                  <th>IP</th>
                  <th>Classification</th>
                  <th>Decision</th>
                  <th>Confidence</th>
                  <th>Evidence</th>
                  <th>Contradictions</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>${reviewRows}</tbody>
            </table>
          </div>
        </div>
      `;

      bindSubjectLinks(section);
      bindIntelligenceHostLinks(section);
    }


    function renderAccessAudit(payload) {
      let section = document.getElementById("access-audit-panel");

      if (!section) {
        section = document.createElement("section");
        section.id = "access-audit-panel";
        section.dataset.tabPanel = "investigations";

        const investigationCenter = document.getElementById("investigation-center-body");
        const anchor = investigationCenter ? investigationCenter.closest("section") : null;

        if (anchor && anchor.parentNode) {
          anchor.parentNode.insertBefore(section, anchor.nextSibling);
        } else {
          document.body.appendChild(section);
        }
      }

      const items = payload && Array.isArray(payload.items) ? payload.items : [];
      const summary = payload && payload.summary ? payload.summary : {};
      const actionCounts = summary.action_counts || {};

      const summaryText = Object.keys(actionCounts).length
        ? Object.entries(actionCounts)
            .map(([action, count]) => `${esc(action)}=${esc(count)}`)
            .join(", ")
        : "No audit actions observed yet.";

      const rows = items.length
        ? items.map(row => `
            <tr>
              <td><code>${esc(row.created_at || "-")}</code></td>
              <td>${esc(row.action || "-")}</td>
              <td>${esc(row.actor_username || "-")}</td>
              <td>${esc(row.actor_role || "-")}</td>
              <td>${esc(row.target_type || "-")}</td>
              <td><code>${esc(row.target_key || "-")}</code></td>
              <td>${esc(row.source_ip || "-")}</td>
            </tr>
          `).join("")
        : `<tr><td colspan="7">No access audit events found.</td></tr>`;

      section.innerHTML = `
        <h2>Access Audit Trail</h2>
        <p class="muted">Recent operator, token, and dashboard workflow actions recorded by the v0.23 Enterprise Access Control layer.</p>
        <div class="cards">
          <div class="card">
            <div class="label">Audit Events</div>
            <strong>${esc(summary.event_count || items.length || 0)}</strong>
          </div>
          <div class="card">
            <div class="label">Action Summary</div>
            <strong>${summaryText}</strong>
          </div>
        </div>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Action</th>
              <th>Actor</th>
              <th>Role</th>
              <th>Target Type</th>
              <th>Target</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      `;
    }

    function renderRecommendations(summary, scanContext, riskRows) {
      const steps = [];
      const latest = scanContext && scanContext.latest_scan ? scanContext.latest_scan : null;
      const latestFreshness = scanFreshness(latest);
      const risks = riskRows || [];
      const topRisk = risks.length ? risks[0] : null;
      const highRiskCount = risks.filter(row => ["CRITICAL", "HIGH"].includes(String(row.level || "").toUpperCase())).length;

      if (!latest) {
        steps.push("Import a NetSniper telemetry bundle so DeltaAegis has scan data to compare.");
      } else if (latestFreshness.stale) {
        steps.push("Run a fresh NetSniper scan before making decisions from this dashboard.");
      }

      if (topRisk && ["CRITICAL", "HIGH"].includes(String(topRisk.level || "").toUpperCase())) {
        steps.push(`Review the top ${esc(topRisk.level)} risk subject first: ${esc(topRisk.subject_key)}.`);
      } else if (topRisk) {
        steps.push(`Review the highest current risk subject: ${esc(topRisk.subject_key)}.`);
      }

      if (highRiskCount > 1) {
        steps.push(`Triage the ${highRiskCount} high-priority risk subjects before lower-risk changes.`);
      }

      if (summary && Number(summary.open_alerts || 0) > 0) {
        steps.push(`Review ${esc(summary.open_alerts)} open alert(s), then acknowledge or suppress them with a clear reason.`);
      }

      const latestSummary = latest && latest.asset_summary ? latest.asset_summary : {};
      const observed = Number(latestSummary.observed_assets || 0);
      const strong = Number(latestSummary.assets_with_ip_and_mac || 0);

      if (observed && strong < observed) {
        steps.push("Check partial or unknown identities because some assets do not have both MAC and IP evidence.");
      }

      if (summary && Number(summary.asset_annotations || 0) === 0) {
        steps.push("Add owner, role, and criticality annotations for important assets.");
      } else {
        steps.push("Keep asset owner, role, and criticality annotations updated as the network changes.");
      }

      risks
        .filter(row => Array.isArray(row.recommended_actions) && row.recommended_actions.length)
        .slice(0, 3)
        .forEach(row => {
          steps.push(`Role-aware follow-up for ${esc(row.subject_key)}: ${esc(row.recommended_actions[0])}`);
        });

      steps.push("Generate a Markdown investigation report after reviewing risk subjects and alerts.");

      document.getElementById("recommendations").innerHTML = steps
        .map(step => `<li>${step}</li>`)
        .join("");
    }

    async function load() {
      try {
        setupDashboardTabs();

        const [scopes, summary, scanContext, currentState, investigationCenter, scanJobs, assets, currentRisk, historicalRisk, portBehavior, events, alerts, annotations, accessAudit] = await Promise.all([
          api("/api/scopes"),
          api(scopedPath("/api/summary")),
          api(scopedPath("/api/scan-context")),
          api(scopedPath("/api/current-state")),
          api(investigationCenterFilterPath()),
          api(scopedPath("/api/scan-jobs?limit=10")),
          api(scopedPath("/api/assets?limit=25")),
          api(scopedPath("/api/current-risk?limit=10")),
          api(scopedPath("/api/risk?limit=10")),
          api(scopedPath("/api/port-behavior?limit=25&lookback=5")),
          api(scopedPath("/api/events?limit=20")),
          api(scopedPath("/api/alerts?limit=20")),
          api(scopedPath("/api/annotations?limit=20")),
          api(scopedPath("/api/access-audit?limit=20"))
        ]);

        renderScopes(scopes);
        renderMetrics(summary);
        renderCurrentState(currentState);
        renderInvestigationCenter(investigationCenter);
        renderTriageFilterOptions(investigationCenter);
        renderTriageSummaryPanel(investigationCenter);
      bindInvestigationCenterFilters();
        renderScanContext(scanContext);
        renderScanJobs(scanJobs);
        renderAssets(assets);
        renderRisk(currentRisk);
        renderHistoricalRisk(historicalRisk);
        renderPortBehavior(portBehavior);
        renderEvents(events);
        renderAlerts(alerts);
        renderAnnotations(annotations);
        renderAccessAudit(accessAudit);
        renderClassificationSummary(summary);
        renderRecommendations(summary, scanContext, historicalRisk);
        renderExecutiveCharts(summary, currentRisk, portBehavior, investigationCenter, assets, events, alerts);
        applyDashboardTabState();
      } catch (error) {
        const box = document.getElementById("error");
        box.style.display = "block";
        box.textContent = error.message;
      }
    }

    load();
    setInterval(load, 30000);
  </script>
</body>
</html>
"""


def command_dashboard(args):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs, urlparse

    db_path = args.db
    token = args.token

    class DeltaAegisDashboardHandler(BaseHTTPRequestHandler):
        server_version = "DeltaAegisDashboard/0.5.0"

        def log_message(self, fmt, *handler_args):
            if not args.quiet:
                super().log_message(fmt, *handler_args)

        def dashboard_request_token(self):
            supplied = self.headers.get("X-DeltaAegis-Token", "").strip()

            if supplied:
                return supplied

            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)

            return query.get("token", [""])[0].strip()

        def dashboard_legacy_actor(self, auth_type="dashboard_unauthenticated"):
            role = "ADMIN" if auth_type in {"legacy_dashboard_token", "dashboard_unauthenticated"} else "VIEWER"

            return {
                "auth_type": auth_type,
                "user_id": None,
                "username": "dashboard",
                "display_name": "DeltaAegis Dashboard",
                "role": role,
            }

        def authenticate_dashboard_request(self, required_role="VIEWER"):
            required_role = normalize_access_role(required_role)
            supplied = self.dashboard_request_token()
            self.current_actor = None

            if token and supplied == token:
                self.current_actor = self.dashboard_legacy_actor("legacy_dashboard_token")
                return True

            if supplied:
                connection = self.open_connection()

                try:
                    actor = authenticate_access_api_token(
                        connection,
                        supplied,
                        required_role=required_role,
                    )
                finally:
                    connection.close()

                if actor:
                    self.current_actor = actor
                    return True

            if not token and not supplied:
                self.current_actor = self.dashboard_legacy_actor("dashboard_unauthenticated")
                return True

            return False

        def authorized(self):
            return self.authenticate_dashboard_request(required_role="VIEWER")

        def require_auth(self, required_role="VIEWER"):
            if self.authenticate_dashboard_request(required_role=required_role):
                return True

            dashboard_json_response(
                self,
                {
                    "error": "unauthorized",
                    "message": "Provide a valid X-DeltaAegis-Token header or ?token=TOKEN. Database-backed API tokens are supported.",
                    "required_role": normalize_access_role(required_role),
                },
                status=401,
            )

            return False

        def open_connection(self):
            return connect(db_path)

        def do_GET(self):
            parsed = urlparse(self.path)
            route = parsed.path
            query = parse_qs(parsed.query)

            if route == "/healthz":
                dashboard_text_response(self, "ok")
                return

            if route == "/":
                dashboard_html_response(self, dashboard_index_html())
                return

            if not self.require_auth():
                return

            try:
                limit = int(query.get("limit", ["20"])[0])
            except ValueError:
                limit = 20

            limit = max(1, min(limit, 200))

            raw_scope = query.get("scope", [args.scope or ""])[0]
            scope = None

            if raw_scope:
                try:
                    scope = optional_network_scope(raw_scope)
                except ValueError:
                    dashboard_json_response(
                        self,
                        {
                            "error": "invalid_scope",
                            "scope": raw_scope,
                            "message": "Scope must be a valid CIDR network, such as 192.168.4.0/24.",
                        },
                        status=400,
                    )
                    return

            state = query.get("state", [""])[0].strip().upper() or None
            identity = query.get("identity", [""])[0].strip().upper() or None

            allowed_states = {"ACTIVE", "MISSING", "REMOVED", "EPHEMERAL_MISSING"}
            allowed_identities = {"GLOBAL_MAC", "LOCAL_MAC", "IP_ONLY"}

            if state and state not in allowed_states:
                dashboard_json_response(
                    self,
                    {
                        "error": "invalid_state",
                        "state": state,
                        "allowed": sorted(allowed_states),
                    },
                    status=400,
                )
                return

            if identity and identity not in allowed_identities:
                dashboard_json_response(
                    self,
                    {
                        "error": "invalid_identity",
                        "identity": identity,
                        "allowed": sorted(allowed_identities),
                    },
                    status=400,
                )
                return

            connection = self.open_connection()

            try:
                if route == "/api/scopes":
                    dashboard_json_response(self, dashboard_scopes_payload(connection))
                elif route == "/api/summary":
                    dashboard_json_response(self, dashboard_summary_payload(connection, scope=scope))
                elif route == "/api/scan-context":
                    dashboard_json_response(self, dashboard_scan_context_payload(connection, scope=scope))
                elif route == "/api/current-state":
                    dashboard_json_response(self, dashboard_current_state_payload(connection, scope=scope))
                elif route == "/api/scan-jobs":
                    status_filter = query.get("status", [""])[0].strip() or None
                    dashboard_json_response(
                        self,
                        dashboard_scan_jobs_payload(
                            connection,
                            limit=limit,
                            scope=scope,
                            status=status_filter,
                        ),
                    )
                elif route == "/api/assets":
                    dashboard_json_response(
                        self,
                        dashboard_assets_payload(
                            connection,
                            limit,
                            scope=scope,
                            state=state,
                            identity=identity,
                        ),
                    )
                elif route == "/api/asset":
                    identifier = query.get("identifier", query.get("asset_key", [""]))[0].strip()

                    dashboard_json_response(
                        self,
                        dashboard_asset_detail_payload(
                            connection,
                            identifier,
                            scope=scope,
                            limit=limit,
                        ),
                    )
                elif route == "/api/intelligence-host":
                    identifier = query.get("identity", query.get("host", [""]))[0].strip()

                    dashboard_json_response(
                        self,
                        dashboard_netsniper_intelligence_host_payload(
                            connection,
                            identifier,
                        ),
                    )
                elif route == "/api/ticket-evidence":
                    subject_key = query.get("subject_key", [""])[0]
                    evidence_limit = query.get("limit", ["10"])[0]
                    payload = dashboard_ticket_evidence_payload(
                        connection,
                        subject_key=subject_key,
                        scope=scope,
                        limit=evidence_limit,
                    )
                    dashboard_json_response(self, payload)
                elif route == "/api/investigation-center":
                    ticket_status = query.get("ticket_status", ["ALL"])[0]
                    ticket_signal = query.get("ticket_signal", ["ALL"])[0]
                    triage_bucket = query.get("triage_bucket", ["ALL"])[0]
                    triage_urgency = query.get("triage_urgency", ["ALL"])[0]

                    dashboard_json_response(
                        self,
                        dashboard_investigation_center_payload(
                            connection,
                            limit=limit,
                            scope=scope,
                            ticket_status=ticket_status,
                            ticket_signal=ticket_signal,
                            triage_bucket=triage_bucket,
                            triage_urgency=triage_urgency,
                        ),
                    )
                elif route == "/api/events":
                    dashboard_json_response(self, dashboard_events_payload(connection, limit, scope=scope))
                elif route == "/api/alerts":
                    dashboard_json_response(self, dashboard_alerts_payload(connection, limit, scope=scope))
                elif route == "/api/port-behavior":
                    lookback_value = query.get("lookback", ["5"])[0]

                    try:
                        lookback_limit = max(1, min(25, int(lookback_value)))
                    except ValueError:
                        lookback_limit = 5

                    dashboard_json_response(
                        self,
                        dashboard_port_behavior_payload(
                            connection,
                            limit=limit,
                            scope=scope,
                            lookback=lookback_limit,
                        ),
                    )
                elif route == "/api/current-risk":
                    dashboard_json_response(self, dashboard_current_risk_payload(connection, limit, scope=scope))
                elif route == "/api/risk":
                    dashboard_json_response(self, dashboard_risk_payload(connection, limit, scope=scope))
                elif route == "/api/annotations":
                    dashboard_json_response(self, dashboard_annotations_payload(connection, limit, scope=scope))
                elif route == "/api/access-audit":
                    action_filter = query.get("action", [""])[0].strip() or None
                    actor_filter = query.get("actor", [""])[0].strip() or None
                    target_type_filter = query.get("target_type", [""])[0].strip() or None

                    dashboard_json_response(
                        self,
                        dashboard_access_audit_payload(
                            connection,
                            limit=limit,
                            action=action_filter,
                            actor=actor_filter,
                            target_type=target_type_filter,
                        ),
                    )
                else:
                    dashboard_json_response(
                        self,
                        {
                            "error": "not_found",
                            "path": route,
                        },
                        status=404,
                    )
            finally:
                connection.close()

        def do_POST(self):
            parsed = urlparse(self.path)
            route = parsed.path

            if not self.require_auth(required_role="ANALYST"):
                return

            if route not in {"/api/investigate-asset", "/api/ticket-status"}:
                dashboard_json_response(
                    self,
                    {
                        "error": "not_found",
                        "path": route,
                    },
                    status=404,
                )
                return

            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                content_length = 0

            if content_length <= 0:
                dashboard_json_response(
                    self,
                    {
                        "error": "missing_body",
                        "message": "POST body must be JSON.",
                    },
                    status=400,
                )
                return

            if content_length > 65536:
                dashboard_json_response(
                    self,
                    {
                        "error": "body_too_large",
                        "message": "POST body is too large.",
                    },
                    status=413,
                )
                return

            try:
                raw_body = self.rfile.read(content_length).decode("utf-8")
                payload = json.loads(raw_body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                dashboard_json_response(
                    self,
                    {
                        "error": "invalid_json",
                        "message": "POST body must be valid JSON.",
                    },
                    status=400,
                )
                return


            if route == "/api/ticket-status":
                subject_key = str(
                    payload.get("subject_key")
                    or payload.get("identifier")
                    or ""
                ).strip()
                raw_scope = str(payload.get("scope") or "").strip()
                status = str(payload.get("status") or "").strip()
                note = str(payload.get("note") or payload.get("reason") or "").strip()
                analyst = str(payload.get("analyst") or "dashboard").strip()

                try:
                    scope = optional_network_scope(raw_scope) if raw_scope else None
                    connection = self.open_connection()

                    try:
                        state = set_ticket_state(
                            connection,
                            subject_key,
                            status,
                            analyst=analyst,
                            note=note,
                        )
                        record_access_audit_event(
                            connection,
                            action="DASHBOARD_TICKET_STATUS_UPDATE",
                            actor=getattr(self, "current_actor", None),
                            target_type="investigation_ticket",
                            target_key=state.get("ticket_key") or subject_key,
                            source_ip=self.client_address[0] if self.client_address else None,
                            user_agent=self.headers.get("User-Agent", ""),
                            details={
                                "subject_key": subject_key,
                                "scope": raw_scope,
                                "status": status,
                                "analyst": analyst,
                                "note_present": bool(note),
                            },
                        )
                        connection.commit()
                        investigation_center = dashboard_investigation_center_payload(
                            connection,
                            limit=25,
                            scope=scope,
                        )

                        dashboard_json_response(
                            self,
                            {
                                "ok": True,
                                "ticket_state": state,
                                "investigation_center": investigation_center,
                            },
                        )
                    finally:
                        connection.close()
                except (DeltaAegisError, ValueError) as exc:
                    dashboard_json_response(
                        self,
                        {
                            "ok": False,
                            "error": "ticket_status_failed",
                            "message": str(exc),
                        },
                        status=400,
                    )

                return

            identifier = str(payload.get("identifier") or "").strip()
            raw_scope = str(payload.get("scope") or "").strip()
            status = str(payload.get("status") or "").strip()
            reason = str(payload.get("reason") or "").strip()

            try:
                scope = optional_network_scope(raw_scope) if raw_scope else None
                connection = self.open_connection()

                try:
                    asset_key, resolved_scope = resolve_asset_for_investigation(
                        connection,
                        identifier,
                        scope=scope,
                    )
                    record = set_asset_investigation_status(
                        connection,
                        asset_key,
                        resolved_scope,
                        status,
                        reason,
                    )

                    record_access_audit_event(
                        connection,
                        action="DASHBOARD_ASSET_INVESTIGATION_UPDATE",
                        actor=getattr(self, "current_actor", None),
                        target_type="asset_investigation",
                        target_key=asset_key,
                        source_ip=self.client_address[0] if self.client_address else None,
                        user_agent=self.headers.get("User-Agent", ""),
                        details={
                            "identifier": identifier,
                            "asset_key": asset_key,
                            "scope": resolved_scope,
                            "status": status,
                            "reason_present": bool(reason),
                        },
                    )
                    connection.commit()

                    ticket_state = None
                    workflow_status = (
                        str(status or "")
                        .strip()
                        .upper()
                        .replace("-", "_")
                        .replace(" ", "_")
                    )

                    if workflow_status in TICKET_WORKFLOW_STATUSES:
                        ticket_state = set_ticket_state(
                            connection,
                            asset_key,
                            workflow_status,
                            analyst="dashboard",
                            note=reason,
                        )

                    connection.commit()

                    detail = dashboard_asset_detail_payload(
                        connection,
                        asset_key,
                        scope=resolved_scope,
                    )

                    dashboard_json_response(
                        self,
                        {
                            "ok": True,
                            "asset_key": asset_key,
                            "scope": resolved_scope,
                            "investigation": record,
                            "ticket_state": ticket_state,
                            "asset_detail": detail,
                        },
                    )
                finally:
                    connection.close()
            except (DeltaAegisError, ValueError) as exc:
                dashboard_json_response(
                    self,
                    {
                        "ok": False,
                        "error": "investigation_status_failed",
                        "message": str(exc),
                    },
                    status=400,
                )

    server_address = (args.host, args.port)
    server = ThreadingHTTPServer(server_address, DeltaAegisDashboardHandler)

    print("DeltaAegis dashboard starting")
    print("============================")
    print(f"URL:      http://{args.host}:{args.port}")
    print(f"Database: {db_path}")
    print("Mode:     dashboard + investigation status updates")

    if token:
        print("Auth:     token required")
        print("Header:   X-DeltaAegis-Token")
        print("DB Tokens: accepted via X-DeltaAegis-Token")
    else:
        print("Auth:     disabled")
        print("Warning:  bind to 127.0.0.1 unless you are using a trusted network")
        print("DB Tokens: accepted when supplied in X-DeltaAegis-Token")

    print()
    print("Press Ctrl+C to stop.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard.")
    finally:
        server.server_close()

    return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DeltaAegis v0.23.0 Enterprise Access Control, Operator Triage Intelligence, Evidence Timeline Intelligence, Workflow Filters and Operator Views, Investigation Workflow Actions, Executive SIEM Dashboard Refresh, Investigation Command Center, MAC-port behavior correlation, NetSniper scan orchestration, current-state SIEM dashboard, classification storage, calibrated risk policy, reporting, and dashboard console")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS)
    parser.add_argument("--events", type=Path, default=DEFAULT_EVENTS)
    parser.add_argument("--reports-dir", type=Path, default=DEFAULT_REPORTS)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("menu")
    p = sub.add_parser("user-create", help="Create a local DeltaAegis access user")
    p.add_argument("username")
    p.add_argument("--role", choices=list(ACCESS_ROLES), default="VIEWER")
    p.add_argument("--password", help="Initial password. For shared terminals, prefer setting this only during local setup.")
    p.add_argument("--display-name")
    p.add_argument("--inactive", action="store_true")
    p.add_argument("--actor", default="system", help="Audit actor name for this administrative action")

    p = sub.add_parser("users", help="List local DeltaAegis access users")
    p.add_argument("--include-inactive", action="store_true")

    p = sub.add_parser("api-token-create", help="Create a database-backed DeltaAegis API token")
    p.add_argument("username")
    p.add_argument("--name", default="DeltaAegis API Token")
    p.add_argument("--role", choices=list(ACCESS_ROLES), default=None)
    p.add_argument("--expires-at", help="Optional ISO-8601 expiration timestamp")
    p.add_argument("--actor", default="system", help="Audit actor name for this administrative action")

    p = sub.add_parser("api-tokens", help="List database-backed DeltaAegis API tokens")
    p.add_argument("--include-inactive", action="store_true")

    p = sub.add_parser("access-audit", help="List DeltaAegis access audit events")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--action")
    p.add_argument("--actor")
    p.add_argument("--target-type")

    sub.add_parser("ingest")
    p = sub.add_parser("scan-start", help="Run a safe NetSniper v1.8 headless scan job")
    p.add_argument("--target", required=True, help="Private IPv4 CIDR target, such as 192.168.5.0/24")
    p.add_argument("--netsniper-path", type=Path, default=DEFAULT_NETSNIPER)
    p.add_argument("--scan-logs-dir", type=Path, default=DEFAULT_SCAN_LOGS)
    p.add_argument("--auto-ingest", action="store_true", help="Ingest the completed NetSniper bundle after a successful scan")
    p = sub.add_parser("scan-jobs", help="List NetSniper scan orchestration jobs")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--status", choices=sorted(SCAN_JOB_STATUSES))
    p.add_argument("--scope")
    p = sub.add_parser("ticket-status", help="Show or update persistent investigation ticket workflow status")
    p.add_argument("subject_key")
    p.add_argument("--status", choices=["OPEN", "IN_REVIEW", "RESOLVED", "SUPPRESSED"])
    p.add_argument("--analyst")
    p.add_argument("--note")
    p.add_argument("--triage-bucket", default="ALL", help="Filter by triage bucket: ALL, CHANGED_SINCE_REVIEW, NEEDS_REVIEW, NEEDS_CONTEXT, STALE_CLOSED, BASELINE_CONTEXT, MONITOR")
    p.add_argument("--triage-urgency", default="ALL", help="Filter by triage urgency: ALL, IMMEDIATE, HIGH, NORMAL, LOW")

    p = sub.add_parser("ticket-evidence", help="Show evidence package for one investigation ticket")
    p.add_argument("--subject", dest="subject_key", required=True, help="Ticket subject key such as mac:aa:bb:cc:dd:ee:ff")
    p.add_argument("--scope", help="Optional network scope filter")
    p.add_argument("--limit", type=int, default=10, help="Maximum evidence rows per section")

    p = sub.add_parser("ticket-history", help="Show workflow history for one investigation ticket")
    p.add_argument("subject_key")
    p.add_argument("--limit", type=int, default=20)
    p = sub.add_parser("ticket-list", help="List persisted investigation ticket workflow states")
    p.add_argument("--status", choices=["OPEN", "IN_REVIEW", "RESOLVED", "SUPPRESSED"])
    p.add_argument("--limit", type=int, default=50)
    p = sub.add_parser("investigation-center", help="Show prioritized investigation command center queue")
    p.add_argument("--limit", type=int, default=25)
    p.add_argument("--scope")
    p.add_argument("--ticket-status", choices=["ALL", "OPEN", "IN_REVIEW", "RESOLVED", "SUPPRESSED"], default="ALL", help="Filter Investigation Center tickets by workflow status")
    p.add_argument("--ticket-signal", choices=["ALL", "ACTIONABLE", "MEANINGFUL_CHANGE", "BASELINE_CONTEXT"], default="ALL", help="Filter Investigation Center tickets by signal label")
    p.add_argument("--triage-bucket", default="ALL", help="Filter by triage bucket: ALL, CHANGED_SINCE_REVIEW, NEEDS_REVIEW, NEEDS_CONTEXT, STALE_CLOSED, BASELINE_CONTEXT, MONITOR")
    p.add_argument("--triage-urgency", default="ALL", help="Filter by triage urgency: ALL, IMMEDIATE, HIGH, NORMAL, LOW")

    p = sub.add_parser("port-behavior", help="Show MAC-port behavior changes across accepted scans")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--scope")
    p.add_argument("--lookback", type=int, default=5, help="Accepted scan history depth to compare")
    sub.add_parser("scopes")
    p = sub.add_parser("summary")
    p = sub.add_parser("snapshots"); p.add_argument("--limit", type=int, default=20); p.add_argument("--scope")
    p = sub.add_parser("events"); p.add_argument("--limit", type=int, default=50); p.add_argument("--severity"); p.add_argument("--event-type"); p.add_argument("--scope")
    p = sub.add_parser("alerts"); p.add_argument("--status", choices=["OPEN", "ACKNOWLEDGED", "RESOLVED", "SUPPRESSED"], default="OPEN"); p.add_argument("--limit", type=int, default=50); p.add_argument("--scope")
    p = sub.add_parser("ack"); p.add_argument("alert_id", type=int); p.add_argument("--reason")
    p = sub.add_parser("suppress"); p.add_argument("alert_id", type=int); p.add_argument("--reason")
    p = sub.add_parser("assets")
    p.add_argument("--scope")
    p.add_argument("--state", choices=["ACTIVE", "MISSING", "REMOVED", "EPHEMERAL_MISSING"])
    p.add_argument("--identity", choices=["GLOBAL_MAC", "LOCAL_MAC", "IP_ONLY"])
    p.add_argument("--limit", type=int, default=50)

    p = sub.add_parser("asset")
    p.add_argument("identifier")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--scope")
    p = sub.add_parser("health"); p.add_argument("--limit", type=int, default=20)
    p = sub.add_parser("approve"); p.add_argument("scan_id")
    p = sub.add_parser("latest"); p.add_argument("--scope")

    p = sub.add_parser("annotate-asset")
    p.add_argument("asset_key")
    p.add_argument("--owner")
    p.add_argument("--role")
    p.add_argument("--criticality")
    p.add_argument("--notes")

    p = sub.add_parser("investigate-asset")
    p.add_argument("identifier")
    p.add_argument(
        "--status",
        required=True,
        choices=sorted(INVESTIGATION_STATUSES),
    )
    p.add_argument("--reason", required=True)
    p.add_argument("--scope")

    p = sub.add_parser("asset-notes")
    p.add_argument("asset_key")
    p.add_argument("--history", action="store_true")

    p = sub.add_parser("asset-annotations")
    p.add_argument("--limit", type=int, default=50)

    p = sub.add_parser("asset-timeline")
    p.add_argument("asset_key")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--severity")

    p = sub.add_parser("alert-detail")
    p.add_argument("alert_id", type=int)

    p = sub.add_parser("alert-notes")
    p.add_argument("alert_id", type=int)

    p = sub.add_parser("intelligence", help="Show latest NetSniper v1.7 intelligence summary")

    p = sub.add_parser("intelligence-hosts", help="List NetSniper v1.7 per-host intelligence drilldown rows")
    p.add_argument("--limit", type=int, default=25)
    p.add_argument("--action", help="Filter by SIEM action, such as review_queue")
    p.add_argument("--decision", help="Filter by classification decision, such as possible or classified")
    p.add_argument("--band", help="Filter by confidence band, such as weak, possible, strong, high, or unknown")

    p = sub.add_parser("intelligence-host", help="Show NetSniper v1.7 intelligence drilldown for one host")
    p.add_argument("identity", help="Host ID, IP, MAC, or hostname")
    p = sub.add_parser("dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8090)
    p.add_argument("--token")
    p.add_argument("--scope")
    p.add_argument("--quiet", action="store_true")

    p = sub.add_parser("risk")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--subject")
    p.add_argument("--scope")
    p.add_argument("--details", action="store_true")

    p = sub.add_parser("asset-risk")
    p.add_argument("subject_key")
    p.add_argument("--scope")

    p = sub.add_parser("report")
    p.add_argument("--latest", action="store_true")
    p.add_argument("--since")
    p.add_argument("--severity")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--risk-limit", type=int, default=10)
    p.add_argument("--asset-limit", type=int, default=25)
    p.add_argument("--scope")
    p.add_argument("--output", type=Path)

    sub.add_parser("paths")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command in {None, "menu"}: return run_interactive_menu(args)
        if args.command == "user-create": return command_user_create(args)
        if args.command == "users": return command_users(args)
        if args.command == "api-token-create": return command_api_token_create(args)
        if args.command == "api-tokens": return command_api_tokens(args)
        if args.command == "access-audit": return command_access_audit(args)
        if args.command == "ingest": return command_ingest(args)
        if args.command == "scan-start": return command_scan_start(args)
        if args.command == "scan-jobs": return command_scan_jobs(args)
        if args.command == "ticket-status": return command_ticket_status(args)
        if args.command == "ticket-evidence": return command_ticket_evidence(args)
        if args.command == "ticket-history": return command_ticket_history(args)
        if args.command == "ticket-list": return command_ticket_list(args)
        if args.command == "investigation-center": return command_investigation_center(args)
        if args.command == "port-behavior": return command_port_behavior(args)
        if args.command == "summary": return command_summary(args)
        if args.command == "scopes": return command_scopes(args)
        if args.command == "snapshots": return command_snapshots(args)
        if args.command == "events": return command_events(args)
        if args.command == "alerts": return command_alerts(args)
        if args.command == "ack": return set_alert_status(args, "ACKNOWLEDGED")
        if args.command == "suppress": return set_alert_status(args, "SUPPRESSED")
        if args.command == "assets": return command_assets(args)
        if args.command == "asset": return command_asset(args)
        if args.command == "health": return command_health(args)
        if args.command == "approve": return command_approve(args)
        if args.command == "latest": return command_latest(args)
        if args.command == "annotate-asset": return command_annotate_asset(args)

        if args.command == "asset-notes": return command_asset_notes(args)

        if args.command == "asset-annotations": return command_asset_annotations(args)

        if args.command == "asset-timeline": return command_asset_timeline(args)

        if args.command == "alert-detail": return command_alert_detail(args)
        if args.command == "alert-notes": return command_alert_notes(args)


        if args.command == "investigate-asset": return command_investigate_asset(args)
        if args.command == "intelligence": return command_intelligence(args)
        if args.command == "intelligence-hosts": return command_intelligence_hosts(args)
        if args.command == "intelligence-host": return command_intelligence_host(args)
        if args.command == "dashboard": return command_dashboard(args)

        if args.command == "risk": return command_risk(args)

        if args.command == "asset-risk": return command_asset_risk(args)

        if args.command == "report": return command_report(args)

        if args.command == "paths": return command_paths(args)
        raise DeltaAegisError(f"unknown command: {args.command}")
    except DeltaAegisError as exc:
        print(f"DeltaAegis error: {exc}", file=sys.stderr); return 1


if __name__ == "__main__":
    raise SystemExit(main())
