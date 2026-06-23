#!/usr/bin/env python3
"""DeltaAegis v0.11.1: NetSniper v1.7 intelligence review dashboard, classification storage, calibrated SIEM risk policy, investigation workflow, reporting, and dashboard console.

Consumes finalized NetSniper run bundles, preserves snapshot evidence, tracks
stable and ephemeral identities separately, applies a three-scan removal
threshold, and maintains operator-facing alert state without discarding the
append-only delta-event history.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

DEFAULT_DB = Path.home() / "DeltaAegis" / "data" / "deltaaegis.db"
DEFAULT_RUNS = Path.home() / "NetSniper" / "runs"
DEFAULT_EVENTS = Path.home() / "DeltaAegis" / "events" / "events.jsonl"
DEFAULT_REPORTS = Path.home() / "DeltaAegis" / "reports"
QUALITY_RATIO_THRESHOLD = 0.50
IDENTITY_COVERAGE_THRESHOLD = 0.50
IDENTITY_DROP_REVIEW_THRESHOLD = 0.25
REMOVAL_THRESHOLD = 3
MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


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
    append_report_risk_section(lines, report_risk_rows)
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
  <title>DeltaAegis Dashboard</title>
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

  </style>
</head>
<body>
  <header>
    <h1>DeltaAegis Dashboard</h1>
    <p>Local investigation dashboard for network deltas, alerts, annotations, risk prioritization, and asset review workflow.</p>
  </header>

  <main>
    <div id="error" class="error"></div>

    <nav class="dashboard-tabs" aria-label="DeltaAegis dashboard sections">
      <button type="button" class="tab-button" data-tab-target="overview">Overview</button>
      <button type="button" class="tab-button" data-tab-target="investigations">Investigations</button>
      <button type="button" class="tab-button" data-tab-target="risk">Risk</button>
      <button type="button" class="tab-button" data-tab-target="assets">Assets</button>
      <button type="button" class="tab-button" data-tab-target="intelligence">Intelligence</button>
      <button type="button" class="tab-button" data-tab-target="events">Events</button>
      <button type="button" class="tab-button" data-tab-target="alerts">Alerts</button>
    </nav>

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

    <section class="card" data-tab-panel="overview">
      <h2>Network Scopes</h2>
      <p class="muted">Choose which subnet scope the dashboard should display. Deltas are only meaningful inside the same network scope.</p>
      <div id="selected-scope" class="callout">Viewing all network scopes.</div>
      <div id="scope-links" class="scope-links"></div>
    </section>

    <section class="card" data-tab-panel="overview">
      <h2>NetSniper Scan Context</h2>
      <p class="muted">Shows the latest NetSniper scan, the baseline scan used for delta comparison, and identity coverage for MAC/IP tracking.</p>
      <div class="scan-grid" id="scan-context"></div>
    </section>

    <section class="card" data-tab-panel="assets">
      <h2>Asset Inventory</h2>
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
      <h2>Top Risk Subjects</h2>
      <table>
        <thead>
          <tr><th>Level</th><th>Score</th><th>Subject</th><th>IP</th><th>MAC</th><th>Identity</th><th>Owner</th><th>Role</th><th>Open Alerts</th><th>Events</th><th>Primary Reason</th></tr>
        </thead>
        <tbody id="risk-body"></tbody>
      </table>
    </section>

    <section class="card" data-tab-panel="events">
      <h2>Recent Delta Events</h2>
      <table>
        <thead>
          <tr><th>ID</th><th>Scan</th><th>Baseline</th><th>Severity</th><th>Type</th><th>Subject</th><th>IP</th><th>MAC</th><th>Identity</th><th>Created</th><th>Summary</th></tr>
        </thead>
        <tbody id="events-body"></tbody>
      </table>
    </section>

    <section class="card" data-tab-panel="alerts">
      <h2>Recent Alerts</h2>
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
      "investigations",
      "risk",
      "assets",
      "intelligence",
      "events",
      "alerts"
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
      return `<div class="card"><div class="label">${esc(label)}</div><div class="metric">${esc(value)}</div></div>`;
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

    function renderRisk(rows) {
  const tbody = document.getElementById("risk-body");

  if (!tbody) return;

  if (!rows || !rows.length) {
    tbody.innerHTML = `<tr><td colspan="11">No risk subjects calculated for the current dashboard scope.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map(row => {
    const reasons = Array.isArray(row.reasons) ? row.reasons : [];
    const primaryReason = reasons.length ? reasons[0] : "-";

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
        <td>${esc(row.event_count ?? 0)}</td>
        <td>${esc(primaryReason)}</td>
      </tr>
    `;
  }).join("");

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

        const [scopes, summary, scanContext, assets, risk, events, alerts, annotations] = await Promise.all([
          api("/api/scopes"),
          api(scopedPath("/api/summary")),
          api(scopedPath("/api/scan-context")),
          api(scopedPath("/api/current-state")),
          api(scopedPath("/api/assets?limit=25")),
          api(scopedPath("/api/risk?limit=10")),
          api(scopedPath("/api/events?limit=20")),
          api(scopedPath("/api/alerts?limit=20")),
          api(scopedPath("/api/annotations?limit=20"))
        ]);

        renderScopes(scopes);
        renderMetrics(summary);
        renderScanContext(scanContext);
        renderAssets(assets);
        renderRisk(risk);
        renderEvents(events);
        renderAlerts(alerts);
        renderAnnotations(annotations);
        renderClassificationSummary(summary);
        renderRecommendations(summary, scanContext, risk);
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

        def authorized(self):
            if not token:
                return True

            supplied = self.headers.get("X-DeltaAegis-Token", "")

            if supplied == token:
                return True

            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)

            return query.get("token", [""])[0] == token

        def require_auth(self):
            if self.authorized():
                return True

            dashboard_json_response(
                self,
                {
                    "error": "unauthorized",
                    "message": "Provide X-DeltaAegis-Token header or ?token=TOKEN.",
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
                elif route == "/api/events":
                    dashboard_json_response(self, dashboard_events_payload(connection, limit, scope=scope))
                elif route == "/api/alerts":
                    dashboard_json_response(self, dashboard_alerts_payload(connection, limit, scope=scope))
                elif route == "/api/risk":
                    dashboard_json_response(self, dashboard_risk_payload(connection, limit, scope=scope))
                elif route == "/api/annotations":
                    dashboard_json_response(self, dashboard_annotations_payload(connection, limit, scope=scope))
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

            if not self.require_auth():
                return

            if route != "/api/investigate-asset":
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
    else:
        print("Auth:     disabled")
        print("Warning:  bind to 127.0.0.1 unless you are using a trusted network")

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
    parser = argparse.ArgumentParser(description="DeltaAegis v0.11.1 NetSniper v1.7 intelligence review dashboard, classification storage, calibrated SIEM risk policy, investigation workflow, reporting, and dashboard console")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS)
    parser.add_argument("--events", type=Path, default=DEFAULT_EVENTS)
    parser.add_argument("--reports-dir", type=Path, default=DEFAULT_REPORTS)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("menu")
    sub.add_parser("ingest")
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
        if args.command == "ingest": return command_ingest(args)
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
