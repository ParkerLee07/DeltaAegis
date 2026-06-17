#!/usr/bin/env python3
"""DeltaAegis v0.4.1: delta-first network-state monitoring, investigation, risk prioritization, and reporting console.

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
    asset_key TEXT PRIMARY KEY,
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
    removed_at TEXT
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
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_column(connection: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


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
    ensure_column(connection, "asset_observations", "identity_class", "identity_class TEXT NOT NULL DEFAULT 'IP_ONLY'")
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
        confidence = "HIGH" if source in {"DISCOVERY_XML", "SERVICE_XML"} else "MEDIUM" if source == "NEIGHBOR_TABLE" else "LOW"
        preliminary.append(AssetObservation("", classify_identity(mac), confidence, source, ipv4, mac, vendor, hostname, interpretation.get("device_type"), interpretation.get("severity"), interpretation.get("score"), sorted(services, key=lambda item: item.key), [item for item in findings if isinstance(item, dict)]))
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


def snapshot_exists(connection: sqlite3.Connection, scan_id: str) -> bool:
    return connection.execute("SELECT 1 FROM snapshots WHERE scan_id = ?", (scan_id,)).fetchone() is not None


def latest_accepted_snapshot(connection: sqlite3.Connection, target: str) -> sqlite3.Row | None:
    return connection.execute("SELECT * FROM snapshots WHERE target = ? AND quality_status = 'ACCEPTED' ORDER BY created_at DESC, imported_at DESC LIMIT 1", (target,)).fetchone()


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
    connection.execute("""INSERT INTO snapshots (scan_id, manifest_path, target, scanner_version, scan_profile, created_at, imported_at, bundle_status, quality_status, quality_reason, xml_exit_status, hosts_up, hosts_down, hosts_total, mac_backed_assets, identity_coverage, is_accepted_baseline, manifest_schema_version, profile_fingerprint, monitored_ports_json, protocols_json, discovery_interface, nmap_version, scan_started_at, scan_completed_at, neighbors_captured_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (snapshot.scan_id, snapshot.manifest_path, snapshot.target, snapshot.scanner_version, snapshot.scan_profile, snapshot.created_at, utc_now(), snapshot.bundle_status, quality_status, quality_reason, snapshot.xml_exit_status, snapshot.hosts_up, snapshot.hosts_down, snapshot.hosts_total, snapshot.mac_backed_assets, snapshot.identity_coverage, 1 if quality_status == "ACCEPTED" else 0, snapshot.manifest_schema_version, snapshot.profile_fingerprint, json.dumps(snapshot.monitored_ports), json.dumps(snapshot.protocols), snapshot.discovery_interface, snapshot.nmap_version, snapshot.scan_started_at, snapshot.scan_completed_at, snapshot.neighbors_captured_at))
    for asset in snapshot.assets.values():
        connection.execute("""INSERT INTO asset_observations (scan_id, asset_key, identity_class, identity_confidence, identity_source, ip_address, mac_address, vendor, hostname, device_type, severity, score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (snapshot.scan_id, asset.asset_key, asset.identity_class, asset.identity_confidence, asset.identity_source, asset.ip_address, asset.mac_address, asset.vendor, asset.hostname, asset.device_type, asset.severity, asset.score))
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
        assets[row["asset_key"]] = AssetObservation(row["asset_key"], row["identity_class"], row["identity_confidence"], row["identity_source"], row["ip_address"], row["mac_address"], row["vendor"], row["hostname"], row["device_type"], row["severity"], row["score"], services, findings)
    return assets


def event(event_type: str, severity: str, subject_key: str, summary: str, previous_value: Any = None, current_value: Any = None) -> dict[str, Any]:
    return {"event_type": event_type, "severity": severity, "subject_key": subject_key, "summary": summary, "previous_value": previous_value, "current_value": current_value}


def reset_lifecycle(connection: sqlite3.Connection, scan_id: str, created_at: str, assets: dict[str, AssetObservation]) -> None:
    connection.execute("DELETE FROM asset_lifecycle")
    for asset in assets.values():
        connection.execute("""INSERT INTO asset_lifecycle (asset_key, identity_class, state, missing_count, current_ip, mac_address, vendor, hostname, first_seen_scan_id, last_seen_scan_id, first_seen_at, last_seen_at, removed_at) VALUES (?, ?, 'ACTIVE', 0, ?, ?, ?, ?, ?, ?, ?, ?, NULL)""", (asset.asset_key, asset.identity_class, asset.ip_address, asset.mac_address, asset.vendor, asset.hostname, scan_id, scan_id, created_at, created_at))


def initialize_lifecycle(connection: sqlite3.Connection, snapshot: Snapshot) -> None:
    reset_lifecycle(connection, snapshot.scan_id, snapshot.created_at, snapshot.assets)


def lifecycle_events(connection: sqlite3.Connection, snapshot: Snapshot) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    existing = {row["asset_key"]: row for row in connection.execute("SELECT * FROM asset_lifecycle")}
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
            connection.execute("""INSERT INTO asset_lifecycle (asset_key, identity_class, state, missing_count, current_ip, mac_address, vendor, hostname, first_seen_scan_id, last_seen_scan_id, first_seen_at, last_seen_at, removed_at) VALUES (?, ?, 'ACTIVE', 0, ?, ?, ?, ?, ?, ?, ?, ?, NULL)""", (key, asset.identity_class, asset.ip_address, asset.mac_address, asset.vendor, asset.hostname, snapshot.scan_id, snapshot.scan_id, snapshot.created_at, snapshot.created_at))
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
        connection.execute("""UPDATE asset_lifecycle SET identity_class = ?, state = 'ACTIVE', missing_count = 0, current_ip = ?, mac_address = ?, vendor = COALESCE(?, vendor), hostname = COALESCE(?, hostname), last_seen_scan_id = ?, last_seen_at = ?, removed_at = NULL WHERE asset_key = ?""", (asset.identity_class, asset.ip_address, asset.mac_address, asset.vendor, asset.hostname, snapshot.scan_id, snapshot.created_at, key))
    for key, row in existing.items():
        if key in current_keys:
            continue
        missing_count = int(row["missing_count"]) + 1
        if row["identity_class"] == "LOCAL_MAC":
            if row["state"] == "ACTIVE":
                events.append(event("EPHEMERAL_IDENTITY_NOT_OBSERVED", "INFO", key, f"Locally administered identity {key} was not observed in the current accepted snapshot. Last known IP: {row['current_ip']}."))
            connection.execute("UPDATE asset_lifecycle SET state = 'EPHEMERAL_MISSING', missing_count = ? WHERE asset_key = ?", (missing_count, key))
        elif row["identity_class"] == "GLOBAL_MAC":
            if row["state"] == "ACTIVE":
                events.append(event("ASSET_NOT_OBSERVED", "LOW", key, f"Previously observed asset {key} was not observed in the current accepted snapshot. Last known IP: {row['current_ip']}."))
                connection.execute("UPDATE asset_lifecycle SET state = 'MISSING', missing_count = ? WHERE asset_key = ?", (missing_count, key))
            elif row["state"] != "REMOVED" and missing_count >= REMOVAL_THRESHOLD:
                events.append(event("ASSET_REMOVED", "MEDIUM", key, f"Asset {key} has not been observed in {REMOVAL_THRESHOLD} consecutive accepted snapshots. Last known IP: {row['current_ip']}."))
                connection.execute("UPDATE asset_lifecycle SET state = 'REMOVED', missing_count = ?, removed_at = ? WHERE asset_key = ?", (missing_count, snapshot.created_at, key))
            elif row["state"] != "REMOVED":
                connection.execute("UPDATE asset_lifecycle SET missing_count = ? WHERE asset_key = ?", (missing_count, key))
        else:
            if row["state"] == "ACTIVE":
                events.append(event("IP_NOT_OBSERVED", "LOW", key, f"Previously observed IP address {row['current_ip']} was not observed in the current accepted snapshot."))
            connection.execute("UPDATE asset_lifecycle SET state = 'MISSING', missing_count = ? WHERE asset_key = ?", (missing_count, key))
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


def query_events(connection: sqlite3.Connection, limit: int, severity: str | None = None, event_type: str | None = None) -> list[sqlite3.Row]:
    clauses, params = [], []
    if severity:
        clauses.append("severity = ?"); params.append(severity.upper())
    if event_type:
        clauses.append("event_type = ?"); params.append(event_type.upper())
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    params.append(limit)
    return connection.execute(f"SELECT event_id, created_at, severity, event_type, subject_key, summary FROM delta_events{where} ORDER BY event_id DESC LIMIT ?", tuple(params)).fetchall()


def print_event_rows(rows: Iterable[sqlite3.Row]) -> None:
    rows = list(rows)
    if not rows:
        print("No matching delta events found.")
    for row in rows:
        print(f"{row['event_id']:>5}  {row['severity']:<6}  {row['event_type']:<36}  {row['subject_key']}")
        print(f"       {row['summary']}")


def command_events(args: argparse.Namespace) -> int:
    print_event_rows(query_events(connect(args.db), args.limit, getattr(args, "severity", None), getattr(args, "event_type", None)))
    return 0


def command_snapshots(args: argparse.Namespace) -> int:
    rows = connect(args.db).execute("SELECT scan_id, created_at, manifest_schema_version, target, scan_profile, quality_status, hosts_up, hosts_total, identity_coverage FROM snapshots ORDER BY created_at DESC, imported_at DESC LIMIT ?", (args.limit,)).fetchall()
    for row in rows:
        print(f"{row['scan_id']}  {row['quality_status']:<15}  hosts={row['hosts_up']}/{row['hosts_total']}  mac_identity={float(row['identity_coverage']):.0%}  schema={row['manifest_schema_version']}  profile={row['scan_profile']}  target={row['target']}")
    return 0


def command_summary(args: argparse.Namespace) -> int:
    connection = connect(args.db)
    snapshot_count = connection.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
    accepted_count = connection.execute("SELECT COUNT(*) FROM snapshots WHERE quality_status = 'ACCEPTED'").fetchone()[0]
    event_count = connection.execute("SELECT COUNT(*) FROM delta_events").fetchone()[0]
    open_alerts = connection.execute("SELECT COUNT(*) FROM alerts WHERE status = 'OPEN'").fetchone()[0]
    latest = connection.execute("SELECT scan_id, quality_status, hosts_up, identity_coverage FROM snapshots ORDER BY created_at DESC LIMIT 1").fetchone()
    print("DeltaAegis v0.4.1 Summary")
    print(f"Snapshots imported: {snapshot_count}")
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
    reset_lifecycle(connection, args.scan_id, row["created_at"], assets)
    connection.execute("UPDATE snapshots SET quality_status = 'ACCEPTED', quality_reason = ?, is_accepted_baseline = 1 WHERE scan_id = ?", ("Manually approved as the new baseline by the operator.", args.scan_id))
    approval = event("PROFILE_BASELINE_APPROVED", "INFO", f"scan:{args.scan_id}", "Operator approved this reviewed snapshot as the new comparison baseline.")
    store_events(connection, args.scan_id, previous["scan_id"] if previous else None, [approval], args.events)
    connection.commit()
    print(f"Snapshot {args.scan_id} approved as the new baseline.")
    return 0


def command_alerts(args: argparse.Namespace) -> int:
    connection = connect(args.db)
    rows = connection.execute("SELECT alert_id, status, severity, event_type, subject_key, summary, opened_at FROM alerts WHERE status = ? ORDER BY alert_id DESC LIMIT ?", (args.status.upper(), args.limit)).fetchall()
    if not rows:
        print(f"No {args.status.upper()} alerts found.")
    for row in rows:
        print(f"{row['alert_id']:>5}  {row['status']:<12}  {row['severity']:<6}  {row['event_type']:<30}  {row['subject_key']}")
        print(f"       {row['summary']}")
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

def command_asset(args: argparse.Namespace) -> int:
    connection = connect(args.db)
    identifier = args.identifier.strip().lower()
    row = connection.execute("SELECT * FROM asset_lifecycle WHERE asset_key = ?", (identifier,)).fetchone()
    if row is None:
        row = connection.execute("SELECT * FROM asset_lifecycle WHERE current_ip = ?", (identifier,)).fetchone()
    if row is None:
        raise DeltaAegisError(f"asset not found: {args.identifier}")
    print("Asset History")
    print("────────────────────────────────────────")
    for label, key in [("Asset key", "asset_key"), ("Identity class", "identity_class"), ("State", "state"), ("Missing scans", "missing_count"), ("Current IP", "current_ip"), ("MAC address", "mac_address"), ("Vendor", "vendor"), ("Hostname", "hostname"), ("First seen", "first_seen_at"), ("Last seen", "last_seen_at")]:
        print(f"{label + ':':<18}{row[key] or '-'}")
    print("\nRecent events")
    print_event_rows(connection.execute("SELECT event_id, created_at, severity, event_type, subject_key, summary FROM delta_events WHERE subject_key = ? ORDER BY event_id DESC LIMIT ?", (row["asset_key"], args.limit)).fetchall())
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
    row = connect(args.db).execute("SELECT * FROM snapshots WHERE quality_status='ACCEPTED' ORDER BY created_at DESC, imported_at DESC LIMIT 1").fetchone()
    if row is None:
        print("No accepted DeltaAegis snapshot has been imported yet."); return 0
    print("Latest Accepted Snapshot\n────────────────────────────────────────")
    print(f"Snapshot ID:        {row['scan_id']}")
    print(f"Quality:            {row['quality_status']}")
    print(f"Hosts observed:     {row['hosts_up']}/{row['hosts_total']}")
    print(f"MAC identity:       {float(row['identity_coverage']):.0%}")
    print(f"Manifest schema:    {row['manifest_schema_version']}")
    print(f"Scanner version:    {row['scanner_version']}")
    print(f"Scan profile:       {row['scan_profile']}")
    print(f"Target:             {row['target']}")
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


def report_event_rows(connection, latest_only, since, severity, limit):
    clauses = []
    params = []

    if latest_only:
        latest = fetch_latest_accepted_snapshot(connection)
        if latest is None:
            print("No accepted snapshot exists for --latest report.")
            return []
        clauses.append("scan_id = ?")
        params.append(latest["scan_id"])

    if since:
        clauses.append("created_at >= ?")
        params.append(since)

    if severity:
        clauses.append("severity = ?")
        params.append(str(severity).upper())

    where = " WHERE " + " AND ".join(clauses) if clauses else ""

    params.append(limit)

    return connection.execute(
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
        {where}
        ORDER BY event_id DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()



RISK_SEVERITY_POINTS = {
    "CRITICAL": 40,
    "HIGH": 30,
    "MEDIUM": 15,
    "LOW": 5,
    "INFO": 1,
}

RISK_CRITICALITY_POINTS = {
    "CRITICAL": 25,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 0,
}


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


def build_risk_register(connection, limit, subject_filter=None):
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

    event_rows = connection.execute(
        """
        SELECT subject_key, severity, event_type, created_at, summary
        FROM delta_events
        ORDER BY event_id DESC
        LIMIT 500
        """
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

    alert_rows = connection.execute(
        """
        SELECT alert_id, status, severity, event_type, subject_key, summary, last_seen_at
        FROM alerts
        ORDER BY alert_id DESC
        LIMIT 500
        """
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

        record["score"] = min(100, score)
        record["level"] = risk_level(record["score"])

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

    rows = build_risk_register(
        connection,
        args.limit,
        subject_filter=args.subject,
    )

    print("DeltaAegis Risk Register")
    print("========================")
    print()

    if not rows:
        print("No risk subjects were found.")
        return 0

    for record in rows:
        print_risk_record(record, detailed=args.details)

    return 0


def command_asset_risk(args):
    connection = connect(args.db)

    rows = build_risk_register(
        connection,
        None,
        subject_filter=args.subject_key,
    )

    exact = [
        row for row in rows
        if row["subject_key"] == args.subject_key
    ]

    if exact:
        rows = exact

    print(f"Asset Risk: {args.subject_key}")
    print("=" * (12 + len(args.subject_key)))
    print()

    if not rows:
        print("No risk data matched this subject key.")
        return 1

    for record in rows:
        print_risk_record(record, detailed=True)

    return 0


def append_report_risk_section(lines, risk_rows):
    lines.append("## Top Risk Subjects")
    lines.append("")

    if not risk_rows:
        lines.append("No risk subjects were calculated for this report.")
        lines.append("")
        return

    lines.append("| Level | Score | Subject | Owner | Role | Criticality | Open Alerts | Events | Primary Reason |")
    lines.append("|---|---:|---|---|---|---|---:|---:|---|")

    for record in risk_rows:
        reasons = record.get("reasons") or []
        primary_reason = reasons[0] if reasons else "-"

        lines.append(
            "| "
            f"{safe_markdown(record['level'])} | "
            f"{record['score']} | "
            f"`{safe_markdown(record['subject_key'])}` | "
            f"{safe_markdown(record.get('owner') or '-')} | "
            f"{safe_markdown(record.get('role') or '-')} | "
            f"{safe_markdown(record.get('criticality') or '-')} | "
            f"{record.get('open_alerts', 0)} | "
            f"{record.get('event_count', 0)} | "
            f"{safe_markdown(primary_reason)} |"
        )

    lines.append("")
    lines.append("Risk scores are explainable and are calculated from recent delta events, alert state, repeated activity, asset criticality, and missing asset context.")
    lines.append("")

def command_report(args):
    from collections import Counter
    from datetime import datetime, timezone

    connection = connect(args.db)

    reports_dir = args.reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)

    events = report_event_rows(
        connection=connection,
        latest_only=args.latest,
        since=args.since,
        severity=args.severity,
        limit=args.limit,
    )

    latest_snapshot = fetch_latest_accepted_snapshot(connection)

    snapshot_count = connection.execute(
        "SELECT COUNT(*) FROM snapshots"
    ).fetchone()[0]

    accepted_count = connection.execute(
        "SELECT COUNT(*) FROM snapshots WHERE quality_status = 'ACCEPTED'"
    ).fetchone()[0]

    open_alerts = connection.execute(
        """
        SELECT alert_id, severity, event_type, subject_key, summary, opened_at
        FROM alerts
        WHERE status = 'OPEN'
        ORDER BY alert_id DESC
        LIMIT 25
        """
    ).fetchall()

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
    lines.append(f"- Snapshots imported: **{snapshot_count}**")
    lines.append(f"- Accepted snapshots: **{accepted_count}**")
    lines.append(f"- Events included in this report: **{len(events)}**")
    lines.append(f"- Open alerts: **{len(open_alerts)}**")
    lines.append("")

    lines.append("## Report Scope")
    lines.append("")
    lines.append(f"- Latest snapshot only: `{args.latest}`")
    lines.append(f"- Since: `{args.since or 'not specified'}`")
    lines.append(f"- Severity filter: `{args.severity or 'not specified'}`")
    lines.append(f"- Event limit: `{args.limit}`")
    lines.append("")

    append_report_risk_section(lines, report_risk_rows)

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DeltaAegis v0.4.1 delta-first network-state monitoring, investigation, risk prioritization, and reporting console")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS)
    parser.add_argument("--events", type=Path, default=DEFAULT_EVENTS)
    parser.add_argument("--reports-dir", type=Path, default=DEFAULT_REPORTS)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("menu")
    sub.add_parser("ingest")
    p = sub.add_parser("summary")
    p = sub.add_parser("snapshots"); p.add_argument("--limit", type=int, default=20)
    p = sub.add_parser("events"); p.add_argument("--limit", type=int, default=50); p.add_argument("--severity"); p.add_argument("--event-type")
    p = sub.add_parser("alerts"); p.add_argument("--status", choices=["OPEN", "ACKNOWLEDGED", "RESOLVED", "SUPPRESSED"], default="OPEN"); p.add_argument("--limit", type=int, default=50)
    p = sub.add_parser("ack"); p.add_argument("alert_id", type=int); p.add_argument("--reason")
    p = sub.add_parser("suppress"); p.add_argument("alert_id", type=int); p.add_argument("--reason")
    p = sub.add_parser("asset"); p.add_argument("identifier"); p.add_argument("--limit", type=int, default=20)
    p = sub.add_parser("health"); p.add_argument("--limit", type=int, default=20)
    p = sub.add_parser("approve"); p.add_argument("scan_id")
    sub.add_parser("latest")

    p = sub.add_parser("annotate-asset")
    p.add_argument("asset_key")
    p.add_argument("--owner")
    p.add_argument("--role")
    p.add_argument("--criticality")
    p.add_argument("--notes")

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

    p = sub.add_parser("risk")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--subject")
    p.add_argument("--details", action="store_true")

    p = sub.add_parser("asset-risk")
    p.add_argument("subject_key")

    p = sub.add_parser("report")
    p.add_argument("--latest", action="store_true")
    p.add_argument("--since")
    p.add_argument("--severity")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--risk-limit", type=int, default=10)
    p.add_argument("--output", type=Path)

    sub.add_parser("paths")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command in {None, "menu"}: return run_interactive_menu(args)
        if args.command == "ingest": return command_ingest(args)
        if args.command == "summary": return command_summary(args)
        if args.command == "snapshots": return command_snapshots(args)
        if args.command == "events": return command_events(args)
        if args.command == "alerts": return command_alerts(args)
        if args.command == "ack": return set_alert_status(args, "ACKNOWLEDGED")
        if args.command == "suppress": return set_alert_status(args, "SUPPRESSED")
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


        if args.command == "risk": return command_risk(args)

        if args.command == "asset-risk": return command_asset_risk(args)

        if args.command == "report": return command_report(args)

        if args.command == "paths": return command_paths(args)
        raise DeltaAegisError(f"unknown command: {args.command}")
    except DeltaAegisError as exc:
        print(f"DeltaAegis error: {exc}", file=sys.stderr); return 1


if __name__ == "__main__":
    raise SystemExit(main())
