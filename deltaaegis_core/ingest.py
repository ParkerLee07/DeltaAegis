#!/usr/bin/env python3
"""NetSniper bundle trust and normalization boundary for DeltaAegis v0.44."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from deltaaegis_core.auth import DeltaAegisError


NETSNIPER_SUPPORTED_SCHEMAS = {"netsniper-run-v1", "netsniper-run-v2", "netsniper-run-v3"}
NETSNIPER_BUNDLE_QUALITY_SCHEMA_VERSION = "netsniper-bundle-quality-v1"
MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


@dataclass(frozen=True)
class IngestContext:
    """Root-owned model constructors retained across the extraction seam."""

    service_type: type[Any]
    identity_evidence_type: type[Any]
    asset_observation_type: type[Any]
    snapshot_type: type[Any]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DeltaAegisError(f"could not read JSON {path}: {exc}") from exc


def resolve_bundle_member(
    bundle_dir: Path,
    filename: str,
    *,
    key: str,
) -> Path:
    """Resolve a manifest member without allowing it to escape its bundle."""
    if not isinstance(filename, str) or not filename.strip():
        raise DeltaAegisError(f"manifest files.{key} must be a non-empty relative path")

    relative = Path(filename.strip())
    if relative.is_absolute():
        raise DeltaAegisError(f"manifest files.{key} must be relative to the bundle")

    try:
        root = bundle_dir.resolve(strict=True)
        candidate = (root / relative).resolve(strict=False)
        candidate.relative_to(root)
    except (OSError, ValueError) as exc:
        raise DeltaAegisError(
            f"manifest files.{key} escapes the immutable bundle boundary: {filename!r}"
        ) from exc

    return candidate


def require_file(bundle_dir: Path, manifest: dict[str, Any], key: str) -> Path:
    filename = manifest.get("files", {}).get(key)
    if not isinstance(filename, str) or not filename:
        raise DeltaAegisError(f"manifest missing files.{key}")
    path = resolve_bundle_member(bundle_dir, filename, key=key)
    if not path.is_file():
        raise DeltaAegisError(f"required bundle file is missing: {path}")
    return path


def optional_file(bundle_dir: Path, manifest: dict[str, Any], key: str) -> Path | None:
    filename = manifest.get("files", {}).get(key)
    if not isinstance(filename, str) or not filename:
        return None
    path = resolve_bundle_member(bundle_dir, filename, key=key)
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


def parse_discovery_xml(path: Path, target_network: ipaddress._BaseNetwork, *, context: IngestContext) -> dict[str, IdentityEvidence]:
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
        result[ipv4] = context.identity_evidence_type(mac, vendor, hostname, "DISCOVERY_XML" if mac else "IP_ONLY")
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


def parse_service_xml(path: Path, analysis: dict[str, dict[str, Any]], target_network: ipaddress._BaseNetwork, discovery: dict[str, IdentityEvidence], neighbors: dict[str, str], *, context: IngestContext) -> tuple[str, int, int, int, dict[str, AssetObservation]]:
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
        evidence = discovery.get(ipv4, context.identity_evidence_type())
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
            services.append(context.service_type(
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
            context.asset_observation_type(
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

        evidence = discovery.get(ipv4, context.identity_evidence_type())

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
            context.asset_observation_type(
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


def _first_nonempty_text(*values: Any, default: str = "") -> str:
    for value in values:
        if value is None or isinstance(value, dict):
            continue
        clean = str(value).strip()
        if clean:
            return clean
    return default


def _optional_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    lowered = str(value).strip().lower()
    if lowered in {"true", "yes", "1"}:
        return True
    if lowered in {"false", "no", "0"}:
        return False
    return None


def load_netsniper_bundle_quality(bundle_dir: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    files = manifest.get("files", {})
    if not isinstance(files, dict):
        files = {}

    for key in ("bundle_quality_json", "bundle_quality"):
        filename = files.get(key)
        if isinstance(filename, str) and filename.strip():
            candidate = resolve_bundle_member(bundle_dir, filename, key=key)
            if candidate.is_file():
                loaded = load_json(candidate)
                return loaded if isinstance(loaded, dict) else {}

    candidate = resolve_bundle_member(
        bundle_dir,
        "bundle_quality.json",
        key="bundle_quality_json",
    )
    if candidate.is_file():
        loaded = load_json(candidate)
        return loaded if isinstance(loaded, dict) else {}

    embedded = manifest.get("quality")
    return embedded if isinstance(embedded, dict) else {}


def netsniper_profile_contract(manifest: dict[str, Any]) -> dict[str, Any]:
    for key in ("profile_contract", "profile"):
        value = manifest.get(key)
        if isinstance(value, dict):
            return value
    return {}


def load_snapshot(manifest_path: Path, *, context: IngestContext) -> Snapshot:
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict):
        raise DeltaAegisError(f"manifest must contain an object: {manifest_path}")

    schema = str(manifest.get("schema_version", ""))
    if schema not in NETSNIPER_SUPPORTED_SCHEMAS:
        raise DeltaAegisError(f"unsupported manifest schema: {schema!r}")

    if manifest.get("status") != "COMPLETE":
        raise DeltaAegisError(f"bundle is not finalized: {manifest_path}")

    bundle_dir = manifest_path.parent
    bundle_quality = load_netsniper_bundle_quality(bundle_dir, manifest)
    bundle_deltaaegis_ready = _optional_bool(bundle_quality.get("deltaaegis_ready"))

    if schema == "netsniper-run-v3":
        quality_schema = str(bundle_quality.get("schema_version") or "").strip()
        if quality_schema != NETSNIPER_BUNDLE_QUALITY_SCHEMA_VERSION:
            raise DeltaAegisError(
                "netsniper-run-v3 requires bundle_quality.json schema "
                f"{NETSNIPER_BUNDLE_QUALITY_SCHEMA_VERSION!r}; rejecting missing or invalid quality evidence."
            )
        if bundle_deltaaegis_ready is not True:
            raise DeltaAegisError(
                "netsniper-run-v3 requires deltaaegis_ready=true; "
                "rejecting missing, invalid, or false readiness evidence."
            )
    elif bundle_deltaaegis_ready is False:
        raise DeltaAegisError(
            "NetSniper bundle_quality.json marked deltaaegis_ready=false; "
            "rejecting bundle before ingest."
        )

    services_xml = require_file(bundle_dir, manifest, "services_xml")
    discovery_xml = require_file(bundle_dir, manifest, "discovery_xml")
    analysis_json = require_file(bundle_dir, manifest, "analysis_json")

    target = _first_nonempty_text(manifest.get("target"), manifest.get("network_scope"))
    if not target:
        raise DeltaAegisError("manifest missing target or network_scope")

    target_network = parse_target_network(target)
    analysis = analysis_by_ip(analysis_json)
    discovery = parse_discovery_xml(discovery_xml, target_network, context=context)
    neighbors = parse_neighbors(optional_file(bundle_dir, manifest, "neighbors"), target_network)
    exit_status, hosts_up, hosts_down, hosts_total, assets = parse_service_xml(
        services_xml,
        analysis,
        target_network,
        discovery,
        neighbors,
        context=context,
    )

    counts = manifest.get("counts", {}) if isinstance(manifest.get("counts"), dict) else {}
    discovered_hosts = safe_int(counts.get("discovered_hosts"))
    inventory_hosts = max(len(assets), discovered_hosts or 0)
    if inventory_hosts > hosts_up:
        hosts_up = inventory_hosts
    if hosts_total < hosts_up:
        hosts_total = hosts_up

    profile = netsniper_profile_contract(manifest)

    effective_profile = _first_nonempty_text(
        manifest.get("effective_profile"),
        manifest.get("scan_profile_effective"),
        manifest.get("effective_scan_profile"),
        manifest.get("scan_profile"),
        manifest.get("requested_profile"),
        manifest.get("scan_profile_requested"),
        default="UNKNOWN",
    )
    requested_profile = _first_nonempty_text(
        manifest.get("requested_profile"),
        manifest.get("scan_profile_requested"),
        manifest.get("requested_scan_profile"),
        effective_profile,
        default=effective_profile,
    )

    monitored_ports = tuple(
        sorted(
            int(port)
            for port in profile.get("monitored_ports", [])
            if isinstance(port, int) or str(port).isdigit()
        )
    )
    protocols = tuple(
        sorted(
            str(item).lower()
            for item in profile.get("protocols", [])
            if isinstance(item, str)
        )
    )
    fingerprint = str(
        profile.get("fingerprint")
        or manifest.get("profile_fingerprint")
        or legacy_profile_fingerprint(effective_profile, target)
    )

    telemetry = manifest.get("telemetry", {}) if isinstance(manifest.get("telemetry"), dict) else {}
    timestamps = manifest.get("timestamps", {}) if isinstance(manifest.get("timestamps"), dict) else {}

    profile_contract_name = _first_nonempty_text(
        manifest.get("profile_contract_schema"),
        manifest.get("scan_profile_contract_schema"),
        manifest.get("profile_contract"),
        profile.get("schema_version"),
        profile.get("contract"),
        default="",
    ) or None

    return context.snapshot_type(
        scan_id=str(manifest["scan_id"]),
        manifest_path=str(manifest_path),
        manifest_schema_version=schema,
        target=target,
        scanner_version=str(manifest.get("scanner_version", "unknown")),
        scan_profile=effective_profile,
        profile_fingerprint=fingerprint,
        monitored_ports=monitored_ports,
        protocols=protocols,
        created_at=str(
            manifest.get("created_at")
            or manifest.get("timestamp")
            or manifest.get("started_at")
            or timestamps.get("archived_at")
            or utc_now()
        ),
        scan_started_at=telemetry.get("started_at") or manifest.get("started_at"),
        scan_completed_at=telemetry.get("completed_at") or manifest.get("completed_at"),
        neighbors_captured_at=telemetry.get("neighbors_captured_at"),
        discovery_interface=telemetry.get("discovery_interface"),
        nmap_version=telemetry.get("nmap_version"),
        bundle_status=str(manifest.get("status", "UNKNOWN")),
        xml_exit_status=exit_status,
        hosts_up=hosts_up,
        hosts_down=hosts_down,
        hosts_total=hosts_total,
        assets=assets,
        requested_profile=requested_profile,
        effective_profile=effective_profile,
        profile_contract=profile_contract_name,
        profile_runtime_budget_seconds=safe_int(
            manifest.get("profile_runtime_budget_seconds")
            or profile.get("runtime_budget_seconds")
        ),
        profile_host_timeout_seconds=safe_int(
            manifest.get("profile_host_timeout_seconds")
            or profile.get("host_timeout_seconds")
        ),
        profile_duration_seconds=safe_int(
            manifest.get("profile_duration_seconds")
            or manifest.get("duration_seconds")
        ),
        profile_budget_exceeded=_optional_bool(manifest.get("profile_budget_exceeded")),
        bundle_quality_schema_version=(
            str(bundle_quality.get("schema_version"))
            if bundle_quality.get("schema_version") is not None
            else None
        ),
        bundle_deltaaegis_ready=bundle_deltaaegis_ready,
        bundle_quality_json=json.dumps(bundle_quality, sort_keys=True),
    )


def manifest_file_path(manifest_path: Path, manifest: dict[str, Any], key: str) -> Path | None:
    files = manifest.get("files", {})
    if not isinstance(files, dict):
        return None

    value = files.get(key)
    if not value:
        return None

    return resolve_bundle_member(
        manifest_path.parent,
        str(value),
        key=key,
    )


def load_json_file(path: Path | None, default: Any = None) -> Any:
    if path is None or not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default
