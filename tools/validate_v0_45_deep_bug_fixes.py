#!/usr/bin/env python3
"""Validate the approved DeltaAegis v0.45 deep bug-fix scope."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "contracts" / "v0.45" / "telemetry-quality-policy.json"


def require(condition, message):
    if not condition:
        raise SystemExit(f"[FAIL] {message}")


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_v21(root: Path, *, run_id: str = "deep-fix-run", host_count: int = 1):
    root.mkdir(parents=True, exist_ok=True)
    files = {
        "discovery.xml": "<nmaprun></nmaprun>\n",
        "services.xml": "<nmaprun></nmaprun>\n",
        "analysis.json": json.dumps({"hosts": []}) + "\n",
        "analysis.enriched.json": json.dumps({"hosts": []}) + "\n",
        "hosts.txt": "" if host_count == 0 else "192.168.1.10\n",
        "classification_quality.json": json.dumps({"host_count": host_count}) + "\n",
    }
    for name, text in files.items():
        (root / name).write_text(text, encoding="utf-8")

    hosts = []
    for index in range(host_count):
        hosts.append(
            {
                "host_id": f"host-{index + 1}",
                "schema_version": "netsniper-host-classification-v2",
                "classifier_version": "netsniper-classifier-v2",
                "taxonomy_version": "netsniper-device-taxonomy-v2",
                "evidence_profile_version": "netsniper-evidence-profiles-v2",
                "device_family": {
                    "decision": "classified",
                    "confidence": 80,
                    "evidence_ids": ["e1"],
                    "contradictions": [],
                },
                "legacy_projection": {"decision": "classified", "confidence": 80},
                "identity": {
                    "observed_keys": [
                        {
                            "kind": "mac",
                            "value": f"00:11:22:33:44:{55 + index:02x}",
                            "stable": True,
                        }
                    ]
                },
                "observation_quality": {
                    "inventory_complete": True,
                    "negative_evidence_allowed": True,
                    "scan_completeness": "complete",
                    "failed_collectors": [],
                    "unavailable_collectors": [],
                },
            }
        )
    write_json(root / "host_classifications.json", hosts)

    artifacts = []
    for name in sorted([*files, "host_classifications.json"]):
        path = root / name
        artifacts.append(
            {
                "artifact_id": name.replace(".", "_"),
                "kind": "test",
                "path": name,
                "sha256": digest(path),
                "size_bytes": path.stat().st_size,
                "required": True,
                "status": "present",
            }
        )

    capability = {
        "schema_version": "netsniper-capability-manifest-v1",
        "run_id": run_id,
        "target": {
            "requested_scope": "192.168.1.0/24",
            "normalized_scope": "192.168.1.0/24",
            "private_scope_enforced": True,
        },
        "sensor": {
            "netsniper_version": "2.1.0",
            "classifier_version": "netsniper-classifier-v2",
            "host_classification_schema_version": "netsniper-host-classification-v2",
        },
        "execution": {"status": "complete", "privilege_context": "privileged"},
        "integrity": {
            "bundle_finalized": True,
            "hashes_verified": True,
            "host_inventory_preserved": True,
            "manifest_complete": True,
        },
        "inventory": {
            "discovered_host_count": host_count,
            "emitted_host_count": host_count,
            "omitted_host_count": 0,
        },
        "collectors": [
            {"collector_id": "discovery", "requested": True, "status": "completed"},
            {"collector_id": "tcp_services", "requested": True, "status": "completed"},
        ],
        "artifacts": artifacts,
    }
    write_json(root / "capability_manifest.json", capability)

    manifest = {
        "scan_id": run_id,
        "schema_version": "netsniper-run-v3",
        "scanner_version": "2.1.0",
        "status": "COMPLETE",
        "created_at": "2026-07-21T12:00:00Z",
        "network_scope": "192.168.1.0/24",
        "target": "192.168.1.0/24",
        "contracts": {
            "capability_manifest_version": "netsniper-capability-manifest-v1",
            "host_classification_version": "netsniper-host-classification-v2",
            "classifier_version": "netsniper-classifier-v2",
        },
        "files": {
            "capability_manifest_json": "capability_manifest.json",
            "host_classifications_json": "host_classifications.json",
            "analysis_json": "analysis.json",
            "analysis_enriched_json": "analysis.enriched.json",
            "discovery_xml": "discovery.xml",
            "services_xml": "services.xml",
            "hosts": "hosts.txt",
            "classification_quality_json": "classification_quality.json",
        },
    }
    write_json(root / "manifest.json", manifest)
    return manifest, capability


def refresh_capability(root: Path, capability: dict) -> None:
    write_json(root / "capability_manifest.json", capability)


def evaluate(quality, root: Path):
    return quality.evaluate_bundle_record(root / "manifest.json", policy_path=POLICY)


def test_runtime_contracts(quality, tmp: Path):
    accepted_root = tmp / "accepted"
    make_v21(accepted_root)
    accepted = evaluate(quality, accepted_root)
    require(accepted["current_state"] == "ACCEPTED", "baseline v2.1 fixture not accepted")

    zero_root = tmp / "zero"
    make_v21(zero_root, run_id="zero-host-run", host_count=0)
    zero = evaluate(quality, zero_root)
    require(zero["current_state"] == "ACCEPTED", "complete zero-host scan was not accepted")
    require(zero["coverage_capabilities"]["negative_evidence_allowed"], "zero-host scan lacks negative-evidence authority")

    traversal_root = tmp / "traversal"
    make_v21(traversal_root, run_id="/tmp/escape-attempt")
    traversal = evaluate(quality, traversal_root)
    require(traversal["current_state"] == "REJECTED", "pathful run ID was not rejected")
    require("required_artifact_invalid" in traversal["reason_codes"], "pathful run ID reason missing")
    evidence_root = tmp / "evidence"
    receipt = quality.retain_bundle_receipt(
        traversal_root / "manifest.json", evidence_root=evidence_root, decision=traversal
    )
    retained = Path(str(receipt.get("manifest_path") or "")) if receipt.get("manifest_path") else None
    require(retained is None or retained.resolve().is_relative_to(evidence_root.resolve()), "retention escaped evidence root")

    variants = []
    # Remove all integrity metadata.
    root = tmp / "missing-hashes"
    _, capability = make_v21(root, run_id="missing-hashes")
    for artifact in capability["artifacts"]:
        artifact.pop("sha256", None)
        artifact.pop("size_bytes", None)
    refresh_capability(root, capability)
    variants.append((root, {"REJECTED"}, "missing artifact integrity metadata"))

    root = tmp / "empty-collectors"
    _, capability = make_v21(root, run_id="empty-collectors")
    capability["collectors"] = []
    refresh_capability(root, capability)
    variants.append((root, {"DEGRADED", "QUARANTINED", "REJECTED"}, "missing required collectors"))

    root = tmp / "missing-execution"
    _, capability = make_v21(root, run_id="missing-execution")
    capability.pop("execution", None)
    refresh_capability(root, capability)
    variants.append((root, {"QUARANTINED", "REJECTED"}, "missing execution status"))

    root = tmp / "count-mismatch"
    _, capability = make_v21(root, run_id="count-mismatch")
    capability["inventory"]["emitted_host_count"] = 0
    refresh_capability(root, capability)
    variants.append((root, {"QUARANTINED", "REJECTED"}, "inventory mismatch"))

    root = tmp / "version-mismatch"
    _, capability = make_v21(root, run_id="version-mismatch")
    capability["sensor"]["netsniper_version"] = "9.9.9"
    refresh_capability(root, capability)
    variants.append((root, {"QUARANTINED", "REJECTED"}, "sensor version disagreement"))

    root = tmp / "duplicate-host-id"
    _, capability = make_v21(root, run_id="duplicate-host-id", host_count=2)
    hosts = json.loads((root / "host_classifications.json").read_text(encoding="utf-8"))
    hosts[1]["host_id"] = hosts[0]["host_id"]
    write_json(root / "host_classifications.json", hosts)
    for artifact in capability["artifacts"]:
        if artifact["path"] == "host_classifications.json":
            artifact["sha256"] = digest(root / "host_classifications.json")
            artifact["size_bytes"] = (root / "host_classifications.json").stat().st_size
    refresh_capability(root, capability)
    variants.append((root, {"QUARANTINED", "REJECTED"}, "duplicate host IDs"))

    for root, allowed, label in variants:
        record = evaluate(quality, root)
        require(record["current_state"] in allowed, f"{label} failed open as {record['current_state']}")


def test_transaction_boundaries(quality, current_state):
    for module, label in ((quality, "telemetry quality"), (current_state, "current state")):
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.execute("CREATE TABLE snapshots (scan_id TEXT PRIMARY KEY)")
        connection.execute("CREATE TABLE marker (value TEXT)")
        connection.commit()
        connection.execute("INSERT INTO marker VALUES ('pending')")
        require(connection.in_transaction, f"{label} test transaction did not start")
        module.ensure_schema(connection)
        require(connection.in_transaction, f"{label} schema helper committed caller transaction")
        connection.rollback()
        count = connection.execute("SELECT COUNT(*) FROM marker").fetchone()[0]
        require(count == 0, f"{label} marker survived rollback")
        connection.close()


def test_risk_scope_and_ceiling(current_state):
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    current_state.ensure_schema(connection)
    for scope, score in (("192.168.1.0/24", 50), ("192.168.2.0/24", 50)):
        connection.execute(
            """
            INSERT INTO telemetry_current_assets (
                network_scope, asset_key, ip_address, mac_address, hostname,
                vendor, device_type, classification_primary_type,
                classification_calibrated_decision, classification_decision,
                classification_confidence, identity_confidence,
                source_scan_id, source_decision_id, source_quality_state,
                accepted_evidence_seen, observed_at
            ) VALUES (?, 'asset:shared', '192.168.1.10', '00:11:22:33:44:55',
                      'host', 'vendor', 'device', 'server', 'classified',
                      'classified', 80, 90, 'scan', 'decision', 'DEGRADED', 0,
                      '2026-07-21T12:00:00Z')
            """,
            (scope,),
        )
        connection.execute(
            """
            INSERT INTO telemetry_current_findings (
                network_scope, asset_key, finding_id, port, name, service,
                score, evidence, source_scan_id, source_decision_id,
                source_quality_state, accepted_evidence_seen, observed_at
            ) VALUES (?, 'asset:shared', 'finding', 443, 'finding', 'https', ?,
                      'evidence', 'scan', 'decision', 'DEGRADED', 0,
                      '2026-07-21T12:00:00Z')
            """,
            (scope, score),
        )
    rows = [
        {
            "subject_key": "asset:shared",
            "asset_key": "asset:shared",
            "network_scope": "192.168.1.0/24",
            "score": 10,
            "level": "LOW",
            "reasons": [],
        },
        {
            "subject_key": "asset:shared",
            "asset_key": "asset:shared",
            "network_scope": "192.168.2.0/24",
            "score": 95,
            "level": "CRITICAL",
            "reasons": [],
        },
    ]
    merged = current_state.merge_risk_rows(
        connection, rows, scope=None, limit=20,
        risk_level=lambda score: "CRITICAL" if score >= 85 else "HIGH" if score >= 65 else "MEDIUM" if score >= 35 else "LOW",
    )
    require(len(merged) == 2, "same asset key collapsed across scopes")
    by_scope = {row["network_scope"]: row for row in merged}
    require(by_scope["192.168.1.0/24"]["score"] == 30, "existing low row did not merge projected risk")
    require(by_scope["192.168.1.0/24"]["score"] <= 64, "degraded-only risk exceeded ceiling")
    require(by_scope["192.168.2.0/24"]["score"] == 95, "independent existing risk was incorrectly lowered")
    connection.close()


def test_historical_ordering(current_state):
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE snapshots (
            scan_id TEXT PRIMARY KEY,
            target TEXT,
            network_scope TEXT,
            quality_status TEXT,
            quality_decision_id TEXT,
            created_at TEXT,
            imported_at TEXT
        );
        CREATE TABLE telemetry_quality_decisions (
            decision_id TEXT PRIMARY KEY,
            current_state TEXT,
            import_status TEXT
        );
        """
    )
    connection.execute(
        "INSERT INTO snapshots VALUES ('newer','192.168.1.0/24','192.168.1.0/24','ACCEPTED',NULL,'2026-07-21T12:00:00Z','2026-07-21T12:01:00Z')"
    )
    require(
        current_state.snapshot_is_historical(
            connection, scope="192.168.1.0/24", created_at="2026-07-21T11:00:00Z", scan_id="older"
        ),
        "older snapshot was not classified as historical",
    )
    require(
        not current_state.snapshot_is_historical(
            connection, scope="192.168.1.0/24", created_at="2026-07-21T13:00:00Z", scan_id="newest"
        ),
        "newer snapshot was incorrectly classified as historical",
    )
    connection.close()


def test_static_boundaries():
    root_source = (ROOT / "deltaaegis.py").read_text(encoding="utf-8")
    quality_source = (ROOT / "deltaaegis_core" / "telemetry_quality.py").read_text(encoding="utf-8")
    current_source = (ROOT / "deltaaegis_core" / "current_state.py").read_text(encoding="utf-8")
    web_source = (ROOT / "deltaaegis_core" / "web.py").read_text(encoding="utf-8")

    require("def canonical_run_id(" in quality_source, "run-ID validation helper missing")
    require("def _confined_destination(" in quality_source, "retention confinement helper missing")
    require("def retain_bundle_receipt(" in quality_source, "retention receipt helper missing")
    require("def prepare_retained_bundle_transition(" in quality_source, "two-phase evidence transition missing")
    require("def abort_retained_bundle_transition(" in quality_source, "evidence rollback helper missing")
    require("class TelemetryQualityError(ValueError):" in quality_source, "quality errors are not bounded value errors")
    require("executescript(" not in quality_source, "telemetry schema still commits implicitly")
    require("executescript(" not in current_source, "current-state schema still commits implicitly")
    require("snapshot_is_historical(" in root_source, "historical-ingest guard missing")
    require("historical=true, current_state_unchanged=true" in root_source, "historical import receipt missing")
    require("retention_receipt" in root_source and "cleanup_retained_bundle" in root_source, "failed-ingest evidence cleanup missing")
    require("prepare_retained_bundle_transition" in root_source and "abort_retained_bundle_transition" in root_source, "atomic override transition missing")
    override_start = root_source.index("def dashboard_telemetry_quality_override_payload")
    override_end = root_source.index("def dashboard_current_state_payload", override_start)
    override_source = root_source[override_start:override_end]
    require("store_netsniper_intelligence_summary" in override_source, "override intelligence backfill missing")
    main_esc_start = root_source.index("function esc(value)")
    main_esc = root_source[main_esc_start:main_esc_start + 700]
    require("&quot;" in main_esc, "main dashboard escaper does not escape double quotes")
    require("&#039;" in main_esc or "&#39;" in main_esc, "main dashboard escaper does not escape single quotes")
    require("except (DeltaAegisError, ValueError) as exc:" in web_source, "quality GET error boundary missing")
    require("(\n            str(item.get(\"network_scope\")" in current_source, "risk rows are not keyed by scope")


def main():
    quality = load_module("deltaaegis_v045_deep_quality", ROOT / "deltaaegis_core" / "telemetry_quality.py")
    current_state = load_module("deltaaegis_v045_deep_current", ROOT / "deltaaegis_core" / "current_state.py")
    test_static_boundaries()
    with tempfile.TemporaryDirectory(prefix="deltaaegis-v045-deep-fixes-") as tmp:
        test_runtime_contracts(quality, Path(tmp))
    test_transaction_boundaries(quality, current_state)
    test_risk_scope_and_ceiling(current_state)
    test_historical_ordering(current_state)
    print("[PASS] v0.45 deep bug fixes: confinement, atomicity, capability, zero-host, XSS, risk, and ordering")


if __name__ == "__main__":
    main()
