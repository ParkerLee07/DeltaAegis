#!/usr/bin/env python3
"""Validate the DeltaAegis v0.45 telemetry-quality decision runtime."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "deltaaegis_core" / "telemetry_quality.py"
POLICY = ROOT / "contracts" / "v0.45" / "telemetry-quality-policy.json"


def require(condition, message):
    if not condition:
        raise SystemExit(f"[FAIL] {message}")


PUBLIC_KEYS = {
    "schema_version",
    "policy_version",
    "bundle_id",
    "bundle_sha256",
    "source_contract",
    "automated_state",
    "current_state",
    "reasons",
    "effects",
    "retention_disposition",
    "review",
    "evaluated_at",
}
REASON_KEYS = {"code", "severity", "scope", "detail", "overridable"}
REVIEW_KEYS = {
    "status",
    "reviewer",
    "reviewed_at",
    "override_from",
    "override_to",
    "override_reason",
}
SOURCE_KEYS = {
    "bundle_schema_version",
    "capability_manifest_version",
    "host_classification_version",
    "netsniper_version",
}
EFFECT_KEYS = {
    "apply_absence_mutations",
    "create_alerts",
    "create_high_severity_classification_alerts",
    "quality_center_visibility",
    "resolve_alerts",
    "retain_raw_bundle",
    "update_device_classification",
    "update_positive_observations",
    "update_risk_score",
}


def validate_contract(payload):
    require(isinstance(payload, dict), "decision contract must be an object")
    require(
        set(payload) == PUBLIC_KEYS,
        f"public decision keys mismatch: {sorted(payload)}",
    )
    require(
        payload["schema_version"]
        == "deltaaegis-telemetry-quality-decision-v1",
        "public decision schema version mismatch",
    )
    require(
        payload["policy_version"] == "deltaaegis-v0.45-stage0f",
        "public decision policy version mismatch",
    )
    require(
        bool(re.fullmatch(r"[0-9a-f]{64}", payload["bundle_sha256"])),
        "public bundle SHA-256 must be lowercase hexadecimal",
    )
    require(
        payload["automated_state"]
        in {"ACCEPTED", "DEGRADED", "QUARANTINED", "REJECTED"},
        "unsupported automated state",
    )
    require(
        payload["current_state"]
        in {"ACCEPTED", "DEGRADED", "QUARANTINED", "REJECTED"},
        "unsupported current state",
    )
    require(
        isinstance(payload["reasons"], list) and payload["reasons"],
        "public decision must contain at least one reason",
    )
    for reason in payload["reasons"]:
        require(
            isinstance(reason, dict) and set(reason) == REASON_KEYS,
            f"reason contract mismatch: {reason!r}",
        )
        require(
            reason["scope"]
            in {"bundle", "artifact", "collector", "host", "policy"},
            f"unsupported reason scope: {reason['scope']!r}",
        )
        require(
            reason["severity"]
            in {"info", "warning", "error", "critical"},
            f"unsupported reason severity: {reason['severity']!r}",
        )
    require(
        isinstance(payload["effects"], dict)
        and set(payload["effects"]) == EFFECT_KEYS,
        "effect contract mismatch",
    )
    require(
        isinstance(payload["source_contract"], dict)
        and set(payload["source_contract"]) == SOURCE_KEYS,
        "source-contract keys mismatch",
    )
    require(
        isinstance(payload["review"], dict)
        and set(payload["review"]) == REVIEW_KEYS,
        "review contract mismatch",
    )
    require(
        payload["review"]["status"]
        in {"not_reviewed", "reviewed", "overridden"},
        "review status mismatch",
    )


def evaluate(quality, manifest_path):
    record = quality.evaluate_bundle_record(
        manifest_path,
        policy_path=POLICY,
    )
    contract = quality.evaluate_bundle(
        manifest_path,
        policy_path=POLICY,
    )
    expected = quality.decision_contract_payload(record)
    for key in sorted(PUBLIC_KEYS - {"evaluated_at"}):
        require(
            contract[key] == expected[key],
            f"public evaluator diverges from ledger record for {key}",
        )
    validate_contract(contract)
    return contract, record


def load_module():
    spec = importlib.util.spec_from_file_location(
        "deltaaegis_v045_quality_runtime",
        MODULE,
    )
    if spec is None or spec.loader is None:
        raise SystemExit("[FAIL] could not load telemetry_quality module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def make_v21(root):
    files = {
        "discovery.xml": "<nmaprun></nmaprun>\n",
        "services.xml": "<nmaprun></nmaprun>\n",
        "analysis.json": '{"hosts": []}\n',
        "analysis.enriched.json": '{"hosts": []}\n',
        "hosts.txt": "192.168.1.10\n",
        "classification_quality.json": '{"host_count": 1}\n',
    }
    for name, text in files.items():
        (root / name).write_text(text, encoding="utf-8")

    host = {
        "host_id": "host-1",
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
        "legacy_projection": {
            "decision": "classified",
            "confidence": 80,
        },
        "identity": {
            "observed_keys": [
                {"kind": "mac", "value": "00:11:22:33:44:55", "stable": True}
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
    write_json(root / "host_classifications.json", [host])

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
        "run_id": "run-v21",
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
        "execution": {
            "status": "complete",
            "privilege_context": "privileged",
        },
        "integrity": {
            "bundle_finalized": True,
            "hashes_verified": True,
            "host_inventory_preserved": True,
            "manifest_complete": True,
        },
        "inventory": {
            "discovered_host_count": 1,
            "emitted_host_count": 1,
            "omitted_host_count": 0,
        },
        "collectors": [
            {
                "collector_id": "discovery",
                "requested": True,
                "status": "completed",
            },
            {
                "collector_id": "tcp_services",
                "requested": True,
                "status": "completed",
            },
        ],
        "artifacts": artifacts,
    }
    write_json(root / "capability_manifest.json", capability)

    manifest = {
        "scan_id": "run-v21",
        "schema_version": "netsniper-run-v3",
        "scanner_version": "2.1.0",
        "status": "COMPLETE",
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


def main():
    quality = load_module()
    with tempfile.TemporaryDirectory(prefix="deltaaegis-v045-quality-") as tmp:
        root = Path(tmp) / "accepted"
        root.mkdir()
        make_v21(root)
        accepted, accepted_record = evaluate(
            quality,
            root / "manifest.json",
        )
        require(
            accepted["automated_state"] == "ACCEPTED",
            f"expected ACCEPTED, got {accepted['automated_state']}: "
            f"{accepted_record['reason_codes']}",
        )
        require(
            accepted_record["coverage_capabilities"]["negative_evidence_allowed"],
            "accepted fixture did not prove negative-evidence coverage",
        )

        evidence_root = Path(tmp) / "evidence"
        retained_manifest = quality.retain_bundle(
            root / "manifest.json",
            evidence_root=evidence_root,
            decision=accepted_record,
        )
        require(
            Path(retained_manifest).is_file(),
            "accepted bundle was not retained",
        )
        require(
            quality.bundle_digest(Path(retained_manifest))
            == accepted_record["bundle_digest"],
            "retained bundle digest differs from evaluated evidence",
        )
        (Path(retained_manifest).parent / "analysis.json").write_text(
            '{"tampered_after_retention": true}\n',
            encoding="utf-8",
        )
        try:
            quality.retain_bundle(
                root / "manifest.json",
                evidence_root=evidence_root,
                decision=accepted_record,
            )
        except quality.TelemetryQualityError:
            pass
        else:
            raise SystemExit(
                "[FAIL] mismatched existing retained evidence was trusted"
            )

        legacy_root = Path(tmp) / "legacy"
        legacy_root.mkdir()
        write_json(
            legacy_root / "manifest.json",
            {
                "scan_id": "legacy-v2",
                "schema_version": "netsniper-run-v3",
                "scanner_version": "2.0.0",
                "network_scope": "192.168.2.0/24",
                "target": "192.168.2.0/24",
                "files": {},
            },
        )
        legacy, legacy_record = evaluate(
            quality,
            legacy_root / "manifest.json",
        )
        require(
            legacy["automated_state"] == "DEGRADED",
            "valid v2.0 compatibility bundle must default to DEGRADED",
        )

        quarantine_root = Path(tmp) / "quarantine"
        quarantine_root.mkdir()
        make_v21(quarantine_root)
        capability = json.loads(
            (quarantine_root / "capability_manifest.json").read_text()
        )
        capability["integrity"]["host_inventory_preserved"] = False
        write_json(
            quarantine_root / "capability_manifest.json",
            capability,
        )
        quarantined, quarantined_record = evaluate(
            quality,
            quarantine_root / "manifest.json",
        )
        require(
            quarantined["automated_state"] == "QUARANTINED",
            "host inventory loss must quarantine safely retained telemetry",
        )

        mismatch_root = Path(tmp) / "mismatch"
        mismatch_root.mkdir()
        make_v21(mismatch_root)
        (mismatch_root / "analysis.json").write_text(
            '{"tampered": true}\n',
            encoding="utf-8",
        )
        rejected, rejected_record = evaluate(
            quality,
            mismatch_root / "manifest.json",
        )
        require(
            rejected["automated_state"] == "REJECTED",
            "artifact hash mismatch must reject",
        )
        require(
            "hash_mismatch" in rejected_record["reason_codes"],
            "hash mismatch reason was not preserved",
        )

        escape_root = Path(tmp) / "escape"
        escape_root.mkdir()
        make_v21(escape_root)
        manifest = json.loads(
            (escape_root / "manifest.json").read_text()
        )
        manifest["files"]["analysis_json"] = "../outside.json"
        write_json(escape_root / "manifest.json", manifest)
        escaped, escaped_record = evaluate(
            quality,
            escape_root / "manifest.json",
        )
        require(
            escaped["automated_state"] == "REJECTED",
            "path escape must reject",
        )

        symlink_root = Path(tmp) / "symlink"
        symlink_root.mkdir()
        make_v21(symlink_root)
        outside = Path(tmp) / "outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        (symlink_root / "unsafe-link").symlink_to(outside)
        symlinked, symlinked_record = evaluate(
            quality,
            symlink_root / "manifest.json",
        )
        require(
            symlinked["automated_state"] == "REJECTED",
            "bundle symbolic link must fail closed",
        )
        require(
            "bundle_unreadable" in symlinked_record["reason_codes"],
            "symbolic-link rejection reason is missing",
        )

        unknown_root = Path(tmp) / "unknown"
        unknown_root.mkdir()
        write_json(
            unknown_root / "manifest.json",
            {
                "scan_id": "future",
                "schema_version": "netsniper-run-v99",
                "network_scope": "192.168.3.0/24",
                "target": "192.168.3.0/24",
                "files": {},
            },
        )
        unknown, unknown_record = evaluate(
            quality,
            unknown_root / "manifest.json",
        )
        require(
            unknown["automated_state"] == "REJECTED",
            "unknown future schema must fail closed",
        )

        missing_root = Path(tmp) / "missing"
        missing_root.mkdir()
        missing, missing_record = evaluate(
            quality,
            missing_root / "manifest.json",
        )
        require(
            missing["automated_state"] == "REJECTED",
            "missing manifest must reject",
        )
        require(
            "manifest_missing" in missing_record["reason_codes"],
            "missing manifest reason is absent",
        )
        require(
            bool(re.fullmatch(r"[0-9a-f]{64}", missing["bundle_sha256"])),
            "rejection receipt does not expose a schema-valid digest",
        )

        invalid_root = Path(tmp) / "invalid"
        invalid_root.mkdir()
        (invalid_root / "manifest.json").write_text(
            "{not-json}\n",
            encoding="utf-8",
        )
        invalid, invalid_record = evaluate(
            quality,
            invalid_root / "manifest.json",
        )
        require(
            invalid["automated_state"] == "REJECTED",
            "invalid manifest must reject",
        )
        require(
            bool(re.fullmatch(r"[0-9a-f]{64}", invalid["bundle_sha256"])),
            "invalid bundle receipt does not expose a schema-valid digest",
        )

    print("[PASS] v0.45 deterministic telemetry-quality runtime")


if __name__ == "__main__":
    main()
