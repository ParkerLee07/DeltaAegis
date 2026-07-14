#!/usr/bin/env python3
"""Validate the behavior-preserving v0.44 NetSniper ingest extraction."""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import inspect
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHARACTERIZATION_PATH = ROOT / "docs" / "v0.44-stage4-ingest-characterization.json"
EXPECTED_SOURCE_TREE = "b80804b43fbd108f45c243e593742b4e835efa1f"

sys.path.insert(0, str(ROOT))

import deltaaegis as facade  # noqa: E402
from deltaaegis_core import ingest  # noqa: E402


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_error(action, fragment: str) -> None:
    try:
        action()
    except facade.DeltaAegisError as exc:
        check(fragment.lower() in str(exc).lower(), f"unexpected error: {exc}")
    else:
        raise AssertionError(f"expected DeltaAegisError containing {fragment!r}")


def load_characterization() -> dict:
    payload = json.loads(CHARACTERIZATION_PATH.read_text(encoding="utf-8"))
    check(
        payload.get("format") == "deltaaegis-v0.44-stage4-ingest-characterization-v1",
        "unexpected Stage 4 characterization format",
    )
    check(
        payload.get("source_checkpoint_tree") == EXPECTED_SOURCE_TREE,
        "Stage 4 is not anchored to the committed Stage 3 tree",
    )
    check(payload.get("schema_change") is False, "Stage 4 must not claim a schema change")
    return payload


def top_level_functions(path: Path) -> dict[str, ast.FunctionDef]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }


def comparable_parameters(function) -> list[tuple[str, inspect._ParameterKind, str]]:
    result = []
    for parameter in inspect.signature(function).parameters.values():
        if parameter.name == "context":
            continue
        default = "<empty>" if parameter.default is inspect.Parameter.empty else repr(parameter.default)
        result.append((parameter.name, parameter.kind, default))
    return result


def validate_ownership_and_facade(characterization: dict) -> None:
    root_path = ROOT / "deltaaegis.py"
    ingest_path = ROOT / "deltaaegis_core" / "ingest.py"
    root_source = root_path.read_text(encoding="utf-8")
    ingest_source = ingest_path.read_text(encoding="utf-8")
    root_functions = top_level_functions(root_path)
    ingest_functions = top_level_functions(ingest_path)

    check("from deltaaegis_core import ingest as _ingest" in root_source, "ingest import missing")
    check("ingest" in __import__("deltaaegis_core").__all__, "ingest package export missing")
    check("class IngestContext" in ingest_source, "model compatibility context missing")

    for name in characterization["facade_functions"]:
        check(name in root_functions, f"root facade function missing: {name}")
        check(name in ingest_functions, f"ingest implementation missing: {name}")
        segment = ast.get_source_segment(root_source, root_functions[name]) or ""
        check("_ingest." in segment, f"root function is not a thin ingest facade: {name}")
        check("ET.parse" not in segment, f"XML parsing leaked into root facade: {name}")
        check("read_text" not in segment, f"bundle file reading leaked into root facade: {name}")
        check(
            comparable_parameters(getattr(facade, name))
            == comparable_parameters(getattr(ingest, name)),
            f"compatibility parameters changed: {name}",
        )

    context = facade._INGEST_CONTEXT
    check(context.service_type is facade.Service, "Service model identity changed")
    check(context.identity_evidence_type is facade.IdentityEvidence, "identity model changed")
    check(context.asset_observation_type is facade.AssetObservation, "asset model changed")
    check(context.snapshot_type is facade.Snapshot, "snapshot model identity changed")
    check(
        facade.NETSNIPER_SUPPORTED_SCHEMAS == ingest.NETSNIPER_SUPPORTED_SCHEMAS,
        "supported manifest schemas split",
    )
    check(
        facade.NETSNIPER_BUNDLE_QUALITY_SCHEMA_VERSION
        == ingest.NETSNIPER_BUNDLE_QUALITY_SCHEMA_VERSION,
        "bundle quality schema split",
    )


def snapshot_digest(snapshot: facade.Snapshot, relative_manifest: str) -> str:
    payload = dataclasses.asdict(snapshot)
    payload["manifest_path"] = relative_manifest
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_fixtures_and_receipts(characterization: dict) -> None:
    snapshots = []
    for relative, expected in characterization["fixtures"].items():
        snapshot = facade.load_snapshot(ROOT / relative)
        check(isinstance(snapshot, facade.Snapshot), f"snapshot model changed for {relative}")
        check(
            snapshot_digest(snapshot, relative) == expected["snapshot_sha256"],
            f"normalized snapshot changed for {relative}",
        )
        snapshots.append((relative, expected))

    with tempfile.TemporaryDirectory(prefix="deltaaegis-v044-stage4-receipt-") as temporary:
        root = Path(temporary)
        connection = facade.connect(root / "stage4.db")
        try:
            for relative, expected in snapshots:
                receipt = facade.ingest_manifest(
                    connection,
                    ROOT / relative,
                    root / "events.jsonl",
                )
                check(receipt == expected["receipt"], f"ingest receipt changed for {relative}")
        finally:
            connection.close()


def write_manifest(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")


def validate_trust_boundaries() -> None:
    with tempfile.TemporaryDirectory(prefix="deltaaegis-v044-stage4-trust-") as temporary:
        root = Path(temporary)
        bundle = root / "bundle"
        bundle.mkdir()
        outside = root / "outside.json"
        outside.write_text("{}\n", encoding="utf-8")

        expect_error(
            lambda: facade.resolve_bundle_member(bundle, "../outside.json", key="analysis_json"),
            "escapes",
        )
        expect_error(
            lambda: facade.resolve_bundle_member(bundle, str(outside.resolve()), key="analysis_json"),
            "relative",
        )
        symlink = bundle / "outside-link.json"
        symlink.symlink_to(outside)
        expect_error(
            lambda: facade.resolve_bundle_member(bundle, symlink.name, key="analysis_json"),
            "escapes",
        )

        manifest_path = bundle / "manifest.json"
        write_manifest(
            manifest_path,
            {"schema_version": "unsupported", "status": "COMPLETE"},
        )
        expect_error(lambda: facade.load_snapshot(manifest_path), "unsupported manifest schema")

        write_manifest(
            manifest_path,
            {"schema_version": "netsniper-run-v2", "status": "RUNNING"},
        )
        expect_error(lambda: facade.load_snapshot(manifest_path), "not finalized")

        write_manifest(
            manifest_path,
            {
                "schema_version": "netsniper-run-v3",
                "status": "COMPLETE",
                "quality": {"deltaaegis_ready": True},
            },
        )
        expect_error(lambda: facade.load_snapshot(manifest_path), "requires bundle_quality")

        write_manifest(
            manifest_path,
            {
                "schema_version": "netsniper-run-v2",
                "status": "COMPLETE",
                "quality": {"deltaaegis_ready": False},
            },
        )
        expect_error(lambda: facade.load_snapshot(manifest_path), "deltaaegis_ready=false")


def validate_scope_and_identity_rules() -> None:
    network = facade.parse_target_network("192.168.50.0/24")
    check(not facade.is_usable_target_address("192.168.50.0", network), "network address accepted")
    check(not facade.is_usable_target_address("192.168.50.255", network), "broadcast accepted")
    check(not facade.is_usable_target_address("192.168.51.10", network), "out-of-scope host accepted")
    check(facade.is_usable_target_address("192.168.50.10", network), "usable host rejected")
    check(facade.normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff", "MAC normalization changed")

    with tempfile.TemporaryDirectory(prefix="deltaaegis-v044-stage4-identity-") as temporary:
        service_xml = Path(temporary) / "services.xml"
        service_xml.write_text(
            """<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="192.168.50.10" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac"/><ports/></host>
  <host><status state="up"/><address addr="192.168.50.11" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac"/><ports/></host>
  <runstats><finished exit="success"/><hosts up="2" down="252" total="254"/></runstats>
</nmaprun>
""",
            encoding="utf-8",
        )
        _exit, _up, _down, _total, assets = facade.parse_service_xml(
            service_xml,
            {},
            network,
            {},
            {},
        )
        check(set(assets) == {"ip:192.168.50.10", "ip:192.168.50.11"}, "duplicate MAC fallback changed")
        check(
            all(asset.identity_source == "DUPLICATE_MAC_FALLBACK" for asset in assets.values()),
            "duplicate MAC evidence classification changed",
        )


def main() -> int:
    print("DeltaAegis v0.44 Stage 4 NetSniper Ingest Boundary Validator")
    print("===============================================================")
    characterization = load_characterization()
    validate_ownership_and_facade(characterization)
    print("PASS: extracted ingest ownership, model identity, and compatibility facade")
    validate_fixtures_and_receipts(characterization)
    print("PASS: normalized fixture snapshots and ingest receipts are unchanged")
    validate_trust_boundaries()
    print("PASS: bundle finalization, readiness, and path-confinement trust gates")
    validate_scope_and_identity_rules()
    print("PASS: target-scope filtering and duplicate-identity fallback")
    print("PASS: DeltaAegis v0.44 Stage 4 NetSniper ingest extraction")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
