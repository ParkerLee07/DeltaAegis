from __future__ import annotations

import importlib.util
import json
import tempfile
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "deltaaegis.py"
spec = importlib.util.spec_from_file_location("deltaaegis", MODULE_PATH)
da = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = da
assert spec.loader is not None
spec.loader.exec_module(da)


def make_asset(mac: str | None, ip: str, services=()):
    key = f"mac:{mac}" if mac else f"ip:{ip}"
    return da.AssetObservation(
        asset_key=key,
        identity_class=da.classify_identity(mac),
        identity_confidence="HIGH" if mac else "LOW",
        identity_source="DISCOVERY_XML" if mac else "IP_ONLY",
        ip_address=ip,
        mac_address=mac,
        vendor=None,
        hostname=None,
        device_type=None,
        severity=None,
        score=None,
        services=list(services),
        findings=[],
    )


def make_snapshot(scan_id: str, assets: dict[str, da.AssetObservation], fingerprint="sha256:test"):
    return da.Snapshot(
        scan_id=scan_id,
        manifest_path=f"/tmp/{scan_id}/manifest.json",
        manifest_schema_version="netsniper-run-v2",
        target="192.0.2.0/24",
        scanner_version="v1.3.1",
        scan_profile="FAST_MONITORED_TCP",
        profile_fingerprint=fingerprint,
        monitored_ports=(80, 8080),
        protocols=("tcp",),
        created_at=f"2026-06-12T00:00:{scan_id[-2:]}+00:00",
        scan_started_at=None,
        scan_completed_at=None,
        neighbors_captured_at=None,
        discovery_interface="eth0",
        nmap_version="7.98",
        bundle_status="COMPLETE",
        xml_exit_status="success",
        hosts_up=max(1, len(assets)),
        hosts_down=0,
        hosts_total=max(1, len(assets)),
        assets=assets,
    )


class DeltaAegisV02Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "deltaaegis.db"
        self.events = self.root / "events.jsonl"
        self.connection = da.connect(self.db)

    def tearDown(self):
        self.connection.close()
        self.tmp.cleanup()

    def test_local_mac_is_ephemeral(self):
        self.assertEqual(da.classify_identity("02:11:22:33:44:55"), "LOCAL_MAC")
        self.assertEqual(da.classify_identity("00:11:22:33:44:55"), "GLOBAL_MAC")
        self.assertEqual(da.classify_identity(None), "IP_ONLY")
        snapshot = make_snapshot("000001", {"mac:02:11:22:33:44:55": make_asset("02:11:22:33:44:55", "192.0.2.10")})
        events = da.lifecycle_events(self.connection, snapshot)
        self.assertEqual(events[0]["event_type"], "EPHEMERAL_IDENTITY_FIRST_OBSERVED")
        self.assertEqual(events[0]["severity"], "INFO")

    def test_three_scan_removal_threshold(self):
        asset = make_asset("00:11:22:33:44:55", "192.0.2.10")
        base = make_snapshot("000001", {asset.asset_key: asset})
        da.initialize_lifecycle(self.connection, base)
        first = da.lifecycle_events(self.connection, make_snapshot("000002", {}))
        second = da.lifecycle_events(self.connection, make_snapshot("000003", {}))
        third = da.lifecycle_events(self.connection, make_snapshot("000004", {}))
        self.assertEqual([item["event_type"] for item in first], ["ASSET_NOT_OBSERVED"])
        self.assertEqual(second, [])
        self.assertEqual([item["event_type"] for item in third], ["ASSET_REMOVED"])

    def test_ip_changed_for_stable_mac(self):
        old = make_asset("00:11:22:33:44:55", "192.0.2.10")
        da.initialize_lifecycle(self.connection, make_snapshot("000001", {old.asset_key: old}))
        new = make_asset("00:11:22:33:44:55", "192.0.2.20")
        events = da.lifecycle_events(self.connection, make_snapshot("000002", {new.asset_key: new}))
        self.assertIn("IP_CHANGED", [item["event_type"] for item in events])

    def test_service_open_alert_resolves_on_close(self):
        opened = da.event("MONITORED_SERVICE_OPENED", "MEDIUM", "mac:00:11:22:33:44:55", "opened", current_value={"protocol": "tcp", "port": 8080})
        closed = da.event("MONITORED_SERVICE_CLOSED", "INFO", "mac:00:11:22:33:44:55", "closed", previous_value={"protocol": "tcp", "port": 8080})
        # snapshots are required by delta_events FK
        snap = make_snapshot("000001", {})
        da.insert_snapshot(self.connection, snap, "ACCEPTED", "ok")
        da.store_events(self.connection, "000001", None, [opened], self.events)
        status = self.connection.execute("SELECT status FROM alerts").fetchone()[0]
        self.assertEqual(status, "OPEN")
        da.store_events(self.connection, "000001", None, [closed], self.events)
        status = self.connection.execute("SELECT status FROM alerts").fetchone()[0]
        self.assertEqual(status, "RESOLVED")

    def test_profile_fingerprint_change_requires_review(self):
        snap = make_snapshot("000001", {}, fingerprint="sha256:old")
        da.insert_snapshot(self.connection, snap, "ACCEPTED", "ok")
        baseline = da.latest_accepted_snapshot(self.connection, snap.target)
        current = make_snapshot("000002", {"ip:192.0.2.10": make_asset(None, "192.0.2.10")}, fingerprint="sha256:new")
        status, reason = da.assess_quality(current, baseline)
        self.assertEqual(status, "REVIEW_REQUIRED")
        self.assertIn("profile fingerprint changed", reason.lower())

    def test_network_and_broadcast_filtered(self):
        network = da.parse_target_network("192.0.2.0/24")
        self.assertFalse(da.is_usable_target_address("192.0.2.0", network))
        self.assertFalse(da.is_usable_target_address("192.0.2.255", network))
        self.assertTrue(da.is_usable_target_address("192.0.2.10", network))


if __name__ == "__main__":
    unittest.main()
