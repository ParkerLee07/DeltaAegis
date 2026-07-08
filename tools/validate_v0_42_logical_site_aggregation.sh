#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

branch="$(git branch --show-current)"
case "$branch" in
  feature/v0.42-logical-site-scopes|main)
    ;;
  *)
    echo "FAIL: unexpected branch $branch"
    exit 1
    ;;
esac

echo "DeltaAegis v0.42 Logical Site Aggregation Validator"
echo "====================================================="

echo "[v0.42 checkpoint 4] source syntax"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py
echo "PASS: source syntax"

echo "[v0.42 checkpoint 4] static aggregation contract"
python3 - <<'PY'
from pathlib import Path
import ast

text = Path("deltaaegis.py").read_text(encoding="utf-8")
ast.parse(text)

required = (
    "# v0.42 checkpoint 4: logical site core SIEM aggregation",
    "def dashboard_site_aggregation_context(",
    "def dashboard_site_aggregation_metadata(",
    "def dashboard_site_tag_rows(",
    "def dashboard_site_summary_payload(",
    "def dashboard_site_current_state_payload(",
    "def dashboard_site_scan_context_payload(",
    "def dashboard_site_assets_payload(",
    "def dashboard_site_events_payload(",
    "def dashboard_site_alerts_payload(",
    "def dashboard_site_annotations_payload(",
    "def dashboard_site_scan_jobs_payload(",
    "def dashboard_site_port_behavior_payload(",
    "def dashboard_site_current_risk_payload(",
    "def dashboard_site_risk_payload(",
    "def dashboard_site_investigation_center_payload(",
    "def dashboard_site_asset_detail_payload(",
    "def dashboard_site_ticket_evidence_payload(",
    "def dashboard_site_latest_network_changes_payload(",
    "def dashboard_site_scan_freshness_payload(",
    "def dashboard_site_route_payload(",
    "site_scope_key",
    "ambiguous_scope_selection",
    "site_aggregation_not_supported",
    "function siteAwareInvestigationCenterPath()",
    "api(siteAwareInvestigationCenterPath())",
    "Core site-wide SIEM aggregation is active",
)

for marker in required:
    if marker not in text:
        raise SystemExit(
            f"missing Checkpoint 4 marker: {marker}"
        )

if (
    'return path + separator + "scope="'
    ' + encodeURIComponent(scope);'
) in text:
    raise SystemExit(
        "old scope-only scopedPath implementation remains"
    )

print("PASS: site aggregation helpers")
print("PASS: fail-closed site route interception")
print("PASS: browser carries site_id to core APIs")
PY

echo "[v0.42 checkpoint 4] functional aggregate semantics"
python3 - <<'PY'
from pathlib import Path
import importlib.util
import sys
import tempfile

module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v042_checkpoint4_functional"

spec = importlib.util.spec_from_file_location(
    module_name,
    module_path,
)
if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module
try:
    spec.loader.exec_module(module)
finally:
    sys.modules.pop(module_name, None)

with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v042-site-aggregation-"
) as temp_name:
    db_path = Path(temp_name) / "deltaaegis.db"

    with module.connect(db_path) as connection:
        site = module.create_logical_site(
            connection,
            "Aggregate Fixture Site",
        )
        for scope in (
            "192.168.4.0/24",
            "192.168.5.0/24",
        ):
            module.assign_network_scope_to_logical_site(
                connection,
                site["site_id"],
                scope,
            )

        original_summary = module.dashboard_summary_payload
        original_state = module.dashboard_current_state_payload
        original_assets = module.dashboard_assets_payload
        original_events = module.dashboard_events_payload
        original_risk = module.dashboard_current_risk_payload

        try:
            summary_map = {
                "192.168.4.0/24": {
                    "selected_scope": "192.168.4.0/24",
                    "snapshots": 2,
                    "events": 3,
                    "alerts": 1,
                    "open_alerts": 1,
                    "asset_annotations": 1,
                    "alert_status_counts": [
                        {"status": "OPEN", "count": 1}
                    ],
                    "event_severity_counts": [
                        {"severity": "HIGH", "count": 3}
                    ],
                    "classification_summary": {
                        "classified_count": 2,
                        "unknown_count": 1,
                    },
                    "top_risks": [
                        {"subject_key": "mac:shared", "score": 70}
                    ],
                },
                "192.168.5.0/24": {
                    "selected_scope": "192.168.5.0/24",
                    "snapshots": 4,
                    "events": 5,
                    "alerts": 2,
                    "open_alerts": 1,
                    "asset_annotations": 2,
                    "alert_status_counts": [
                        {"status": "OPEN", "count": 1},
                        {"status": "ACKNOWLEDGED", "count": 1},
                    ],
                    "event_severity_counts": [
                        {"severity": "HIGH", "count": 1},
                        {"severity": "MEDIUM", "count": 4},
                    ],
                    "classification_summary": {
                        "classified_count": 3,
                        "unknown_count": 2,
                    },
                    "top_risks": [
                        {"subject_key": "ip:192.168.5.9", "score": 90}
                    ],
                },
            }

            module.dashboard_summary_payload = (
                lambda connection, scope=None: summary_map[scope]
            )
            module.dashboard_current_state_payload = (
                lambda connection, scope=None: {
                    "available": True,
                    "selected_scope": scope,
                    "scan_id": (
                        "scan-4" if scope.endswith("4.0/24")
                        else "scan-5"
                    ),
                    "target": scope,
                    "network_scope": scope,
                    "created_at": (
                        "2026-07-08T10:00:00Z"
                        if scope.endswith("4.0/24")
                        else "2026-07-08T11:00:00Z"
                    ),
                    "imported_at": (
                        "2026-07-08T10:05:00Z"
                        if scope.endswith("4.0/24")
                        else "2026-07-08T11:05:00Z"
                    ),
                    "scanner_version": "1.9.0",
                    "scan_profile": "balanced",
                    "quality_status": "ACCEPTED",
                    "hosts_up": (
                        10 if scope.endswith("4.0/24") else 20
                    ),
                    "hosts_total": (
                        12 if scope.endswith("4.0/24") else 24
                    ),
                    "mac_backed_assets": (
                        8 if scope.endswith("4.0/24") else 16
                    ),
                    "identity_coverage": 0.6666667,
                    "assets": (
                        10 if scope.endswith("4.0/24") else 20
                    ),
                    "intelligence_hosts": (
                        10 if scope.endswith("4.0/24") else 20
                    ),
                    "service_observed_assets": (
                        7 if scope.endswith("4.0/24") else 14
                    ),
                    "discovery_only_or_no_open_service_assets": (
                        3 if scope.endswith("4.0/24") else 6
                    ),
                    "summary_host_count": (
                        10 if scope.endswith("4.0/24") else 20
                    ),
                    "classified": (
                        5 if scope.endswith("4.0/24") else 10
                    ),
                    "possible_or_review": 1,
                    "unknown": (
                        4 if scope.endswith("4.0/24") else 9
                    ),
                    "contradiction_hosts": 0,
                    "false_confidence_candidates": 0,
                    "unknown_with_exposed_services": 1,
                    "snapshot": {
                        "scan_id": (
                            "scan-4"
                            if scope.endswith("4.0/24")
                            else "scan-5"
                        )
                    },
                }
            )
            module.dashboard_assets_payload = (
                lambda connection, limit, scope=None,
                state=None, identity=None: [
                    {
                        "asset_key": "mac:shared",
                        "current_ip": (
                            "192.168.4.10"
                            if scope.endswith("4.0/24")
                            else "192.168.5.10"
                        ),
                        "state": "ACTIVE",
                    }
                ]
            )
            module.dashboard_events_payload = (
                lambda connection, limit, scope=None: [
                    {
                        "event_id": (
                            4 if scope.endswith("4.0/24") else 5
                        ),
                        "subject_key": "mac:shared",
                        "created_at": (
                            "2026-07-08T10:00:00Z"
                            if scope.endswith("4.0/24")
                            else "2026-07-08T11:00:00Z"
                        ),
                    }
                ]
            )
            module.dashboard_current_risk_payload = (
                lambda connection, limit, scope=None: [
                    {
                        "subject_key": "mac:shared",
                        "score": (
                            40 if scope.endswith("4.0/24") else 80
                        ),
                    }
                ]
            )

            summary = module.dashboard_site_summary_payload(
                connection,
                site["site_id"],
            )
            state = module.dashboard_site_current_state_payload(
                connection,
                site["site_id"],
            )
            assets = module.dashboard_site_assets_payload(
                connection,
                site["site_id"],
                25,
            )
            events = module.dashboard_site_events_payload(
                connection,
                site["site_id"],
                20,
            )
            risks = module.dashboard_site_current_risk_payload(
                connection,
                site["site_id"],
                20,
            )
        finally:
            module.dashboard_summary_payload = original_summary
            module.dashboard_current_state_payload = original_state
            module.dashboard_assets_payload = original_assets
            module.dashboard_events_payload = original_events
            module.dashboard_current_risk_payload = original_risk

    if summary["snapshots"] != 6:
        raise AssertionError("site snapshot total mismatch")
    if summary["events"] != 8:
        raise AssertionError("site event total mismatch")
    if summary["alerts"] != 3:
        raise AssertionError("site alert total mismatch")
    if summary["classification_summary"]["classified_count"] != 5:
        raise AssertionError("classification count aggregation mismatch")
    if summary["top_risks"][0]["score"] != 90:
        raise AssertionError("site risk ranking mismatch")

    if state["hosts_up"] != 30 or state["assets"] != 30:
        raise AssertionError("latest-per-member current state mismatch")
    if len(state["member_states"]) != 2:
        raise AssertionError("member current-state provenance missing")

    if len(assets) != 2:
        raise AssertionError("cross-scope duplicate asset was collapsed")
    if len({row["network_scope"] for row in assets}) != 2:
        raise AssertionError("asset subnet provenance missing")
    if len({row["site_scope_key"] for row in assets}) != 2:
        raise AssertionError("site scope keys are not collision-safe")

    if events[0]["network_scope"] != "192.168.5.0/24":
        raise AssertionError("event ordering/provenance mismatch")
    if risks[0]["score"] != 80:
        raise AssertionError("site current-risk ordering mismatch")

print("PASS: site summary totals")
print("PASS: latest accepted state summed per member subnet")
print("PASS: cross-scope duplicate assets remain distinct")
print("PASS: event and risk ordering preserves provenance")
PY

echo "[v0.42 checkpoint 4] real schema asset isolation"
python3 - <<'PY'
from pathlib import Path
import importlib.util
import sys
import tempfile

module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v042_checkpoint4_schema"

spec = importlib.util.spec_from_file_location(
    module_name,
    module_path,
)
if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module
try:
    spec.loader.exec_module(module)
finally:
    sys.modules.pop(module_name, None)

with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v042-site-schema-"
) as temp_name:
    db_path = Path(temp_name) / "deltaaegis.db"

    with module.connect(db_path) as connection:
        site = module.create_logical_site(
            connection,
            "Schema Isolation Site",
        )
        member_scopes = (
            "192.168.4.0/24",
            "192.168.5.0/24",
        )

        for scope in member_scopes:
            module.assign_network_scope_to_logical_site(
                connection,
                site["site_id"],
                scope,
            )

        rows = (
            (
                "192.168.4.0/24",
                "192.168.4.10",
                "scan-member-4",
            ),
            (
                "192.168.5.0/24",
                "192.168.5.10",
                "scan-member-5",
            ),
            (
                "192.168.99.0/24",
                "192.168.99.10",
                "scan-unrelated",
            ),
        )

        for scope, ip_address, scan_id in rows:
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
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scope,
                    "mac:aa:bb:cc:dd:ee:ff",
                    "GLOBAL_MAC",
                    "ACTIVE",
                    0,
                    ip_address,
                    "aa:bb:cc:dd:ee:ff",
                    "Fixture Vendor",
                    "fixture-host",
                    scan_id,
                    scan_id,
                    "2026-07-08T10:00:00Z",
                    "2026-07-08T11:00:00Z",
                    None,
                ),
            )

        aggregated = module.dashboard_site_assets_payload(
            connection,
            site["site_id"],
            25,
        )
        global_rows = module.dashboard_assets_payload(
            connection,
            25,
        )

    if len(aggregated) != 2:
        raise AssertionError(
            f"expected 2 site assets, found {len(aggregated)}"
        )
    if len(global_rows) != 3:
        raise AssertionError(
            f"expected 3 global assets, found {len(global_rows)}"
        )
    if {
        row["network_scope"] for row in aggregated
    } != set(member_scopes):
        raise AssertionError(
            "site assets included an unrelated subnet"
        )
    if len({
        row["site_scope_key"] for row in aggregated
    }) != 2:
        raise AssertionError(
            "duplicate MAC identity was silently collapsed"
        )

print("PASS: unrelated subnet excluded")
print("PASS: real-schema duplicate identity preserved by scope")
PY

echo "[v0.42 checkpoint 4] authenticated HTTP routing"
python3 - <<'PY'
from __future__ import annotations

from pathlib import Path
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


def reserve_port() -> int:
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    ) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(
    url: str,
    *,
    token: str | None = None,
) -> tuple[int, bytes]:
    headers = {"Accept": "application/json, text/html"}

    if token:
        headers["X-DeltaAegis-Token"] = token

    req = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(
            req,
            timeout=5.0,
        ) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read()


module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v042_checkpoint4_http"

spec = importlib.util.spec_from_file_location(
    module_name,
    module_path,
)
if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module
try:
    spec.loader.exec_module(module)
finally:
    sys.modules.pop(module_name, None)

with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v042-site-http-"
) as temp_name:
    temp = Path(temp_name)
    db_path = temp / "deltaaegis.db"
    stdout_path = temp / "dashboard.stdout"
    stderr_path = temp / "dashboard.stderr"
    token = "checkpoint4-site-token"
    port = reserve_port()

    with module.connect(db_path) as connection:
        site = module.create_logical_site(
            connection,
            "HTTP Aggregate Site",
        )

        for scope in (
            "192.168.4.0/24",
            "192.168.5.0/24",
        ):
            module.assign_network_scope_to_logical_site(
                connection,
                site["site_id"],
                scope,
            )

        for scope, ip_address, scan_id in (
            (
                "192.168.4.0/24",
                "192.168.4.10",
                "scan-http-4",
            ),
            (
                "192.168.5.0/24",
                "192.168.5.10",
                "scan-http-5",
            ),
            (
                "192.168.99.0/24",
                "192.168.99.10",
                "scan-http-unrelated",
            ),
        ):
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
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scope,
                    "mac:11:22:33:44:55:66",
                    "GLOBAL_MAC",
                    "ACTIVE",
                    0,
                    ip_address,
                    "11:22:33:44:55:66",
                    "HTTP Fixture",
                    "http-fixture",
                    scan_id,
                    scan_id,
                    "2026-07-08T10:00:00Z",
                    "2026-07-08T11:00:00Z",
                    None,
                ),
            )

    with stdout_path.open(
        "w",
        encoding="utf-8",
    ) as stdout_handle, stderr_path.open(
        "w",
        encoding="utf-8",
    ) as stderr_handle:
        process = subprocess.Popen(
            [
                sys.executable,
                "deltaaegis.py",
                "--db",
                str(db_path),
                "dashboard",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--token",
                token,
                "--quiet",
                "--no-enable-scheduled-scans",
            ],
            stdout=stdout_handle,
            stderr=stderr_handle,
            text=True,
            start_new_session=True,
        )

        base = f"http://127.0.0.1:{port}"

        try:
            deadline = time.time() + 15.0

            while time.time() < deadline:
                if process.poll() is not None:
                    break

                try:
                    status, body = request(base + "/healthz")
                    if status == 200 and body == b"ok":
                        break
                except OSError:
                    pass

                time.sleep(0.1)
            else:
                raise AssertionError(
                    "dashboard did not become ready"
                )

            if process.poll() is not None:
                raise AssertionError(
                    "dashboard exited before HTTP checks\n"
                    + stderr_path.read_text(
                        encoding="utf-8",
                    )
                )

            encoded_site = urllib.parse.quote(
                site["site_id"],
            )

            status, body = request(
                base
                + "/api/assets?limit=25&site_id="
                + encoded_site,
                token=token,
            )
            if status != 200:
                raise AssertionError(
                    f"site assets returned {status}: "
                    f"{body.decode(errors='replace')}"
                )
            payload = json.loads(body)

            if len(payload) != 2:
                raise AssertionError(
                    "site asset endpoint did not isolate members"
                )
            if {
                row["network_scope"] for row in payload
            } != {
                "192.168.4.0/24",
                "192.168.5.0/24",
            }:
                raise AssertionError(
                    "site asset endpoint leaked unrelated scope"
                )

            global_status, global_body = request(
                base + "/api/assets?limit=25",
                token=token,
            )
            if global_status != 200:
                raise AssertionError(
                    f"global assets returned {global_status}"
                )
            if len(json.loads(global_body)) != 3:
                raise AssertionError(
                    "global fixture did not contain unrelated row"
                )

            summary_status, summary_body = request(
                base
                + "/api/summary?site_id="
                + encoded_site,
                token=token,
            )
            if summary_status != 200:
                raise AssertionError(
                    f"site summary returned {summary_status}"
                )
            summary = json.loads(summary_body)
            if not summary.get("site_aggregate"):
                raise AssertionError(
                    "site summary metadata missing"
                )
            if summary.get("member_scope_count") != 2:
                raise AssertionError(
                    "site summary member count mismatch"
                )

            ambiguous_status, ambiguous_body = request(
                base
                + "/api/assets?scope=192.168.4.0%2F24"
                + "&site_id="
                + encoded_site,
                token=token,
            )
            if ambiguous_status != 400:
                raise AssertionError(
                    "scope+site_id did not fail closed"
                )
            if json.loads(ambiguous_body).get("error") != (
                "ambiguous_scope_selection"
            ):
                raise AssertionError(
                    "ambiguous selector error mismatch"
                )

            unknown_status, unknown_body = request(
                base
                + "/api/assets?site_id=site-does-not-exist",
                token=token,
            )
            if unknown_status != 404:
                raise AssertionError(
                    "unknown site did not return 404"
                )
            if json.loads(unknown_body).get("error") != (
                "logical_site_not_found"
            ):
                raise AssertionError(
                    "unknown site error mismatch"
                )

            unsupported_status, unsupported_body = request(
                base
                + "/api/validation-summary?site_id="
                + encoded_site,
                token=token,
            )
            if unsupported_status != 400:
                raise AssertionError(
                    "unsupported site route did not fail closed"
                )
            if json.loads(unsupported_body).get("error") != (
                "site_aggregation_not_supported"
            ):
                raise AssertionError(
                    "unsupported route error mismatch"
                )

            page_status, page_body = request(
                base + "/",
                token=token,
            )
            if page_status != 200:
                raise AssertionError(
                    f"dashboard page returned {page_status}"
                )
            page_text = page_body.decode("utf-8")

            for marker in (
                "function siteAwareInvestigationCenterPath()",
                "site_id=",
                "Core site-wide SIEM aggregation is active",
            ):
                if marker not in page_text:
                    raise AssertionError(
                        f"rendered dashboard missing {marker}"
                    )

        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass

                try:
                    process.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(
                            process.pid,
                            signal.SIGKILL,
                        )
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5.0)

print("PASS: authenticated site asset aggregation")
print("PASS: unrelated subnet excluded over HTTP")
print("PASS: site summary aggregation metadata")
print("PASS: scope/site ambiguity rejected")
print("PASS: unknown site returns 404")
print("PASS: unsupported site route fails closed")
print("PASS: rendered browser carries site_id")
PY

echo "[v0.42 checkpoint 4] rendered JavaScript syntax"
./tools/validate_v0_40_dashboard_javascript_syntax.sh
echo "PASS: rendered JavaScript syntax"

echo "[v0.42 checkpoint 4] prior checkpoint compatibility"
./tools/validate_v0_42_logical_site_foundation.sh
./tools/validate_v0_42_dashboard_lan_flag.sh
./tools/validate_v0_42_logical_site_cli.sh
./tools/validate_v0_42_logical_site_dashboard_foundation.sh
echo "PASS: prior checkpoint compatibility"

echo "[v0.42 checkpoint 4] repository hygiene"
git diff --check
echo "PASS: repository hygiene"

echo "PASS: DeltaAegis v0.42 logical site aggregation validator"
