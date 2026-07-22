#!/usr/bin/env python3
"""Validate the combined DeltaAegis v1 Stages 3–5 upgrade."""

from __future__ import annotations

import http.client
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping
from urllib.parse import quote, urlencode


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import deltaaegis  # noqa: E402
from deltaaegis_core import api_v1, auth, detection, identity, operations  # noqa: E402


class ValidationFailure(RuntimeError):
    pass


def check(condition: Any, message: str) -> None:
    if not condition:
        raise ValidationFailure(message)


def load_json(relative: str) -> Any:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def validate_contracts() -> None:
    check(
        deltaaegis.DELTAAEGIS_VERSION == "1.0.0-stage35",
        "combined candidate version is not 1.0.0-stage35",
    )
    check(
        load_json("contracts/v1/detection-rules.json") == detection.rules_contract(),
        "tracked detection rules differ from the runtime ruleset",
    )
    check(
        load_json("contracts/v1/integration-compatibility.json")
        == operations.INTEGRATION_COMPATIBILITY,
        "tracked integration pins differ from runtime compatibility",
    )
    check(
        load_json("docs/v1-performance-targets.json")
        == operations.PERFORMANCE_TARGETS,
        "tracked performance targets differ from runtime thresholds",
    )
    runtime_openapi = api_v1.openapi_document()
    api_v1.validate_openapi_document(runtime_openapi)
    check(
        load_json("contracts/v1/openapi.json") == runtime_openapi,
        "tracked OpenAPI document differs from the runtime inventory",
    )
    endpoint_inventory = {
        (item.method, item.template, item.permission)
        for item in api_v1.API_V1_ENDPOINTS
    }
    for endpoint in {
        ("GET", "/api/v1/health", None),
        ("GET", "/api/v1/readiness", "operations.read"),
        ("GET", "/api/v1/diagnostics", "operations.read"),
        ("POST", "/api/v1/sensors", "identity.sensors.write"),
        ("GET", "/api/v1/detections", "dashboard.read"),
        (
            "POST",
            "/api/v1/detections/{result_id}/reviews",
            "detection.review",
        ),
    }:
        check(endpoint in endpoint_inventory, f"stable endpoint is missing: {endpoint}")


def asset(
    *,
    key: str,
    ip_address: str,
    hostname: str,
    score: int = 4,
) -> SimpleNamespace:
    return SimpleNamespace(
        asset_key=key,
        identity_class="LOCAL_MAC",
        ip_address=ip_address,
        mac_address="02:00:00:00:00:01",
        hostname=hostname,
        vendor="Fixture",
        score=score,
        services=[
            SimpleNamespace(
                protocol="tcp",
                port=443,
                state="open",
                service_name="https",
                product="fixture",
                version="1",
            )
        ],
        findings=[
            SimpleNamespace(
                finding_id="fixture-risk",
                port=443,
                name="Fixture risk",
                service="https",
                score=score,
                evidence="synthetic",
            )
        ],
    )


def project(
    connection: sqlite3.Connection,
    evidence_identity: Mapping[str, Any],
    *,
    observed_at: str,
    hostname: str,
) -> dict[str, Any]:
    return identity.apply_snapshot_projection(
        connection,
        snapshot=SimpleNamespace(
            created_at=observed_at,
            assets={
                "mac:02:00:00:00:00:01": asset(
                    key="mac:02:00:00:00:00:01",
                    ip_address="192.168.77.10",
                    hostname=hostname,
                )
            },
        ),
        decision={
            "decision_id": f"decision-{evidence_identity['internal_scan_id']}",
            "current_state": "ACCEPTED",
        },
        identity=evidence_identity,
    )


def register_fixture_sensors(connection: sqlite3.Connection) -> dict[str, Any]:
    actor = {
        "user_id": "validator-admin",
        "username": "stage35-validator",
        "role": "ADMIN",
        "auth_type": "validator",
    }
    try:
        identity.register_sensor(
            connection,
            sensor_id="sensor-public-denied",
            display_name="Public range must fail",
            trust_domain="fixture",
            network_scopes=["192.0.2.0/24"],
            actor=actor,
        )
    except identity.IdentityError:
        pass
    else:
        raise ValidationFailure("non-RFC1918 sensor scope was enrolled")
    alpha = identity.register_sensor(
        connection,
        sensor_id="sensor-fixture-alpha",
        display_name="Fixture Alpha",
        trust_domain="fixture",
        network_scopes=["192.168.77.0/24"],
        actor=actor,
    )
    bravo = identity.register_sensor(
        connection,
        sensor_id="sensor-fixture-bravo",
        display_name="Fixture Bravo",
        trust_domain="fixture",
        network_scopes=["192.168.77.0/24"],
        actor=actor,
    )
    check(
        alpha["scopes"][0]["scope_id"] != bravo["scopes"][0]["scope_id"],
        "overlapping CIDRs collapsed into one scope identity",
    )
    connection.commit()
    return {"actor": actor, "alpha": alpha, "bravo": bravo}


def validate_identity_and_jobs(
    connection: sqlite3.Connection,
    fixtures: Mapping[str, Any],
    temporary: Path,
) -> dict[str, Any]:
    alpha = fixtures["alpha"]
    bravo = fixtures["bravo"]
    alpha_scope = alpha["scopes"][0]
    bravo_scope = bravo["scopes"][0]
    digest_a = "a" * 64
    digest_b = "b" * 64

    duplicate_identity = identity.identity_for_evidence(
        connection,
        sensor_id=alpha["sensor_id"],
        network_scope="192.168.77.0/24",
        source_scan_id="netsniper-v2.1-duplicate-001",
        bundle_digest=digest_a,
    )
    identity.record_evidence_receipt(
        connection,
        identity=duplicate_identity,
        decision_id="decision-duplicate",
        import_status="IMPORTED",
    )
    replay_identity = identity.identity_for_evidence(
        connection,
        sensor_id=alpha["sensor_id"],
        network_scope="192.168.77.0/24",
        source_scan_id="netsniper-v2.1-duplicate-001",
        bundle_digest=digest_a,
    )
    check(replay_identity["duplicate"] is True, "duplicate evidence was not idempotent")
    try:
        identity.identity_for_evidence(
            connection,
            sensor_id=alpha["sensor_id"],
            network_scope="192.168.77.0/24",
            source_scan_id="netsniper-v2.1-duplicate-001",
            bundle_digest=digest_b,
        )
    except identity.IdentityError:
        pass
    else:
        raise ValidationFailure("conflicting evidence reused a sensor source scan ID")
    try:
        identity.identity_for_evidence(
            connection,
            sensor_id="sensor-fixture-unknown",
            network_scope="192.168.77.0/24",
            source_scan_id="netsniper-v2.1-unknown-001",
            bundle_digest=digest_a,
        )
    except identity.IdentityError:
        pass
    else:
        raise ValidationFailure("evidence from an unknown sensor was accepted")

    alpha_new = identity.identity_for_evidence(
        connection,
        sensor_id=alpha["sensor_id"],
        network_scope="192.168.77.0/24",
        source_scan_id="netsniper-v2.1-alpha-new",
        bundle_digest="1" * 64,
    )
    alpha_old = identity.identity_for_evidence(
        connection,
        sensor_id=alpha["sensor_id"],
        network_scope="192.168.77.0/24",
        source_scan_id="netsniper-v2.1-alpha-old",
        bundle_digest="2" * 64,
    )
    bravo_new = identity.identity_for_evidence(
        connection,
        sensor_id=bravo["sensor_id"],
        network_scope="192.168.77.0/24",
        source_scan_id="netsniper-v2.1-bravo-new",
        bundle_digest="3" * 64,
    )
    check(
        project(
            connection,
            alpha_new,
            observed_at="2026-07-21T18:00:00+00:00",
            hostname="alpha-current",
        )["applied"],
        "newer alpha evidence did not project",
    )
    old_outcome = project(
        connection,
        alpha_old,
        observed_at="2026-07-21T17:00:00+00:00",
        hostname="alpha-stale",
    )
    check(
        old_outcome == {"applied": False, "reason": "historical"},
        "out-of-order evidence changed current state",
    )
    check(
        project(
            connection,
            bravo_new,
            observed_at="2026-07-21T18:05:00+00:00",
            hostname="bravo-current",
        )["applied"],
        "bravo evidence did not project",
    )
    alpha_assets = identity.list_assets(
        connection,
        scope_id=alpha_scope["scope_id"],
    )
    bravo_assets = identity.list_assets(
        connection,
        scope_id=bravo_scope["scope_id"],
    )
    check(
        len(alpha_assets) == len(bravo_assets) == 1,
        "overlapping scope projections are incomplete",
    )
    check(
        alpha_assets[0]["hostname"] == "alpha-current"
        and bravo_assets[0]["hostname"] == "bravo-current",
        "overlapping scope projections leaked across sensors",
    )

    connection.commit()
    netsniper = temporary / "netsniper.py"
    netsniper.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    netsniper.chmod(0o755)
    runs = temporary / "runs"
    runs.mkdir()
    alpha_job = deltaaegis.reserve_scan_job_if_idle(
        connection,
        "192.168.77.0/24",
        netsniper,
        runs,
        sensor_id=alpha["sensor_id"],
        scope_id=alpha_scope["scope_id"],
    )
    bravo_job = deltaaegis.reserve_scan_job_if_idle(
        connection,
        "192.168.77.0/24",
        netsniper,
        runs,
        sensor_id=bravo["sensor_id"],
        scope_id=bravo_scope["scope_id"],
    )
    check(
        alpha_job["job_id"] != bravo_job["job_id"],
        "different sensors could not reserve concurrent scan jobs",
    )
    try:
        deltaaegis.reserve_scan_job_if_idle(
            connection,
            "192.168.77.0/24",
            netsniper,
            runs,
            sensor_id=alpha["sensor_id"],
            scope_id=alpha_scope["scope_id"],
        )
    except deltaaegis.ActiveScanJobExistsError:
        pass
    else:
        raise ValidationFailure("one sensor reserved two active scan jobs")
    return {
        "alpha_identity": alpha_new,
        "bravo_identity": bravo_new,
        "alpha_scope_id": alpha_scope["scope_id"],
        "bravo_scope_id": bravo_scope["scope_id"],
    }


def validate_detection(
    connection: sqlite3.Connection,
    identities: Mapping[str, Any],
    actor: Mapping[str, Any],
) -> str:
    events = load_json("examples/v1-stage3-5-fixtures/detection-events.json")[
        "events"
    ]
    decision = {
        "decision_id": "decision-detection-fixture",
        "current_state": "ACCEPTED",
        "evaluated_at": "2026-07-21T18:10:00+00:00",
    }
    first = detection.persist_results(
        connection,
        events,
        identity=identities["alpha_identity"],
        decision=decision,
        baseline_scan_id="baseline-fixture-001",
    )
    replay = detection.persist_results(
        connection,
        events,
        identity=identities["alpha_identity"],
        decision=decision,
        baseline_scan_id="baseline-fixture-001",
    )
    check(first["inserted"] == 2, "fixture detections were not persisted")
    check(
        replay["inserted"] == 0
        and replay["replayed"] == 2
        and replay["result_ids"] == first["result_ids"],
        "detection replay was not deterministic and idempotent",
    )
    bravo = detection.persist_results(
        connection,
        events,
        identity=identities["bravo_identity"],
        decision=decision,
        baseline_scan_id="baseline-fixture-001",
    )
    check(
        set(bravo["result_ids"]).isdisjoint(first["result_ids"]),
        "detection identities collided across sensor scopes",
    )
    result_id = first["result_ids"][0]
    result_before = detection.result_by_id(connection, result_id)
    check(
        result_before["evidence"]["scope_id"] == identities["alpha_scope_id"]
        and result_before["explanation"]["provenance"]["sensor_id"]
        == identities["alpha_identity"]["sensor_id"],
        "detection provenance is incomplete",
    )
    try:
        connection.execute(
            "UPDATE detection_results SET severity='LOW' WHERE result_id=?",
            (result_id,),
        )
    except sqlite3.IntegrityError:
        pass
    else:
        raise ValidationFailure("immutable detection result was updated")
    suppressed = detection.review_result(
        connection,
        result_id=result_id,
        action="SUPPRESSED",
        reason="Known synthetic validator condition.",
        actor=actor,
    )
    check(
        suppressed["disposition"] == "SUPPRESSED"
        and suppressed["severity"] == result_before["severity"],
        "suppression rewrote the immutable detection result",
    )
    reopened = detection.review_result(
        connection,
        result_id=result_id,
        action="UNSUPPRESSED",
        reason="Validator confirms separate append-only review state.",
        actor=actor,
    )
    check(
        reopened["disposition"] == "OPEN" and len(reopened["reviews"]) == 2,
        "append-only detection review history is incomplete",
    )
    check(
        [item["review_sequence"] for item in reopened["reviews"]]
        == sorted(item["review_sequence"] for item in reopened["reviews"]),
        "detection reviews are not ordered by append sequence",
    )
    try:
        connection.execute(
            "UPDATE detection_reviews SET reason='changed' WHERE result_id=?",
            (result_id,),
        )
    except sqlite3.IntegrityError:
        pass
    else:
        raise ValidationFailure("immutable detection review was updated")
    connection.commit()
    return result_id


def validate_trueaegis_identity(
    connection: sqlite3.Connection,
    identities: Mapping[str, Any],
    temporary: Path,
) -> None:
    source_rows = load_json(
        "examples/trueaegis-fixtures/basic-validation/validation_results.json"
    )
    scoped_rows = []
    for index, row in enumerate(source_rows):
        item = dict(row)
        item["host"] = f"192.168.77.{10 + index}"
        scoped_rows.append(item)
    scoped_path = temporary / "trueaegis-scoped.json"
    scoped_path.write_text(
        json.dumps(scoped_rows, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    alpha = deltaaegis.import_trueaegis_validation_results(
        connection,
        scoped_path,
        sensor_id=identities["alpha_identity"]["sensor_id"],
        scope_id=identities["alpha_scope_id"],
    )
    bravo = deltaaegis.import_trueaegis_validation_results(
        connection,
        scoped_path,
        sensor_id=identities["bravo_identity"]["sensor_id"],
        scope_id=identities["bravo_scope_id"],
    )
    check(
        alpha["validation_run_id"] != bravo["validation_run_id"],
        "TrueAegis replay identity collided across sensor scopes",
    )
    for result, expected_sensor, expected_scope in (
        (
            alpha,
            identities["alpha_identity"]["sensor_id"],
            identities["alpha_scope_id"],
        ),
        (
            bravo,
            identities["bravo_identity"]["sensor_id"],
            identities["bravo_scope_id"],
        ),
    ):
        row = connection.execute(
            "SELECT sensor_id, scope_id FROM validation_runs "
            "WHERE validation_run_id=?",
            (result["validation_run_id"],),
        ).fetchone()
        check(
            row is not None
            and row["sensor_id"] == expected_sensor
            and row["scope_id"] == expected_scope,
            "TrueAegis run provenance is incomplete",
        )
        observation_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM validation_observations "
                "WHERE validation_run_id=? AND sensor_id=? AND scope_id=?",
                (result["validation_run_id"], expected_sensor, expected_scope),
            ).fetchone()[0]
        )
        check(
            observation_count == len(scoped_rows),
            "TrueAegis observation provenance is incomplete",
        )
    outside_path = temporary / "trueaegis-outside-scope.json"
    outside_path.write_text(
        json.dumps(source_rows, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    try:
        deltaaegis.import_trueaegis_validation_results(
            connection,
            outside_path,
            sensor_id=identities["alpha_identity"]["sensor_id"],
            scope_id=identities["alpha_scope_id"],
        )
    except identity.IdentityError:
        pass
    else:
        raise ValidationFailure("out-of-scope TrueAegis evidence was attributed")


def validate_operations(connection: sqlite3.Connection, database: Path) -> None:
    expected_migrations = list(operations.EXPECTED_MIGRATIONS)
    actual_migrations = [
        str(row["migration_id"])
        for row in connection.execute(
            "SELECT migration_id FROM schema_migrations ORDER BY migration_id"
        )
    ]
    check(actual_migrations == expected_migrations, "migration 0004/0005 ledger drift")
    identity.validate_schema(connection)
    detection.validate_schema(connection)
    readiness = operations.readiness_report(connection, database_path=database)
    check(readiness["status"] == "READY", "healthy fixture is not READY")
    missing = operations.readiness_report(
        connection,
        database_path=database,
        netsniper_path=database.parent / "missing-netsniper",
    )
    check(
        missing["status"] == "NOT_READY",
        "missing required NetSniper integration did not fail readiness",
    )
    connection.execute("PRAGMA query_only=ON")
    query_only = operations.readiness_report(connection, database_path=database)
    connection.execute("PRAGMA query_only=OFF")
    check(
        query_only["status"] == "NOT_READY",
        "read-only database did not fail readiness",
    )
    connection.execute("PRAGMA cache_size=-2048")
    connection.execute("PRAGMA mmap_size=0")
    check(
        operations.readiness_report(connection, database_path=database)["status"]
        == "READY",
        "bounded-cache operation failed",
    )
    fixture = load_json(
        "examples/trueaegis-fixtures/basic-validation/validation_results.json"
    )
    check(
        operations.validate_trueaegis_fixture(fixture)["status"] == "PASS",
        "pinned TrueAegis fixture contract failed",
    )
    try:
        operations.validate_trueaegis_fixture({"status": "CONFIRMED"})
    except operations.OperationsError:
        pass
    else:
        raise ValidationFailure("malformed TrueAegis evidence was accepted")
    redacted = operations._redact(  # type: ignore[attr-defined]
        {
            "password": "not-for-output",
            "nested": {"authorization": "Bearer secret", "safe": "visible"},
        }
    )
    check(
        "not-for-output" not in json.dumps(redacted)
        and "Bearer secret" not in json.dumps(redacted),
        "diagnostic redaction exposed a secret",
    )
    diagnostics = operations.diagnostics_report(
        connection,
        database_path=database,
    )
    rendered = json.dumps(diagnostics)
    check(
        len(rendered.encode("utf-8")) < 65536
        and "raw_token" not in rendered.casefold(),
        "diagnostics are unbounded or contain raw credentials",
    )


class Client:
    def __init__(self, port: int) -> None:
        self.port = port

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        payload: Any = None,
        idempotency_key: str | None = None,
    ) -> tuple[int, Mapping[str, str], Any]:
        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        body = None
        if payload is not None:
            body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            response_headers = {key.casefold(): value for key, value in response.getheaders()}
            raw = response.read()
        finally:
            connection.close()
        document = json.loads(raw.decode("utf-8"))
        if path.startswith("/api/v1"):
            api_v1.validate_envelope(document)
            check(
                response_headers.get("x-request-id")
                == document["meta"]["request_id"],
                "stable HTTP request ID drift",
            )
            check(len(raw) < 65536, "stable HTTP response is unbounded")
        return response.status, response_headers, document


def unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def start_server(database: Path, temporary: Path, port: int) -> subprocess.Popen[bytes]:
    command = [
        sys.executable,
        "-u",
        str(ROOT / "deltaaegis.py"),
        "--db",
        str(database),
        "--events",
        str(temporary / "events.jsonl"),
        "--reports-dir",
        str(temporary / "reports"),
        "dashboard",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--token",
        "legacy-stage35-validator",
        "--require-login",
        "--no-enable-scheduled-scans",
        "--quiet",
    ]
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.Popen(
        command,
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def wait_for_server(process: subprocess.Popen[bytes], port: int) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = (process.stdout.read() if process.stdout else b"").decode(
                "utf-8", errors="replace"
            )
            raise ValidationFailure(f"dashboard exited during startup:\n{output}")
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            connection.request("GET", "/healthz")
            response = connection.getresponse()
            body = response.read()
            connection.close()
        except OSError:
            time.sleep(0.05)
            continue
        if response.status == 200 and body == b"ok":
            return
        raise ValidationFailure("dashboard health endpoint failed")
    raise ValidationFailure("dashboard did not start within 15 seconds")


def create_http_tokens(database: Path) -> dict[str, str]:
    connection = deltaaegis.connect(database)
    try:
        admin = auth.create_access_user(
            connection,
            "stage35-http-admin",
            role="ADMIN",
            password="Stage35-HTTP-Admin!",
        )
        viewer = auth.create_access_user(
            connection,
            "stage35-http-viewer",
            role="VIEWER",
            password="Stage35-HTTP-Viewer!",
        )
        admin_token = auth.create_scoped_access_api_token(
            connection,
            admin["user_id"],
            "stage35-admin",
            role="ADMIN",
            scopes=[
                "dashboard.read",
                "detection.review",
                "identity.sensors.write",
                "operations.read",
                "session.read",
            ],
        )
        viewer_token = auth.create_scoped_access_api_token(
            connection,
            viewer["user_id"],
            "stage35-viewer",
            role="VIEWER",
            scopes=["dashboard.read", "session.read"],
        )
        connection.commit()
        return {"admin": admin_token["token"], "viewer": viewer_token["token"]}
    finally:
        connection.close()


def validate_http(
    database: Path,
    temporary: Path,
    result_id: str,
    alpha_scope_id: str,
) -> None:
    tokens = create_http_tokens(database)
    port = unused_port()
    client = Client(port)
    process = start_server(database, temporary, port)
    try:
        wait_for_server(process, port)
        status, _headers, payload = client.request("GET", "/api/v1/health")
        check(
            status == 200
            and payload["data"]["status"] == "UP"
            and "database" not in payload["data"],
            "public liveness exposed dependency state",
        )
        status, _headers, payload = client.request("GET", "/api/v1/readiness")
        check(status == 401 and not payload["ok"], "readiness was public")
        status, _headers, payload = client.request(
            "GET", "/api/v1/readiness", token=tokens["viewer"]
        )
        check(status == 403 and not payload["ok"], "VIEWER read readiness")
        status, _headers, payload = client.request(
            "GET", "/api/v1/readiness", token=tokens["admin"]
        )
        check(
            status == 200 and payload["data"]["status"] == "READY",
            "authorized readiness failed",
        )
        status, _headers, payload = client.request(
            "GET", "/api/v1/diagnostics", token=tokens["admin"]
        )
        check(
            status == 200 and "raw_token" not in json.dumps(payload).casefold(),
            "authenticated diagnostics failed or leaked tokens",
        )

        sensor_payload = {
            "sensor_id": "sensor-http-charlie",
            "display_name": "HTTP Charlie",
            "trust_domain": "validator",
            "network_scopes": ["10.88.0.0/24"],
            "metadata": {"fixture": True},
        }
        status, _headers, payload = client.request(
            "POST",
            "/api/v1/sensors",
            token=tokens["viewer"],
            payload=sensor_payload,
            idempotency_key="stage35-sensor-denied-001",
        )
        check(status == 403 and not payload["ok"], "VIEWER enrolled a sensor")
        status, headers, payload = client.request(
            "POST",
            "/api/v1/sensors",
            token=tokens["admin"],
            payload=sensor_payload,
            idempotency_key="stage35-sensor-create-001",
        )
        check(
            status == 201 and payload["data"]["sensor_id"] == "sensor-http-charlie",
            "authorized sensor enrollment failed",
        )
        first_payload = payload
        status, replay_headers, replay_payload = client.request(
            "POST",
            "/api/v1/sensors",
            token=tokens["admin"],
            payload=sensor_payload,
            idempotency_key="stage35-sensor-create-001",
        )
        check(
            status == 201
            and replay_headers.get("idempotency-replayed") == "true"
            and replay_payload == first_payload,
            "sensor enrollment idempotency replay drifted",
        )
        status, _headers, payload = client.request(
            "GET", "/api/v1/sensors?limit=50", token=tokens["viewer"]
        )
        check(
            status == 200
            and any(
                item["sensor_id"] == "sensor-http-charlie"
                for item in payload["data"]["items"]
            ),
            "sensor inventory did not expose the enrolled sensor",
        )
        status, _headers, payload = client.request(
            "GET",
            "/api/v1/assets?"
            + urlencode({"scope_id": alpha_scope_id, "limit": 50}),
            token=tokens["viewer"],
        )
        check(
            status == 200
            and len(payload["data"]["items"]) == 1
            and payload["data"]["items"][0]["scope_id"] == alpha_scope_id,
            "stable API did not preserve scope-isolated assets",
        )
        status, _headers, payload = client.request(
            "GET", "/api/v1/detections?limit=50", token=tokens["viewer"]
        )
        check(
            status == 200
            and any(item["result_id"] == result_id for item in payload["data"]["items"]),
            "stable API omitted immutable detections",
        )
        review_payload = {
            "action": "REVIEWED",
            "reason": "HTTP validator confirms separate review state.",
        }
        review_path = f"/api/v1/detections/{quote(result_id, safe='')}/reviews"
        status, _headers, payload = client.request(
            "POST",
            review_path,
            token=tokens["viewer"],
            payload=review_payload,
            idempotency_key="stage35-review-denied-001",
        )
        check(status == 403 and not payload["ok"], "VIEWER reviewed a detection")
        status, _headers, payload = client.request(
            "POST",
            review_path,
            token=tokens["admin"],
            payload=review_payload,
            idempotency_key="stage35-review-create-001",
        )
        check(
            status == 201 and payload["data"]["disposition"] == "REVIEWED",
            f"authorized detection review failed: status={status}, payload={payload}",
        )
        status, replay_headers, replay_payload = client.request(
            "POST",
            review_path,
            token=tokens["admin"],
            payload=review_payload,
            idempotency_key="stage35-review-create-001",
        )
        check(
            status == 201
            and replay_headers.get("idempotency-replayed") == "true"
            and replay_payload == payload,
            "detection review idempotency replay drifted",
        )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main() -> int:
    validate_contracts()
    with tempfile.TemporaryDirectory(prefix="deltaaegis-v1-stage35-") as raw:
        temporary = Path(raw)
        database = temporary / "stage35.db"
        connection = deltaaegis.connect(database)
        try:
            fixtures = register_fixture_sensors(connection)
            identities = validate_identity_and_jobs(connection, fixtures, temporary)
            result_id = validate_detection(connection, identities, fixtures["actor"])
            validate_trueaegis_identity(connection, identities, temporary)
            validate_operations(connection, database)
            connection.commit()
        finally:
            connection.close()
        validate_http(database, temporary, result_id, identities["alpha_scope_id"])
        verification = sqlite3.connect(database)
        try:
            check(
                verification.execute("PRAGMA quick_check").fetchone()[0] == "ok",
                "final fixture database quick_check failed",
            )
            check(
                verification.execute("PRAGMA foreign_key_check").fetchall() == [],
                "final fixture database has foreign-key violations",
            )
        finally:
            verification.close()
    print(
        "[PASS] v1 Stages 3–5: sensor/scope isolation, evidence conflict and "
        "ordering controls, per-sensor concurrency, deterministic immutable "
        "detections, append-only reviews, stable authorized APIs, readiness, "
        "diagnostics, low-resource operation, and pinned integrations"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValidationFailure, ValueError, sqlite3.Error) as exc:
        print(f"[FAIL] v1 Stages 3–5: {exc}", file=sys.stderr)
        raise SystemExit(1)
