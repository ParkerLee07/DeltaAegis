#!/usr/bin/env python3
"""Regression checks for the DeltaAegis v0.42 security/integrity hotfix."""

from __future__ import annotations

import http.client
import importlib.util
import json
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "deltaaegis.py"
FIXTURE = (
    REPO
    / "examples"
    / "demo-emergency-alert"
    / "runs"
    / "20260617-000000-demo-baseline"
)


def load_deltaaegis():
    spec = importlib.util.spec_from_file_location("deltaaegis_hotfix", SOURCE)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load deltaaegis.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


da = load_deltaaegis()


def assert_raises(error_type, function, *args, contains: str = "", **kwargs):
    try:
        function(*args, **kwargs)
    except error_type as exc:
        if contains and contains.lower() not in str(exc).lower():
            raise AssertionError(f"unexpected error: {exc}") from exc
        return exc
    raise AssertionError(f"{error_type.__name__} was not raised")


def test_source_contract() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    required = (
        'DELTAAEGIS_SECURITY_HOTFIX = "2026-07-13.1"',
        "def resolve_bundle_member(",
        "def revoke_dashboard_user_sessions(",
        "def reserve_scan_job_if_idle(",
        "BEGIN IMMEDIATE",
            "dashboard_setup_request_is_local",
            "The dashboard session is invalid or expired.",
            "[REDACTED]",
    )
    for marker in required:
        if marker not in source:
            raise AssertionError(f"missing hotfix source marker: {marker}")

    request_token_body = source.split(
        "        def dashboard_request_token(self):", 1
    )[1].split("        def dashboard_setup_request_is_local", 1)[0]
    if 'query.get("token"' in request_token_body:
        raise AssertionError("query-string dashboard tokens are still accepted")

    for name in (
        "validate_v0_39_dashboard_http_smoke.py",
        "validate_v0_39_dashboard_cancellation_http_smoke.py",
        "validate_v0_39_schedule_deletion_http_smoke.py",
        "validate_v0_39_cancellation_api.py",
    ):
        text = (REPO / "tools" / name).read_text(encoding="utf-8")
        if 'REPO = Path.home() / "DeltaAegis"' in text:
            raise AssertionError(f"validator still depends on $HOME/DeltaAegis: {name}")
        if "Path(__file__).resolve().parents[1]" not in text:
            raise AssertionError(f"validator does not resolve its checkout: {name}")


def test_rfc1918_boundary() -> None:
    accepted = {
        "10.0.0.0/8": "10.0.0.0/8",
        "172.20.4.0/24": "172.20.4.0/24",
        "192.168.40.9/24": "192.168.40.0/24",
    }
    for raw, expected in accepted.items():
        actual = da.validate_private_cidr(raw)
        if actual != expected:
            raise AssertionError(f"RFC1918 normalization mismatch: {raw} -> {actual}")

    for raw in (
        "127.0.0.0/8",
        "169.254.0.0/16",
        "192.0.2.0/24",
        "0.0.0.0/8",
        "8.8.8.0/24",
        "10.0.0.0/7",
    ):
        assert_raises(da.DeltaAegisError, da.validate_private_cidr, raw)


def copy_fixture(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for path in FIXTURE.iterdir():
        if path.is_file():
            shutil.copy2(path, destination / path.name)


def test_bundle_quality_and_confinement() -> None:
    with tempfile.TemporaryDirectory(prefix="deltaaegis-hotfix-bundle-") as tmp:
        root = Path(tmp)

        missing_quality = root / "missing-quality"
        copy_fixture(missing_quality)
        manifest_path = missing_quality / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["schema_version"] = "netsniper-run-v3"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        assert_raises(
            da.DeltaAegisError,
            da.load_snapshot,
            manifest_path,
            contains="requires bundle_quality.json schema",
        )

        valid_quality = root / "valid-quality"
        copy_fixture(valid_quality)
        manifest_path = valid_quality / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["schema_version"] = "netsniper-run-v3"
        manifest.setdefault("files", {})["bundle_quality_json"] = "bundle_quality.json"
        (valid_quality / "bundle_quality.json").write_text(
            json.dumps(
                {
                    "schema_version": "netsniper-bundle-quality-v1",
                    "deltaaegis_ready": True,
                }
            ),
            encoding="utf-8",
        )
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        snapshot = da.load_snapshot(manifest_path)
        if snapshot.bundle_deltaaegis_ready is not True:
            raise AssertionError("valid v3 readiness was not preserved")
        if da.assess_quality(snapshot, None)[0] != "ACCEPTED":
            raise AssertionError("valid v3 bundle was not accepted")

        bundle = root / "confined-bundle"
        outside = root / "outside"
        copy_fixture(outside)
        bundle.mkdir()
        manifest = json.loads((outside / "manifest.json").read_text(encoding="utf-8"))
        manifest["files"] = {
            key: f"../outside/{value}"
            for key, value in manifest["files"].items()
        }
        escaped_manifest = bundle / "manifest.json"
        escaped_manifest.write_text(json.dumps(manifest), encoding="utf-8")
        assert_raises(
            da.DeltaAegisError,
            da.load_snapshot,
            escaped_manifest,
            contains="escapes the immutable bundle boundary",
        )


def test_session_revocation_and_live_role() -> None:
    with tempfile.TemporaryDirectory(prefix="deltaaegis-hotfix-session-") as tmp:
        connection = da.connect(Path(tmp) / "audit.db")
        first = da.create_access_user(
            connection,
            "admin.one",
            role="ADMIN",
            password="Password123!",
        )
        da.create_access_user(
            connection,
            "admin.two",
            role="ADMIN",
            password="Password123!",
        )
        connection.commit()

        issued = da.dashboard_user_login(connection, "admin.one", "Password123!")
        connection.execute(
            "UPDATE access_users SET role = 'VIEWER' WHERE user_id = ?",
            (first["user_id"],),
        )
        connection.commit()
        if da.authenticate_dashboard_session(
            connection,
            issued["session_token"],
            required_role="ADMIN",
            update_last_seen=False,
        ) is not None:
            raise AssertionError("session retained ADMIN after current user role changed")
        viewer = da.authenticate_dashboard_session(
            connection,
            issued["session_token"],
            required_role="VIEWER",
            update_last_seen=False,
        )
        if not viewer or viewer["role"] != "VIEWER":
            raise AssertionError("session did not use the current user role")

        connection.execute(
            "UPDATE access_users SET role = 'ADMIN' WHERE user_id = ?",
            (first["user_id"],),
        )
        connection.commit()
        demoted_session = da.dashboard_user_login(
            connection, "admin.one", "Password123!"
        )
        da.dashboard_admin_set_user_role(
            connection,
            "admin.one",
            {"role": "VIEWER"},
            {"username": "admin.two", "role": "ADMIN"},
        )
        connection.commit()
        if da.authenticate_dashboard_session(
            connection, demoted_session["session_token"], update_last_seen=False
        ) is not None:
            raise AssertionError("role change did not revoke the existing session")

        password_session = da.dashboard_user_login(
            connection, "admin.one", "Password123!"
        )
        da.dashboard_admin_rotate_user_password(
            connection,
            "admin.one",
            {"password": "Changed123!"},
            {"username": "admin.two", "role": "ADMIN"},
        )
        connection.commit()
        if da.authenticate_dashboard_session(
            connection, password_session["session_token"], update_last_seen=False
        ) is not None:
            raise AssertionError("password rotation did not revoke the existing session")

        disabled_session = da.dashboard_user_login(
            connection, "admin.one", "Changed123!"
        )
        da.dashboard_admin_set_user_enabled(
            connection,
            "admin.one",
            False,
            {"username": "admin.two", "role": "ADMIN"},
        )
        connection.commit()
        da.dashboard_admin_set_user_enabled(
            connection,
            "admin.one",
            True,
            {"username": "admin.two", "role": "ADMIN"},
        )
        connection.commit()
        if da.authenticate_dashboard_session(
            connection, disabled_session["session_token"], update_last_seen=False
        ) is not None:
            raise AssertionError("a disabled user's old session revived after re-enable")
        connection.close()


def test_atomic_scan_reservation() -> None:
    with tempfile.TemporaryDirectory(prefix="deltaaegis-hotfix-scan-") as tmp:
        db_path = Path(tmp) / "audit.db"
        da.connect(db_path).close()
        barrier = threading.Barrier(2)
        results: list[str] = []
        results_lock = threading.Lock()

        def reserve(target: str) -> None:
            connection = da.connect(db_path)
            barrier.wait()
            try:
                da.reserve_scan_job_if_idle(
                    connection,
                    target,
                    Path(tmp) / "netsniper.sh",
                    Path(tmp) / "runs",
                )
                outcome = "created"
            except da.ActiveScanJobExistsError:
                outcome = "blocked"
            finally:
                connection.close()
            with results_lock:
                results.append(outcome)

        threads = [
            threading.Thread(target=reserve, args=("192.168.10.0/24",)),
            threading.Thread(target=reserve, args=("192.168.11.0/24",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            if thread.is_alive():
                raise AssertionError("scan reservation thread did not finish")

        if sorted(results) != ["blocked", "created"]:
            raise AssertionError(f"unexpected scan reservation results: {results}")
        connection = da.connect(db_path)
        active_count = connection.execute(
            "SELECT COUNT(*) FROM scan_jobs WHERE status IN ('QUEUED', 'RUNNING')"
        ).fetchone()[0]
        connection.close()
        if active_count != 1:
            raise AssertionError(f"expected one active scan job, found {active_count}")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(
    port: int,
    method: str,
    path: str,
    *,
    body: str | bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    data = response.read()
    response_headers = {key.lower(): value for key, value in response.getheaders()}
    status = int(response.status)
    connection.close()
    return status, response_headers, data


def test_dashboard_http_boundaries() -> None:
    with tempfile.TemporaryDirectory(prefix="deltaaegis-hotfix-http-") as tmp:
        root = Path(tmp)
        port = free_port()
        db_path = root / "audit.db"
        stderr_path = root / "dashboard.stderr.log"
        stdout_path = root / "dashboard.stdout.log"
        token = "hotfix-header-token"
        command = [
            sys.executable,
            str(SOURCE),
            "--db",
            str(db_path),
            "--events",
            str(root / "events.jsonl"),
            "dashboard",
            "--lan",
            "--port",
            str(port),
            "--token",
            token,
            "--no-enable-scheduled-scans",
        ]

        with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
            process = subprocess.Popen(
                command,
                cwd=REPO,
                stdout=stdout_file,
                stderr=stderr_file,
            )
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise AssertionError("dashboard exited before becoming healthy")
                    try:
                        if request(port, "GET", "/healthz")[0] == 200:
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise AssertionError("dashboard did not become healthy")

                status, _, _ = request(
                    port,
                    "GET",
                    f"/api/session?token={urllib.parse.quote(token)}",
                )
                if status != 401:
                    raise AssertionError(f"query-string token returned HTTP {status}")

                status, _, _ = request(
                    port,
                    "GET",
                    "/api/session",
                    headers={"X-DeltaAegis-Token": token},
                )
                if status != 200:
                    raise AssertionError(f"header token returned HTTP {status}")

                status, response_headers, payload = request(
                    port,
                    "GET",
                    "/api/session",
                    headers={"Cookie": "deltaaegis_session=invalid-session"},
                )
                if status != 401 or b"invalid or expired" not in payload:
                    raise AssertionError("invalid session cookie did not receive JSON 401")
                if "max-age=0" not in response_headers.get("set-cookie", "").lower():
                    raise AssertionError("invalid session cookie was not cleared")

                status, _, _ = request(
                    port,
                    "GET",
                    "/api/netsniper/schedule-history?limit=abc",
                    headers={"X-DeltaAegis-Token": token},
                )
                if status != 200:
                    raise AssertionError(f"invalid limit returned HTTP {status}")

                login_body = urllib.parse.urlencode(
                    {"username": "x", "password": "irrelevant"}
                )
                status, _, _ = request(
                    port,
                    "POST",
                    "/login",
                    body=login_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                if status != 200:
                    raise AssertionError(f"invalid login input returned HTTP {status}")

                status, _, _ = request(port, "GET", "/operator")
                if status != 303:
                    raise AssertionError(f"unauthenticated /operator returned HTTP {status}")

                status, _, setup_html = request(port, "GET", "/setup")
                if status != 200:
                    raise AssertionError(f"local setup GET returned HTTP {status}")
                match = re.search(
                    rb'name="setup_nonce" value="([^"]+)"',
                    setup_html,
                )
                if not match:
                    raise AssertionError("setup nonce was not rendered")
                nonce = match.group(1).decode("ascii")

                setup_fields = {
                    "username": "admin.one",
                    "display_name": "Admin One",
                    "password": "Password123!",
                    "password_confirm": "Password123!",
                }
                status, _, _ = request(
                    port,
                    "POST",
                    "/setup",
                    body=urllib.parse.urlencode(setup_fields),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                if status != 403:
                    raise AssertionError(f"LAN setup without nonce returned HTTP {status}")

                setup_fields["setup_nonce"] = nonce
                status, _, _ = request(
                    port,
                    "POST",
                    "/setup",
                    body=urllib.parse.urlencode(setup_fields),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                if status != 303:
                    raise AssertionError(f"verified local setup returned HTTP {status}")

                connection = sqlite3.connect(db_path)
                users = connection.execute(
                    "SELECT username, role FROM access_users"
                ).fetchall()
                connection.close()
                if users != [("admin.one", "ADMIN")]:
                    raise AssertionError(f"unexpected first-admin rows: {users}")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

        stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
        if "Traceback" in stderr_text or "Exception occurred" in stderr_text:
            raise AssertionError(f"dashboard emitted a request traceback:\n{stderr_text}")
        if token in stderr_text:
            raise AssertionError("dashboard access log exposed a query-string token")
        if "token=[REDACTED]" not in stderr_text:
            raise AssertionError("dashboard access log did not redact the query token")


def main() -> int:
    print("DeltaAegis v0.42 Security/Integrity Hotfix Validator")
    print("=====================================================")
    checks = (
        ("source and validator portability", test_source_contract),
        ("RFC1918 scan boundary", test_rfc1918_boundary),
        ("bundle readiness and confinement", test_bundle_quality_and_confinement),
        ("session privilege revocation", test_session_revocation_and_live_role),
        ("atomic scan reservation", test_atomic_scan_reservation),
        ("dashboard HTTP boundaries", test_dashboard_http_boundaries),
    )
    for label, check in checks:
        check()
        print(f"PASS: {label}")
    print("PASS: DeltaAegis v0.42 security/integrity hotfix")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
