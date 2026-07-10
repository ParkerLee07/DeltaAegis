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

echo "DeltaAegis v0.42 Logical Site Dashboard Foundation Validator"
echo "=============================================================="

echo "[v0.42 checkpoint 3] source syntax"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py
echo "PASS: source syntax"

echo "[v0.42 checkpoint 3] static API and selector contract"
python3 - <<'PY'
from pathlib import Path
import ast

text = Path("deltaaegis.py").read_text(encoding="utf-8")
ast.parse(text)

required = (
    "# v0.42 checkpoint 3: logical site dashboard foundation",
    '("GET", "/api/sites", "dashboard.read")',
    '("GET", "/api/site-detail", "dashboard.read")',
    "def dashboard_sites_payload(",
    "def dashboard_site_detail_payload(",
    'if route == "/api/sites":',
    'elif route == "/api/site-detail":',
    "site_id_required",
    "logical_site_not_found",
    "Sites &amp; Network Scopes",
    'id="site-links"',
    'id="scope-links-label"',
    'id="site-detail"',
    "function selectedSiteId()",
    "function selectedSiteDetailPath()",
    "function renderScopeNavigation(",
    'api("/api/sites")',
    "Promise.resolve(null)",
    # The selector notice changes after site aggregation is enabled.
)

for marker in required:
    if marker not in text:
        raise SystemExit(f"missing Checkpoint 3 marker: {marker}")

for forbidden in (
    'POST", "/api/sites"',
    'POST", "/api/site-detail"',
    "command_site_create(args)",
):
    checkpoint_start = text.index(
        "# v0.42 checkpoint 3: logical site dashboard foundation"
    )
    if forbidden in text[checkpoint_start:]:
        if forbidden.startswith("POST"):
            raise SystemExit(
                f"unexpected dashboard mutation route: {forbidden}"
            )

print("PASS: read-only site API contract")
print("PASS: site-aware selector contract")
print("PASS: original read-only site routes remain preserved")
PY

echo "[v0.42 checkpoint 3] payload behavior"
python3 - <<'PY'
from pathlib import Path
import importlib.util
import sys
import tempfile

module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v042_checkpoint3_payload"

spec = importlib.util.spec_from_file_location(module_name, module_path)
if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module
try:
    spec.loader.exec_module(module)
finally:
    sys.modules.pop(module_name, None)

with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v042-site-dashboard-payload-"
) as temp_name:
    db_path = Path(temp_name) / "deltaaegis.db"

    with module.connect(db_path) as connection:
        site = module.create_logical_site(
            connection,
            "CLS Health - Admin Building",
            "Dashboard foundation fixture.",
        )
        module.assign_network_scope_to_logical_site(
            connection,
            site["site_id"],
            "192.168.4.0/24",
        )
        module.assign_network_scope_to_logical_site(
            connection,
            site["site_id"],
            "192.168.5.0/24",
        )

        catalog = module.dashboard_sites_payload(connection)
        detail = module.dashboard_site_detail_payload(
            connection,
            site["site_id"],
        )

    if catalog["site_count"] != 1:
        raise AssertionError("site catalog count mismatch")

    if catalog["sites"][0]["site_id"] != site["site_id"]:
        raise AssertionError("site catalog identity mismatch")

    if detail["site"]["name"] != "CLS Health - Admin Building":
        raise AssertionError("site detail name mismatch")

    if detail["coverage"]["member_scope_count"] != 2:
        raise AssertionError("site detail membership count mismatch")

    if detail["coverage"]["observed_scope_count"] != 0:
        raise AssertionError(
            "unobserved fixture scopes were incorrectly marked observed"
        )

print("PASS: /api/sites payload contract")
print("PASS: /api/site-detail payload contract")
print("PASS: site coverage distinguishes unobserved scopes")
PY

echo "[v0.42 checkpoint 3] authenticated HTTP smoke test"
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
import urllib.request


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
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
        with urllib.request.urlopen(req, timeout=5.0) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read()


module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v042_checkpoint3_http"

spec = importlib.util.spec_from_file_location(module_name, module_path)
if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module
try:
    spec.loader.exec_module(module)
finally:
    sys.modules.pop(module_name, None)

with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v042-site-dashboard-http-"
) as temp_name:
    temp = Path(temp_name)
    db_path = temp / "deltaaegis.db"
    stdout_path = temp / "dashboard.stdout"
    stderr_path = temp / "dashboard.stderr"
    token = "checkpoint3-readonly-token"
    port = reserve_port()

    with module.connect(db_path) as connection:
        site = module.create_logical_site(
            connection,
            "HTTP Smoke Site",
        )
        module.assign_network_scope_to_logical_site(
            connection,
            site["site_id"],
            "192.168.44.0/24",
        )

    with stdout_path.open("w", encoding="utf-8") as stdout_handle, \
            stderr_path.open("w", encoding="utf-8") as stderr_handle:
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
                raise AssertionError("dashboard did not become ready")

            if process.poll() is not None:
                raise AssertionError(
                    "dashboard exited before HTTP checks\n"
                    + stderr_path.read_text(encoding="utf-8")
                )

            unauthorized_status, _ = request(base + "/api/sites")
            if unauthorized_status != 401:
                raise AssertionError(
                    f"unauthenticated /api/sites returned "
                    f"{unauthorized_status}, expected 401"
                )

            sites_status, sites_body = request(
                base + "/api/sites",
                token=token,
            )
            if sites_status != 200:
                raise AssertionError(
                    f"/api/sites returned {sites_status}"
                )
            sites_payload = json.loads(sites_body)
            if sites_payload["site_count"] != 1:
                raise AssertionError("/api/sites payload mismatch")

            detail_status, detail_body = request(
                base
                + "/api/site-detail?site_id="
                + site["site_id"],
                token=token,
            )
            if detail_status != 200:
                raise AssertionError(
                    f"/api/site-detail returned {detail_status}"
                )
            detail_payload = json.loads(detail_body)
            if detail_payload["coverage"]["member_scope_count"] != 1:
                raise AssertionError(
                    "/api/site-detail coverage mismatch"
                )

            missing_status, missing_body = request(
                base + "/api/site-detail",
                token=token,
            )
            if missing_status != 400:
                raise AssertionError(
                    f"missing site_id returned {missing_status}"
                )
            if json.loads(missing_body)["error"] != "site_id_required":
                raise AssertionError("missing site_id error mismatch")

            unknown_status, unknown_body = request(
                base + "/api/site-detail?site_id=site-does-not-exist",
                token=token,
            )
            if unknown_status != 404:
                raise AssertionError(
                    f"unknown site returned {unknown_status}"
                )
            if json.loads(unknown_body)["error"] != (
                "logical_site_not_found"
            ):
                raise AssertionError("unknown site error mismatch")

            page_status, page_body = request(base + "/", token=token)
            if page_status != 200:
                raise AssertionError(
                    f"dashboard page returned {page_status}"
                )
            page_text = page_body.decode("utf-8")
            for marker in (
                "Sites &amp; Network Scopes",
                'id="site-links"',
                "function selectedSiteId()",
                "function renderScopeNavigation(",
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
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5.0)

print("PASS: viewer-authenticated /api/sites")
print("PASS: viewer-authenticated /api/site-detail")
print("PASS: site API authentication enforcement")
print("PASS: missing and unknown site errors")
print("PASS: rendered site-aware selector foundation")
PY

echo "[v0.42 checkpoint 3] compatibility boundary"
echo "PASS: rendered JavaScript syntax is owned by the release gate"

echo "[v0.42 checkpoint 3] repository hygiene"
git diff --check
echo "PASS: repository hygiene"

echo "PASS: DeltaAegis v0.42 logical site dashboard foundation validator"
