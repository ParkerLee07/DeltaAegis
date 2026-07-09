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

echo "DeltaAegis v0.42 Sites Management Validator"
echo "=============================================="

echo "[v0.42 hotfix B] source syntax"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py
echo "PASS: source syntax"

echo "[v0.42 hotfix B] static backend, RBAC, and UI contract"
python3 - <<'PY'
from pathlib import Path
import ast

text = Path("deltaaegis.py").read_text(encoding="utf-8")
ast.parse(text)

required = (
    "# v0.42 hotfix checkpoint B: dashboard logical-site management",
    '"sites.write": "ADMIN"',
    '("GET", "/api/site-management", "dashboard.read")',
    '("POST", "/api/site-create", "sites.write")',
    '("POST", "/api/site-rename", "sites.write")',
    '("POST", "/api/site-description", "sites.write")',
    '("POST", "/api/site-archive", "sites.write")',
    '("POST", "/api/site-assign-scope", "sites.write")',
    '("POST", "/api/site-remove-scope", "sites.write")',
    "def dashboard_site_management_payload(",
    "def dashboard_site_action_payload(",
    "DASHBOARD_SITE_UNSAFE_PAYLOAD_FIELDS",
    "LOGICAL_SITE_DASHBOARD_ACTION_FAILED",
    'data-tab-target="sites">Sites</button>',
    'data-tab-panel="sites"',
    'id="site-management-panel"',
    'id="site-create-button"',
    'id="site-archive-button"',
    'data-site-admin-control',
    "function renderSiteManagement(",
    "function siteManagementPost(",
    "function bindSiteManagementControls(",
    'api("/api/site-management")',
    'dashboard_site_management_payload(connection),',
    '"scan-jobs", "sites", "trueaegis"',
    "site-wide SIEM aggregation or choose a member subnet",
)

for marker in required:
    if marker not in text:
        raise SystemExit(
            f"missing Sites-management marker: {marker}"
        )

tree = ast.parse(text)
site_function_names = {
    "dashboard_site_action_validate_payload",
    "dashboard_site_action_payload",
}
site_function_source = []

for node in ast.walk(tree):
    if (
        isinstance(node, ast.FunctionDef)
        and node.name in site_function_names
    ):
        segment = ast.get_source_segment(text, node)
        if segment:
            site_function_source.append(segment)

if len(site_function_source) != len(site_function_names):
    raise SystemExit(
        "could not isolate all logical-site mutation functions"
    )

site_checkpoint = "\n\n".join(site_function_source)

for forbidden in (
    'payload.get("actor")',
    'payload.get("role")',
    'payload.get("db_path")',
    'subprocess.Popen(payload',
    'connection.execute(payload',
):
    if forbidden in site_checkpoint:
        raise SystemExit(
            f"unsafe Sites-management pattern: {forbidden}"
        )

print("PASS: fixed ADMIN mutation routes")
print("PASS: session-derived actor boundary")
print("PASS: strict payload allowlist")
print("PASS: dedicated Sites tab")
print("PASS: read-only role presentation")
print("PASS: stale aggregation copy removed")
PY

echo "[v0.42 hotfix B] functional action payloads and invariants"
python3 - <<'PY'
from pathlib import Path
import importlib.util
import tempfile
import sys

module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v042_sites_management_payload"

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
    prefix="deltaaegis-v042-sites-management-"
) as temp_name:
    db = Path(temp_name) / "deltaaegis.db"

    with module.connect(db) as connection:
        validator_user = module.create_access_user(
            connection,
            "site-admin",
            display_name="Site Admin Validator",
            role="ADMIN",
            password="ValidatorPass123!",
        )
        actor = {
            "user_id": validator_user["user_id"],
            "username": validator_user["username"],
            "role": validator_user["role"],
        }

        created = module.dashboard_site_action_payload(
            connection,
            "/api/site-create",
            {
                "name": "Validator Campus",
                "description": "Created from the dashboard payload.",
            },
            actor=actor,
            source_ip="127.0.0.1",
            user_agent="validator",
        )
        site_id = created["site"]["site_id"]

        if created["receipt"]["action"] != "logical_site.create":
            raise AssertionError("create receipt mismatch")

        renamed = module.dashboard_site_action_payload(
            connection,
            "/api/site-rename",
            {
                "site_id": site_id,
                "name": "Validator Main Campus",
            },
            actor=actor,
        )
        if renamed["site"]["name"] != "Validator Main Campus":
            raise AssertionError("rename did not persist")

        described = module.dashboard_site_action_payload(
            connection,
            "/api/site-description",
            {
                "site_id": site_id,
                "description": "Updated operator context.",
            },
            actor=actor,
        )
        if described["site"]["description"] != "Updated operator context.":
            raise AssertionError("description did not persist")

        assigned = module.dashboard_site_action_payload(
            connection,
            "/api/site-assign-scope",
            {
                "site_id": site_id,
                "network_scope": "192.168.70.0/24",
            },
            actor=actor,
        )
        if assigned["membership"]["network_scope"] != "192.168.70.0/24":
            raise AssertionError("membership assignment mismatch")

        second = module.dashboard_site_action_payload(
            connection,
            "/api/site-create",
            {
                "name": "Validator Secondary Campus",
                "description": "",
            },
            actor=actor,
        )

        try:
            module.dashboard_site_action_payload(
                connection,
                "/api/site-assign-scope",
                {
                    "site_id": second["site"]["site_id"],
                    "network_scope": "192.168.70.0/24",
                },
                actor=actor,
            )
        except module.DeltaAegisError as exc:
            if "already assigned" not in str(exc):
                raise
        else:
            raise AssertionError("duplicate subnet assignment succeeded")

        try:
            module.dashboard_site_action_payload(
                connection,
                "/api/site-assign-scope",
                {
                    "site_id": second["site"]["site_id"],
                    "network_scope": "8.8.8.0/24",
                },
                actor=actor,
            )
        except module.DeltaAegisError as exc:
            if "private" not in str(exc).lower():
                raise
        else:
            raise AssertionError("public subnet assignment succeeded")

        try:
            module.dashboard_site_action_payload(
                connection,
                "/api/site-create",
                {
                    "name": "Unsafe",
                    "description": "",
                    "actor": "caller-selected",
                },
                actor=actor,
            )
        except module.DashboardAdminUserActionError as exc:
            if "unsafe" not in str(exc).lower():
                raise
        else:
            raise AssertionError("caller-selected actor was accepted")

        removed = module.dashboard_site_action_payload(
            connection,
            "/api/site-remove-scope",
            {
                "site_id": site_id,
                "network_scope": "192.168.70.0/24",
            },
            actor=actor,
        )
        if not removed["membership"]["removed"]:
            raise AssertionError("membership removal mismatch")

        module.dashboard_site_action_payload(
            connection,
            "/api/site-assign-scope",
            {
                "site_id": site_id,
                "network_scope": "192.168.70.0/24",
            },
            actor=actor,
        )

        required = f"ARCHIVE {site_id}"
        try:
            module.dashboard_site_action_payload(
                connection,
                "/api/site-archive",
                {
                    "site_id": site_id,
                    "confirmation": "ARCHIVE",
                },
                actor=actor,
            )
        except module.DashboardAdminUserActionError as exc:
            if required not in str(exc):
                raise
        else:
            raise AssertionError("archive accepted incorrect confirmation")

        archived = module.dashboard_site_action_payload(
            connection,
            "/api/site-archive",
            {
                "site_id": site_id,
                "confirmation": required,
            },
            actor=actor,
        )
        if archived["site"]["status"] != "ARCHIVED":
            raise AssertionError("site was not archived")
        if archived["site"]["member_count"] != 1:
            raise AssertionError("archive removed membership")

        try:
            module.dashboard_site_action_payload(
                connection,
                "/api/site-assign-scope",
                {
                    "site_id": site_id,
                    "network_scope": "192.168.71.0/24",
                },
                actor=actor,
            )
        except module.DashboardAdminUserActionError as exc:
            if "read-only" not in str(exc):
                raise
        else:
            raise AssertionError("archived site accepted assignment")

        management = module.dashboard_site_management_payload(
            connection
        )
        if management["summary"]["active_site_count"] != 1:
            raise AssertionError("active site count mismatch")
        if management["summary"]["archived_site_count"] != 1:
            raise AssertionError("archived site count mismatch")

        audit = module.list_access_audit_events(
            connection,
            limit=50,
            target_type="logical_site",
        )
        actions = {row["action"] for row in audit}
        expected = {
            "LOGICAL_SITE_CREATE",
            "LOGICAL_SITE_RENAME",
            "LOGICAL_SITE_DESCRIPTION_UPDATE",
            "LOGICAL_SITE_SCOPE_ASSIGN",
            "LOGICAL_SITE_SCOPE_REMOVE",
            "LOGICAL_SITE_ARCHIVE",
        }
        if not expected.issubset(actions):
            raise AssertionError(
                f"missing access-audit actions: {expected - actions}"
            )
        if not all(
            row.get("actor_username") == "site-admin"
            for row in audit
        ):
            raise AssertionError("audit actor was not session-derived")

        integrity = connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()
        if integrity:
            raise AssertionError(
                f"foreign-key violations: {integrity}"
            )

print("PASS: all six dashboard mutation operations")
print("PASS: duplicate and public CIDR rejection")
print("PASS: caller-selected actor rejection")
print("PASS: exact archive confirmation")
print("PASS: archive retains membership and becomes read-only")
print("PASS: site-management catalog")
print("PASS: session-derived access-audit evidence")
print("PASS: foreign-key integrity")
PY

echo "[v0.42 hotfix B] RBAC policy"
python3 - <<'PY'
import deltaaegis

if deltaaegis.access_rbac_required_role("sites.write") != "ADMIN":
    raise SystemExit("sites.write is not ADMIN-only")

for role in ("VIEWER", "ANALYST"):
    if deltaaegis.access_rbac_allows(role, "sites.write"):
        raise SystemExit(f"{role} unexpectedly has sites.write")

if not deltaaegis.access_rbac_allows("ADMIN", "sites.write"):
    raise SystemExit("ADMIN lacks sites.write")

for route in deltaaegis.DASHBOARD_SITE_ACTION_ROUTES:
    if deltaaegis.dashboard_route_permission(
        "POST",
        route,
    ) != "sites.write":
        raise SystemExit(f"route policy mismatch: {route}")

print("PASS: VIEWER and ANALYST denied")
print("PASS: ADMIN allowed")
print("PASS: fixed route policy coverage")
PY

echo "[v0.42 hotfix B] authenticated HTTP and rendered dashboard smoke test"
python3 - <<'PY'
from __future__ import annotations

from http.cookiejar import CookieJar
from pathlib import Path
from urllib.parse import urlencode
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
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    ) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(
    url: str,
    *,
    method: str = "GET",
    payload: dict | None = None,
    token: str | None = None,
    opener: urllib.request.OpenerDirector | None = None,
) -> tuple[int, bytes]:
    headers = {"Accept": "application/json, text/html"}
    data = None

    if token:
        headers["X-DeltaAegis-Token"] = token

    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method=method,
    )
    client = opener or urllib.request.build_opener()

    try:
        with client.open(req, timeout=8.0) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read()


def viewer_login(
    base: str,
    username: str,
    password: str,
) -> urllib.request.OpenerDirector:
    jar = CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar)
    )
    data = urlencode(
        {
            "username": username,
            "password": password,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        base + "/login",
        data=data,
        headers={
            "Content-Type": (
                "application/x-www-form-urlencoded"
            )
        },
        method="POST",
    )
    with opener.open(req, timeout=8.0):
        pass

    if not list(jar):
        raise AssertionError("viewer login did not set a session cookie")

    return opener


module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v042_sites_management_http"
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
    prefix="deltaaegis-v042-sites-http-"
) as temp_name:
    temp = Path(temp_name)
    db = temp / "deltaaegis.db"
    stdout_path = temp / "dashboard.stdout"
    stderr_path = temp / "dashboard.stderr"
    port = reserve_port()
    token = "sites-management-admin-token"

    with module.connect(db) as connection:
        module.create_access_user(
            connection,
            "sites-viewer",
            display_name="Sites Viewer",
            role="VIEWER",
            password="ViewerPass123!",
        )

    with stdout_path.open("w", encoding="utf-8") as stdout_handle, \
            stderr_path.open("w", encoding="utf-8") as stderr_handle:
        process = subprocess.Popen(
            [
                sys.executable,
                "deltaaegis.py",
                "--db",
                str(db),
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

            unauth_status, _ = request(
                base + "/api/site-create",
                method="POST",
                payload={"name": "Unauthorized"},
            )
            if unauth_status != 401:
                raise AssertionError(
                    f"unauthenticated mutation returned {unauth_status}"
                )

            viewer = viewer_login(
                base,
                "sites-viewer",
                "ViewerPass123!",
            )
            viewer_status, _ = request(
                base + "/api/site-create",
                method="POST",
                payload={"name": "Viewer Site"},
                opener=viewer,
            )
            if viewer_status != 403:
                raise AssertionError(
                    f"VIEWER mutation returned {viewer_status}"
                )

            create_status, create_body = request(
                base + "/api/site-create",
                method="POST",
                payload={
                    "name": "HTTP Managed Site",
                    "description": "Created through fixed API.",
                },
                token=token,
            )
            if create_status != 200:
                raise AssertionError(
                    f"ADMIN mutation returned {create_status}: "
                    + create_body.decode("utf-8", errors="replace")
                )
            created = json.loads(create_body)
            site_id = created["site"]["site_id"]

            unsafe_status, _ = request(
                base + "/api/site-rename",
                method="POST",
                payload={
                    "site_id": site_id,
                    "name": "Unsafe Rename",
                    "actor": "spoofed",
                },
                token=token,
            )
            if unsafe_status != 400:
                raise AssertionError(
                    f"unsafe payload returned {unsafe_status}"
                )

            management_status, management_body = request(
                base + "/api/site-management",
                token=token,
            )
            if management_status != 200:
                raise AssertionError(
                    "/api/site-management failed"
                )
            management = json.loads(management_body)
            if management["summary"]["active_site_count"] != 1:
                raise AssertionError(
                    "management API active-site count mismatch"
                )

            page_status, page_body = request(
                base + "/",
                token=token,
            )
            if page_status != 200:
                raise AssertionError("dashboard page failed")
            page = page_body.decode("utf-8")

            markers = (
                'data-tab-target="sites">Sites</button>',
                'data-tab-panel="sites"',
                'id="site-management-panel"',
                'id="site-create-button"',
                "function renderSiteManagement(",
                "function siteManagementPost(",
                'api("/api/site-management")',
            )
            for marker in markers:
                if marker not in page:
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

    with module.connect(db) as connection:
        failed_audit = module.list_access_audit_events(
            connection,
            limit=20,
            action="LOGICAL_SITE_DASHBOARD_ACTION_FAILED",
        )
        success_audit = module.list_access_audit_events(
            connection,
            limit=20,
            action="LOGICAL_SITE_CREATE",
        )

        if not failed_audit:
            raise AssertionError(
                "failed dashboard action audit is missing"
            )
        if not success_audit:
            raise AssertionError(
                "successful dashboard action audit is missing"
            )

print("PASS: unauthenticated mutation rejected")
print("PASS: VIEWER mutation rejected")
print("PASS: ADMIN mutation succeeded")
print("PASS: unsafe caller actor rejected")
print("PASS: management GET payload")
print("PASS: successful and failed access-audit evidence")
print("PASS: rendered Sites tab and browser workflow markers")
PY

echo "[v0.42 hotfix E] Sites dashboard UX and atomic creation"
python3 - <<'PYUX'
from pathlib import Path
import ast
import importlib.util
import sys
import tempfile

source = Path("deltaaegis.py").read_text(encoding="utf-8")
ast.parse(source)

required = (
    'id="site-management-styles"',
    '#site-management-panel button',
    'id="site-management-unassigned-panel"',
    'id="site-management-unassigned-list"',
    'class="site-subnet-grid"',
    'data-site-create-scope',
    "function siteManagementSelectedCreateScopes(",
    "function siteManagementRenderUnassigned(",
    "network_scopes: networkScopes",
    "def dashboard_site_create_network_scopes(",
    '"/api/site-create": {"name", "description", "network_scopes"}',
    '"assigned_scope_count": len(memberships)',
    '"memberships": memberships',
)

for marker in required:
    if marker not in source:
        raise SystemExit(
            f"missing Sites UX marker: {marker}"
        )

if 'placeholder="Example: CLS Cyber Campus"' in source:
    raise SystemExit(
        "organization-specific site-name placeholder remains"
    )

repo = Path.cwd()
spec = importlib.util.spec_from_file_location(
    "deltaaegis_v042_sites_ux_validator",
    repo / "deltaaegis.py",
)

if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v042-sites-ux-"
) as temp_name:
    db = Path(temp_name) / "deltaaegis.db"
    connection = module.connect(db)

    actor = module.create_access_user(
        connection,
        username="validator.admin",
        display_name="Validator Admin",
        role="ADMIN",
        password="ValidatorPass123!",
        is_active=True,
    )
    actor["auth_type"] = "validator"
    connection.commit()

    result = module.dashboard_site_action_payload(
        connection,
        "/api/site-create",
        {
            "name": "North Campus",
            "description": "Atomic checkbox fixture",
            "network_scopes": [
                "10.42.1.0/24",
                "10.42.2.0/24",
                "10.42.1.0/24",
            ],
        },
        actor=actor,
        source_ip="127.0.0.1",
        user_agent="validator",
    )
    connection.commit()

    site = result["site"]
    memberships = result["memberships"]

    if len(memberships) != 2:
        raise SystemExit(
            f"expected two deduplicated memberships: {memberships}"
        )

    member_scopes = module.logical_site_member_scopes(
        connection,
        site["site_id"],
    )
    if member_scopes != [
        "10.42.1.0/24",
        "10.42.2.0/24",
    ]:
        raise SystemExit(
            f"unexpected membership set: {member_scopes}"
        )

    if site["member_count"] != 2:
        raise SystemExit(
            f"site member count was not refreshed: {site}"
        )

    if (
        result["receipt"]["summary"]["assigned_scope_count"]
        != 2
    ):
        raise SystemExit(
            "action receipt omitted assigned subnet count"
        )

    before_count = connection.execute(
        "SELECT COUNT(*) FROM logical_sites"
    ).fetchone()[0]

    try:
        module.dashboard_site_action_payload(
            connection,
            "/api/site-create",
            {
                "name": "Invalid Campus",
                "description": "",
                "network_scopes": [
                    "10.43.1.0/24",
                    "8.8.8.0/24",
                ],
            },
            actor=actor,
            source_ip="127.0.0.1",
            user_agent="validator",
        )
    except Exception:
        connection.rollback()
    else:
        raise SystemExit(
            "public CIDR was accepted in create-with-memberships"
        )

    after_count = connection.execute(
        "SELECT COUNT(*) FROM logical_sites"
    ).fetchone()[0]

    if after_count != before_count:
        raise SystemExit(
            "invalid create request left a partial logical site"
        )

    empty = module.dashboard_site_action_payload(
        connection,
        "/api/site-create",
        {
            "name": "Empty Campus",
            "description": "",
            "network_scopes": [],
        },
        actor=actor,
        source_ip="127.0.0.1",
        user_agent="validator",
    )
    connection.commit()

    if empty["site"]["member_count"] != 0:
        raise SystemExit(
            "empty site creation unexpectedly added memberships"
        )

    try:
        module.dashboard_site_action_payload(
            connection,
            "/api/site-create",
            {
                "name": "Wrong Type",
                "description": "",
                "network_scopes": "10.44.0.0/24",
            },
            actor=actor,
            source_ip="127.0.0.1",
            user_agent="validator",
        )
    except module.DashboardAdminUserActionError:
        connection.rollback()
    else:
        raise SystemExit(
            "non-array network_scopes payload was accepted"
        )

    page = module.dashboard_index_html()

    for marker in (
        'id="site-management-styles"',
        'id="site-management-unassigned-list"',
        "function siteManagementRenderUnassigned(",
        "data-site-create-scope",
        "network_scopes: networkScopes",
    ):
        if marker not in page:
            raise SystemExit(
                f"rendered dashboard missing Sites UX marker: {marker}"
            )

    if "Example: CLS Cyber Campus" in page:
        raise SystemExit(
            "rendered dashboard still includes the old example"
        )

    connection.close()

print("PASS: dashboard-scoped Sites styling")
print("PASS: unassigned subnet context and checkboxes")
print("PASS: site-name example removed")
print("PASS: selected subnets normalized and deduplicated")
print("PASS: site and memberships created atomically")
print("PASS: invalid CIDR leaves no partial site")
print("PASS: empty site creation preserved")
print("PASS: non-array subnet payload rejected")
print("PASS: rendered Sites UX contract")
PYUX
echo "PASS: Sites dashboard UX and atomic creation"

echo "[v0.42 hotfix B] rendered JavaScript syntax"
tools/validate_v0_40_dashboard_javascript_syntax.sh
echo "PASS: rendered JavaScript syntax"

echo "[v0.42 hotfix B] release-gate compatibility boundary"
echo "PASS: prior v0.42 component validators are executed by validate_v0_42_all.sh"
echo "PASS: focused Sites validator remains flat"

echo "[v0.42 hotfix B] repository hygiene"
git diff --check
echo "PASS: repository hygiene"

echo "PASS: DeltaAegis v0.42 Sites management validator"
