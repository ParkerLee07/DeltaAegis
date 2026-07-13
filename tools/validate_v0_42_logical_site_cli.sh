#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

branch="$(git branch --show-current)"
case "$branch" in
  feature/v0.42-logical-site-scopes|release/v0.42.1|release/v0.42.2|main)
    ;;
  *)
    echo "FAIL: unexpected branch $branch"
    exit 1
    ;;
esac

echo "DeltaAegis v0.42 Logical Site CLI Validator"
echo "============================================="

echo "[v0.42 checkpoint 2] source syntax"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py
echo "PASS: source syntax"

echo "[v0.42 checkpoint 2] static CLI contract"
python3 - <<'PY'
from pathlib import Path
import ast

text = Path("deltaaegis.py").read_text(encoding="utf-8")
tree = ast.parse(text)

required = (
    "# v0.42 checkpoint 2: logical site CLI management",
    "def logical_site_detail_payload(",
    "def logical_site_list_payload(",
    "def command_site_list(",
    "def command_site_show(",
    "def command_site_create(",
    "def command_site_rename(",
    "def command_site_description(",
    "def command_site_archive(",
    "def command_site_assign_scope(",
    "def command_site_remove_scope(",
    "def query_network_scope_catalog(",
    "record_access_audit_event(",
    "LOGICAL_SITE_CREATE",
    "LOGICAL_SITE_RENAME",
    "LOGICAL_SITE_DESCRIPTION_UPDATE",
    "LOGICAL_SITE_ARCHIVE",
    "LOGICAL_SITE_SCOPE_ASSIGN",
    "LOGICAL_SITE_SCOPE_REMOVE",
)

for marker in required:
    if marker not in text:
        raise SystemExit(f"missing logical-site CLI marker: {marker}")

function_names = {
    node.name
    for node in tree.body
    if isinstance(node, ast.FunctionDef)
}

for function_name in (
    "command_site_list",
    "command_site_show",
    "command_site_create",
    "command_site_rename",
    "command_site_description",
    "command_site_archive",
    "command_site_assign_scope",
    "command_site_remove_scope",
):
    if function_name not in function_names:
        raise SystemExit(f"missing command function: {function_name}")

print("PASS: static logical-site CLI contract")
PY

echo "[v0.42 checkpoint 2] parser and dispatch"
python3 - <<'PY'
from pathlib import Path
import importlib.util
import sys

module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v042_checkpoint2_parser"

spec = importlib.util.spec_from_file_location(module_name, module_path)
if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module
try:
    spec.loader.exec_module(module)
finally:
    sys.modules.pop(module_name, None)

parser = module.build_parser()

cases = {
    "site-list": ["site-list"],
    "site-show": ["site-show", "site-test"],
    "site-create": ["site-create", "Example Building"],
    "site-rename": ["site-rename", "site-test", "New Name"],
    "site-description": [
        "site-description",
        "site-test",
        "Description",
    ],
    "site-archive": ["site-archive", "site-test"],
    "site-assign-scope": [
        "site-assign-scope",
        "site-test",
        "192.168.4.0/24",
    ],
    "site-remove-scope": [
        "site-remove-scope",
        "site-test",
        "192.168.4.0/24",
    ],
}

for expected, argv in cases.items():
    args = parser.parse_args(argv)
    if args.command != expected:
        raise SystemExit(
            f"parser mismatch for {expected}: {args.command}"
        )

scope_args = parser.parse_args(["scopes", "--unassigned", "--json"])
if not scope_args.unassigned or not scope_args.json:
    raise SystemExit("scopes flags did not parse")

print("PASS: all site commands parse")
print("PASS: scopes --unassigned --json parses")
PY

echo "[v0.42 checkpoint 2] functional CLI and JSON behavior"
python3 - <<'PY'
from __future__ import annotations

from pathlib import Path
import json
import sqlite3
import subprocess
import sys
import tempfile


def run_cli(
    db_path: Path,
    *arguments: str,
    expect: int = 0,
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        "deltaaegis.py",
        "--db",
        str(db_path),
        *arguments,
    ]
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )

    if result.returncode != expect:
        raise AssertionError(
            f"command failed: {command}\n"
            f"expected={expect} actual={result.returncode}\n"
            f"stdout={result.stdout}\n"
            f"stderr={result.stderr}"
        )

    return result


def parse_json(result: subprocess.CompletedProcess[str]) -> dict:
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"invalid JSON output:\n{result.stdout}\n{result.stderr}"
        ) from exc

    if not isinstance(payload, dict):
        raise AssertionError("JSON output is not an object")

    return payload


with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v042-site-cli-"
) as temporary_directory:
    db_path = Path(temporary_directory) / "deltaaegis.db"

    created = parse_json(
        run_cli(
            db_path,
            "site-create",
            "CLS Health - Admin Building",
            "--description",
            "Administrative building subnet group.",
            "--actor",
            "validator.admin",
            "--json",
        )
    )
    site_id = created["site"]["site_id"]

    if created["action"] != "logical_site.create":
        raise AssertionError("unexpected site-create action")
    if created["site"]["name"] != "CLS Health - Admin Building":
        raise AssertionError("site-create name mismatch")

    listed = parse_json(
        run_cli(db_path, "site-list", "--json")
    )
    if listed["site_count"] != 1:
        raise AssertionError("site-list count mismatch")

    shown = parse_json(
        run_cli(db_path, "site-show", site_id, "--json")
    )
    if shown["coverage"]["member_scope_count"] != 0:
        raise AssertionError("new site unexpectedly has members")

    assigned = parse_json(
        run_cli(
            db_path,
            "site-assign-scope",
            site_id,
            "192.168.4.0/24",
            "--actor",
            "validator.admin",
            "--json",
        )
    )
    if assigned["membership"]["network_scope"] != "192.168.4.0/24":
        raise AssertionError("scope assignment mismatch")
    if assigned["membership"]["observed"] is not False:
        raise AssertionError("unobserved assignment was not identified")

    scope_catalog = parse_json(
        run_cli(db_path, "scopes", "--json")
    )
    if scope_catalog["scope_count"] != 1:
        raise AssertionError("scope catalog count mismatch")
    catalog_row = scope_catalog["scopes"][0]
    if catalog_row["site_id"] != site_id:
        raise AssertionError("scope catalog did not include site binding")
    if catalog_row["snapshots"] != 0:
        raise AssertionError("unobserved scope has snapshot history")

    unassigned = parse_json(
        run_cli(db_path, "scopes", "--unassigned", "--json")
    )
    if unassigned["scope_count"] != 0:
        raise AssertionError("assigned scope appeared as unassigned")

    renamed = parse_json(
        run_cli(
            db_path,
            "site-rename",
            site_id,
            "CLS Health - Administration Building",
            "--json",
        )
    )
    if renamed["changed"] is not True:
        raise AssertionError("site rename did not report change")

    unchanged_rename = parse_json(
        run_cli(
            db_path,
            "site-rename",
            site_id,
            "CLS Health - Administration Building",
            "--json",
        )
    )
    if unchanged_rename["changed"] is not False:
        raise AssertionError("rename no-op did not report unchanged")

    described = parse_json(
        run_cli(
            db_path,
            "site-description",
            site_id,
            "Updated site description.",
            "--json",
        )
    )
    if described["site"]["description"] != "Updated site description.":
        raise AssertionError("site description update mismatch")

    duplicate_site = parse_json(
        run_cli(
            db_path,
            "site-create",
            "CLS Health - Clinical Building",
            "--json",
        )
    )
    duplicate_site_id = duplicate_site["site"]["site_id"]

    duplicate_assignment = run_cli(
        db_path,
        "site-assign-scope",
        duplicate_site_id,
        "192.168.4.0/24",
        "--json",
        expect=1,
    )
    if "already assigned" not in duplicate_assignment.stderr:
        raise AssertionError(
            "duplicate scope assignment did not fail clearly"
        )

    public_assignment = run_cli(
        db_path,
        "site-assign-scope",
        duplicate_site_id,
        "8.8.8.0/24",
        "--json",
        expect=1,
    )
    if "private" not in public_assignment.stderr.lower():
        raise AssertionError(
            "public CIDR assignment did not fail closed"
        )

    archived = parse_json(
        run_cli(
            db_path,
            "site-archive",
            site_id,
            "--json",
        )
    )
    if archived["site"]["status"] != "ARCHIVED":
        raise AssertionError("site archive mismatch")
    if archived["site"]["member_count"] != 1:
        raise AssertionError("archive removed site membership")

    archived_assignment = run_cli(
        db_path,
        "site-assign-scope",
        site_id,
        "192.168.5.0/24",
        "--json",
        expect=1,
    )
    if "archived" not in archived_assignment.stderr:
        raise AssertionError(
            "archived site accepted a new membership"
        )

    removed = parse_json(
        run_cli(
            db_path,
            "site-remove-scope",
            site_id,
            "192.168.4.0/24",
            "--json",
        )
    )
    if removed["membership"]["removed"] is not True:
        raise AssertionError("membership removal receipt mismatch")

    shown_after = parse_json(
        run_cli(db_path, "site-show", site_id, "--json")
    )
    if shown_after["coverage"]["member_scope_count"] != 0:
        raise AssertionError("membership removal did not persist")

    active_only = parse_json(
        run_cli(db_path, "site-list", "--json")
    )
    all_sites = parse_json(
        run_cli(
            db_path,
            "site-list",
            "--include-archived",
            "--json",
        )
    )
    if active_only["site_count"] != 1:
        raise AssertionError("active-only site listing mismatch")
    if all_sites["site_count"] != 2:
        raise AssertionError("archived site listing mismatch")

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    actions = {
        str(row["action"])
        for row in connection.execute(
            "SELECT action FROM access_audit_log"
        ).fetchall()
    }
    foreign_key_violations = connection.execute(
        "PRAGMA foreign_key_check"
    ).fetchall()
    connection.close()

    required_actions = {
        "LOGICAL_SITE_CREATE",
        "LOGICAL_SITE_RENAME",
        "LOGICAL_SITE_DESCRIPTION_UPDATE",
        "LOGICAL_SITE_ARCHIVE",
        "LOGICAL_SITE_SCOPE_ASSIGN",
        "LOGICAL_SITE_SCOPE_REMOVE",
    }
    missing_actions = required_actions - actions

    if missing_actions:
        raise AssertionError(
            f"missing logical-site audit actions: "
            f"{sorted(missing_actions)}"
        )

    if foreign_key_violations:
        raise AssertionError(
            f"foreign-key violations: {foreign_key_violations}"
        )

print("PASS: site create/list/show JSON")
print("PASS: private CIDR membership assignment")
print("PASS: unobserved subnet membership visibility")
print("PASS: enriched scope catalog")
print("PASS: rename and description mutation receipts")
print("PASS: duplicate assignment rejection")
print("PASS: public CIDR assignment rejection")
print("PASS: safe archive and archived assignment rejection")
print("PASS: membership removal without telemetry deletion")
print("PASS: active and archived site listing")
print("PASS: logical-site access audit actions")
print("PASS: foreign-key integrity")
PY

echo "[v0.42 checkpoint 2] human-readable output"
temp_dir="$(mktemp -d -t deltaaegis-v042-site-human-XXXXXX)"
trap 'rm -rf "$temp_dir"' EXIT
human_db="$temp_dir/human.db"

human_create="$(
  python3 deltaaegis.py \
    --db "$human_db" \
    site-create \
    "Human Output Site"
)"

grep -F "Created logical site Human Output Site." \
  <<<"$human_create" >/dev/null
grep -F "Site ID:" <<<"$human_create" >/dev/null

human_list="$(
  python3 deltaaegis.py \
    --db "$human_db" \
    site-list
)"

grep -F "DeltaAegis Logical Sites" <<<"$human_list" >/dev/null
grep -F "Human Output Site" <<<"$human_list" >/dev/null

echo "PASS: human-readable site command output"


echo "[v0.42 checkpoint 2] repository hygiene"
git diff --check
echo "PASS: repository hygiene"

echo "PASS: DeltaAegis v0.42 logical site CLI validator"
