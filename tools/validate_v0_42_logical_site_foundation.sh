#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

branch="$(git branch --show-current)"
case "$branch" in
  feature/v0.42-logical-site-scopes|release/v0.42.1|release/v0.42.2|main)
    ;;
  *)
    echo "FAIL: expected feature/v0.42-logical-site-scopes, release/v0.42.1, release/v0.42.2, or main"
    exit 1
    ;;
esac

echo "DeltaAegis v0.42 Logical Site Foundation Validator"
echo "==================================================="

echo "[v0.42 checkpoint 1] source syntax"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py
echo "PASS: source syntax"

echo "[v0.42 checkpoint 1] static contract"
python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = (
    "# v0.42 checkpoint 1: logical site scope foundation",
    "CREATE TABLE IF NOT EXISTS logical_sites",
    "CREATE TABLE IF NOT EXISTS logical_site_memberships",
    "ON DELETE RESTRICT",
    "def create_logical_site(",
    "def list_logical_sites(",
    "def get_logical_site(",
    "def rename_logical_site(",
    "def update_logical_site_description(",
    "def archive_logical_site(",
    "def logical_site_member_scopes(",
    "def logical_site_for_network_scope(",
    "def assign_network_scope_to_logical_site(",
    "def remove_network_scope_from_logical_site(",
)

for marker in required:
    if marker not in text:
        raise SystemExit(f"missing logical-site marker: {marker}")

print("PASS: static logical-site contract")
PY

echo "[v0.42 checkpoint 1] functional schema and behavior"
python3 - <<'PY'
from __future__ import annotations

from pathlib import Path
import importlib.util
import sqlite3
import sys
import tempfile

module_path = Path("deltaaegis.py").resolve()
module_name = "deltaaegis_v042_checkpoint1"

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


def expect_error(callable_object, expected_text: str) -> None:
    try:
        callable_object()
    except module.DeltaAegisError as exc:
        if expected_text not in str(exc):
            raise AssertionError(
                f"expected error containing {expected_text!r}, "
                f"found {str(exc)!r}"
            ) from exc
    else:
        raise AssertionError(
            f"expected DeltaAegisError containing {expected_text!r}"
        )


def table_names(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }


with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v042-site-foundation-"
) as temp_name:
    temp = Path(temp_name)

    fresh_path = temp / "fresh.db"
    fresh = module.connect(fresh_path)
    required_tables = {
        "logical_sites",
        "logical_site_memberships",
    }
    missing = required_tables - table_names(fresh)
    if missing:
        raise AssertionError(
            f"fresh database missing logical-site tables: {sorted(missing)}"
        )

    admin = module.create_logical_site(
        fresh,
        "CLS Health - Admin Building",
        "Seven routed subnet scopes.",
    )
    if admin["status"] != "ACTIVE":
        raise AssertionError("new logical site is not ACTIVE")

    expect_error(
        lambda: module.create_logical_site(
            fresh,
            "cls health - admin building",
        ),
        "already exists",
    )

    clinical = module.create_logical_site(
        fresh,
        "CLS Health - Clinical Building",
    )

    first = module.assign_network_scope_to_logical_site(
        fresh,
        admin["site_id"],
        "192.168.4.0/24",
    )
    if first["network_scope"] != "192.168.4.0/24":
        raise AssertionError("network scope was not preserved canonically")

    module.assign_network_scope_to_logical_site(
        fresh,
        admin["site_id"],
        "192.168.5.0/24",
    )

    expect_error(
        lambda: module.assign_network_scope_to_logical_site(
            fresh,
            admin["site_id"],
            "192.168.4.0/24",
        ),
        "already assigned",
    )

    expect_error(
        lambda: module.assign_network_scope_to_logical_site(
            fresh,
            clinical["site_id"],
            "192.168.4.0/24",
        ),
        "already assigned",
    )

    members = module.logical_site_member_scopes(
        fresh,
        admin["site_id"],
    )
    if members != [
        "192.168.4.0/24",
        "192.168.5.0/24",
    ]:
        raise AssertionError(
            f"unexpected logical-site membership order: {members}"
        )

    resolved = module.logical_site_for_network_scope(
        fresh,
        "192.168.4.0/24",
    )
    if (
        resolved is None
        or resolved["site_id"] != admin["site_id"]
        or resolved["member_count"] != 2
    ):
        raise AssertionError(
            f"network-scope site resolution failed: {resolved}"
        )

    renamed = module.rename_logical_site(
        fresh,
        admin["site_id"],
        "CLS Health - Administration Building",
    )
    if renamed["name"] != "CLS Health - Administration Building":
        raise AssertionError("logical site rename did not persist")

    described = module.update_logical_site_description(
        fresh,
        admin["site_id"],
        "Administrative building network scope.",
    )
    if described["description"] != (
        "Administrative building network scope."
    ):
        raise AssertionError(
            "logical site description update did not persist"
        )

    archived = module.archive_logical_site(
        fresh,
        admin["site_id"],
    )
    if archived["status"] != "ARCHIVED":
        raise AssertionError("logical site archive did not persist")
    if archived["member_count"] != 2:
        raise AssertionError(
            "archiving changed logical-site membership count"
        )

    expect_error(
        lambda: module.assign_network_scope_to_logical_site(
            fresh,
            admin["site_id"],
            "192.168.6.0/24",
        ),
        "archived",
    )

    archived_again = module.archive_logical_site(
        fresh,
        admin["site_id"],
    )
    if archived_again["status"] != "ARCHIVED":
        raise AssertionError("repeat archive changed site status")

    removed = module.remove_network_scope_from_logical_site(
        fresh,
        admin["site_id"],
        "192.168.5.0/24",
    )
    if removed["removed"] is not True:
        raise AssertionError("membership removal receipt is incorrect")

    remaining = module.logical_site_member_scopes(
        fresh,
        admin["site_id"],
    )
    if remaining != ["192.168.4.0/24"]:
        raise AssertionError(
            f"unexpected remaining membership: {remaining}"
        )

    active_sites = module.list_logical_sites(fresh)
    all_sites = module.list_logical_sites(
        fresh,
        include_archived=True,
    )
    if len(active_sites) != 1 or len(all_sites) != 2:
        raise AssertionError(
            "active/archive logical-site listing is incorrect"
        )

    foreign_key_violations = fresh.execute(
        "PRAGMA foreign_key_check"
    ).fetchall()
    if foreign_key_violations:
        raise AssertionError(
            f"foreign-key violations: {foreign_key_violations}"
        )

    fresh.commit()
    fresh.close()

    reopened = module.connect(fresh_path)
    if module.get_logical_site(
        reopened,
        admin["site_id"],
    ) is None:
        raise AssertionError("logical site missing after reopen")
    reopened.close()

    reopened_again = module.connect(fresh_path)
    reopened_again.close()

    legacy_path = temp / "legacy.db"
    legacy_seed = sqlite3.connect(legacy_path)
    legacy_seed.execute(
        "CREATE TABLE legacy_marker "
        "(marker_id INTEGER PRIMARY KEY, value TEXT NOT NULL)"
    )
    legacy_seed.execute(
        "INSERT INTO legacy_marker (value) VALUES ('preserve-me')"
    )
    legacy_seed.commit()
    legacy_seed.close()

    upgraded = module.connect(legacy_path)
    if required_tables - table_names(upgraded):
        raise AssertionError(
            "simulated legacy database was not upgraded"
        )

    marker = upgraded.execute(
        "SELECT value FROM legacy_marker WHERE marker_id = 1"
    ).fetchone()
    if marker is None or marker[0] != "preserve-me":
        raise AssertionError(
            "simulated legacy data was modified during upgrade"
        )
    upgraded.close()

    upgraded_again = module.connect(legacy_path)
    marker_again = upgraded_again.execute(
        "SELECT value FROM legacy_marker WHERE marker_id = 1"
    ).fetchone()
    if marker_again is None or marker_again[0] != "preserve-me":
        raise AssertionError(
            "idempotent reopen modified simulated legacy data"
        )
    upgraded_again.close()

print("PASS: fresh logical-site schema")
print("PASS: simulated pre-v0.42 additive migration")
print("PASS: migration idempotence")
print("PASS: site create, rename, description, and listing")
print("PASS: duplicate site-name rejection")
print("PASS: one-site-per-network-scope invariant")
print("PASS: duplicate membership rejection")
print("PASS: safe site archiving")
print("PASS: archived-site assignment rejection")
print("PASS: membership removal preserves site")
print("PASS: foreign-key integrity")
print("PASS: unrelated legacy data preservation")
PY

echo "[v0.42 checkpoint 1] repository hygiene"
git diff --check
echo "PASS: repository hygiene"

echo "PASS: DeltaAegis v0.42 logical site foundation validator"
