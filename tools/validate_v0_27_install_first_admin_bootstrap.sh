#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

pass() {
  echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

INSTALL_FILE=""
for candidate in install.sh scripts/install.sh setup.sh; do
  if [[ -f "$candidate" ]]; then
    INSTALL_FILE="$candidate"
    break
  fi
done

[[ -n "$INSTALL_FILE" ]] || fail "installer file not found"

python3 -m py_compile deltaaegis.py || fail "deltaaegis.py does not compile"
python3 -m py_compile tools/bootstrap_first_admin.py || fail "bootstrap_first_admin.py does not compile"

grep -Fq "DeltaAegis first-admin bootstrap" "$INSTALL_FILE" \
  || fail "installer missing first-admin bootstrap block"

grep -Fq "tools/bootstrap_first_admin.py" "$INSTALL_FILE" \
  || fail "installer does not call bootstrap_first_admin.py"

if grep -Fq "admin123" "$INSTALL_FILE"; then
  fail "installer must not hardcode public default password admin123"
fi

if grep -Fq "password=\"admin123\"" tools/bootstrap_first_admin.py; then
  fail "bootstrap helper must not hardcode public default password admin123"
fi

python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "install-bootstrap.db"

    result = subprocess.run(
        [
            sys.executable,
            "tools/bootstrap_first_admin.py",
            "--db",
            str(db_path),
            "--username",
            "install.admin",
            "--password",
            "install-admin-password",
            "--display-name",
            "Install Admin",
            "--non-interactive",
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, (
        result.returncode,
        result.stdout,
        result.stderr,
    )

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    row = connection.execute(
        "SELECT username, role FROM access_users WHERE username = ?",
        ("install.admin",),
    ).fetchone()
    connection.close()

    assert row is not None, "install.admin was not created"
    assert row["role"] == "ADMIN", dict(row)

    before = file_sha256(db_path)

    existing = subprocess.run(
        [
            sys.executable,
            "tools/bootstrap_first_admin.py",
            "--db",
            str(db_path),
        ],
        input="",
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert existing.returncode == 0, (
        existing.returncode,
        existing.stdout,
        existing.stderr,
    )
    assert "[SKIP]" in existing.stdout, existing.stdout
    assert "Existing local dashboard accounts: 1" in existing.stdout, (
        existing.stdout
    )
    combined = existing.stdout + existing.stderr
    assert "Create DeltaAegis admin username" not in combined, combined
    assert "Create DeltaAegis admin password" not in combined, combined

    after = file_sha256(db_path)
    assert before == after, (before, after)

    result2 = subprocess.run(
        [
            sys.executable,
            "tools/bootstrap_first_admin.py",
            "--db",
            str(db_path),
            "--username",
            "another.admin",
            "--password",
            "another-admin-password",
            "--non-interactive",
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert result2.returncode == 0, (
        result2.returncode,
        result2.stdout,
        result2.stderr,
    )
    assert "[SKIP]" in result2.stdout, result2.stdout

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    count = connection.execute(
        "SELECT COUNT(*) AS count FROM access_users"
    ).fetchone()["count"]
    connection.close()
    assert count == 1, count

print(
    "[PASS] synthetic install first-admin bootstrap and "
    "initialized-database prompt skip validated"
)
PY

pass "DeltaAegis installer first-admin bootstrap validation passed"
