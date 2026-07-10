#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "DeltaAegis v0.42 License Policy Validator"
echo "=========================================="

python3 - <<'PY'
from pathlib import Path
import hashlib

expected_license_sha256 = (
    "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0"
)

license_bytes = Path("LICENSE").read_bytes()
license_text = license_bytes.decode("utf-8")
readme = Path("README.md").read_text(encoding="utf-8")
licensing = Path("LICENSING.md").read_text(encoding="utf-8")
changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
source = Path("deltaaegis.py").read_text(encoding="utf-8")

actual_hash = hashlib.sha256(license_bytes).hexdigest()
if actual_hash != expected_license_sha256:
    raise SystemExit(
        "LICENSE is not the approved verbatim AGPL-3.0 text: "
        f"{actual_hash}"
    )

for marker in (
    "GNU AFFERO GENERAL PUBLIC LICENSE",
    "Version 3, 19 November 2007",
    "13. Remote Network Interaction",
    "END OF TERMS AND CONDITIONS",
):
    if marker not in license_text:
        raise SystemExit(f"LICENSE missing required AGPL marker: {marker}")

for marker in (
    "GNU Affero General Public License, version 3 only",
    "`AGPL-3.0-only`",
    "`LICENSING.md`",
    "Alternative commercial licensing",
    "Corresponding Source",
):
    if marker not in readme:
        raise SystemExit(f"README missing license marker: {marker}")

for marker in (
    "# DeltaAegis Licensing",
    "Copyright (C) 2026 Parker Lee.",
    "AGPL-3.0-only",
    "Alternative commercial licensing",
    "parkercharleslee@gmail.com",
    "separate written agreement",
    "already distributed under the MIT License",
    "does not purport to revoke permissions already granted",
    "Third-party material",
    "No trademark rights",
):
    if marker not in licensing:
        raise SystemExit(
            f"LICENSING.md missing required policy marker: {marker}"
        )

for marker in ("AGPL-3.0-only", "commercial licensing"):
    if marker.casefold() not in changelog.casefold():
        raise SystemExit(
            f"CHANGELOG missing license transition marker: {marker}"
        )

for marker in (
    "SPDX-License-Identifier: AGPL-3.0-only",
    "Copyright (C) 2026 Parker Lee",
    'data-deltaaegis-license="AGPL-3.0-only"',
    "https://github.com/ParkerLee07/DeltaAegis",
    "View Corresponding Source",
):
    if marker not in source:
        raise SystemExit(
            f"deltaaegis.py missing license/source marker: {marker}"
        )

body_count = sum(
    line.strip() == "</body>"
    for line in source.splitlines()
)
offer_count = sum(
    line.lstrip().startswith(
        '<footer data-deltaaegis-license="AGPL-3.0-only"'
    )
    for line in source.splitlines()
)

if body_count < 1:
    raise SystemExit(
        "deltaaegis.py does not contain a standalone HTML body closer"
    )

if offer_count != body_count:
    raise SystemExit(
        "every rendered HTML body must include the source offer: "
        f"bodies={body_count}, offers={offer_count}"
    )

if Path("RELEASE_CHECKLIST.md").exists():
    raise SystemExit(
        "manual release verification must not be tracked as a repository file"
    )

if "MIT License. See `LICENSE`." in readme:
    raise SystemExit("README still identifies MIT as the current license")

print("PASS: verbatim AGPL-3.0 license text")
print("PASS: v0.42 license and commercial-licensing policy")
print("PASS: prior MIT-copy boundary is documented")
print("PASS: source and dashboard corresponding-source notices")
print("PASS: manual verification remains operator-managed")
print("PASS: DeltaAegis v0.42 license policy validator")
PY
