#!/usr/bin/env python3
"""Validate v0.45 Quality Center preservation under the v1 install boundary."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def check(condition: object, message: str) -> None:
    if not condition:
        raise SystemExit(f"[FAIL] v1/v0.45 quality transition: {message}")


def main() -> int:
    root_source = (ROOT / "deltaaegis.py").read_text(encoding="utf-8")
    web_source = (ROOT / "deltaaegis_core/web.py").read_text(encoding="utf-8")
    report_source = (ROOT / "deltaaegis_core/reports.py").read_text(encoding="utf-8")
    install_source = (ROOT / "install.sh").read_text(encoding="utf-8")
    for relative in (
        "deltaaegis.py",
        "deltaaegis_core/current_state.py",
        "deltaaegis_core/reports.py",
        "deltaaegis_core/telemetry_quality.py",
        "deltaaegis_core/web.py",
    ):
        ast.parse((ROOT / relative).read_text(encoding="utf-8"), filename=relative)

    check(
        root_source.count("DELTAAEGIS_V045_TELEMETRY_TRUST_RUNTIME") == 1,
        "telemetry-trust runtime marker drifted",
    )
    check(
        'href="/operator/telemetry-quality"' in root_source,
        "operator shell no longer links to the Quality Center",
    )
    for route in (
        "/api/telemetry-quality",
        "/api/telemetry-quality/detail",
        "/api/telemetry-quality/review",
        "/api/telemetry-quality/override",
    ):
        check(route in web_source, f"private compatibility route is missing: {route}")
    check(
        "append_report_telemetry_quality_section" in report_source
        and "_reports.append_report_telemetry_quality_section" in root_source,
        "telemetry-quality report disclosure drifted",
    )
    check(
        "telemetry_projection" in root_source
        and "augment_asset_detail" in root_source,
        "current-state or asset provenance disclosure drifted",
    )

    # v0.45 conditionally compiled these modules for historical minimal test
    # fixtures. Stage 1 makes them required so every install converges through
    # the full ledgered schema instead of creating a partial database.
    for relative in (
        "deltaaegis_core/current_state.py",
        "deltaaegis_core/telemetry_quality.py",
    ):
        check(install_source.count(f'"{relative}"') == 2, f"required install boundary drifted: {relative}")
        check((ROOT / relative).is_file(), f"required module is missing: {relative}")

    check(
        "legacy minimal lifecycle fixtures" in root_source
        and "except ImportError:" in root_source,
        "root import compatibility seam was removed",
    )
    print(
        "[PASS] v1/v0.45 quality transition: Quality Center behavior preserved "
        "and its storage modules promoted to required install components"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
