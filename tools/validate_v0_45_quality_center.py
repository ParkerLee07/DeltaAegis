#!/usr/bin/env python3
"""Validate v0.45 Telemetry Quality Center, API, report, and disclosure surfaces."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise SystemExit(f"[FAIL] {message}")


def main():
    root_source = (ROOT / "deltaaegis.py").read_text(encoding="utf-8")
    web_source = (ROOT / "deltaaegis_core" / "web.py").read_text(encoding="utf-8")
    report_source = (
        ROOT / "deltaaegis_core" / "reports.py"
    ).read_text(encoding="utf-8")
    config_source = (
        ROOT / "deltaaegis_core" / "config.py"
    ).read_text(encoding="utf-8")
    install_source = (ROOT / "install.sh").read_text(encoding="utf-8")

    ast.parse(root_source)
    ast.parse(web_source)
    ast.parse(report_source)
    ast.parse(config_source)

    require(
        root_source.count("DELTAAEGIS_V045_TELEMETRY_TRUST_RUNTIME") == 1,
        "runtime integration marker missing or duplicated",
    )
    require(
        'href="/operator/telemetry-quality"' in root_source,
        "operator shell does not link to Telemetry Quality Center",
    )
    body_count = sum(
        line.strip() == "</body>" for line in root_source.splitlines()
    )
    offer_count = sum(
        line.lstrip().startswith(
            '<footer data-deltaaegis-license="AGPL-3.0-only"'
        )
        for line in root_source.splitlines()
    )
    require(
        offer_count == body_count,
        "Telemetry Quality Center omitted the required source offer",
    )
    for route in (
        "/api/telemetry-quality",
        "/api/telemetry-quality/detail",
        "/api/telemetry-quality/review",
        "/api/telemetry-quality/override",
    ):
        require(route in web_source, f"missing quality route {route}")

    require(
        "append_report_telemetry_quality_section" in report_source,
        "report quality section helper is missing",
    )
    require(
        "_reports.append_report_telemetry_quality_section" in root_source,
        "report command does not render telemetry quality",
    )
    require(
        "telemetry_projection" in root_source
        and "telemetry_quality" in root_source,
        "current-state/summary quality disclosure is missing",
    )
    require(
        "augment_asset_detail" in root_source,
        "asset-detail quality provenance is missing",
    )
    require(
        "classification_context" not in (
            root_source[
                root_source.rfind("def dashboard_assets_payload("):
                root_source.find(
                    "def dashboard_asset_detail_payload(",
                    root_source.rfind("def dashboard_assets_payload("),
                )
            ]
        ),
        "asset-list wrapper exposes full classification context",
    )
    require(
        "DEFAULT_TELEMETRY_EVIDENCE" in config_source,
        "managed telemetry evidence path is missing",
    )
    for relative in (
        "deltaaegis_core/current_state.py",
        "deltaaegis_core/telemetry_quality.py",
    ):
        require(
            install_source.count(relative) == 1,
            f"install lifecycle does not conditionally compile {relative}",
        )
    require(
        "characterized legacy minimal lifecycle fixtures" in install_source
        and "if path.is_file():" in install_source,
        "optional legacy lifecycle compile boundary is missing",
    )
    require(
        "except ImportError:" in root_source
        and "legacy minimal lifecycle fixtures" in root_source,
        "legacy minimal lifecycle import compatibility is missing",
    )

    print("[PASS] v0.45 Telemetry Quality Center and disclosure surfaces")


if __name__ == "__main__":
    main()
