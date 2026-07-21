#!/usr/bin/env python3
"""Validate the intentional v0.45 extension of the v0.44 web route inventory."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import validate_v0_44_stage8_web as legacy  # noqa: E402


ADDED_API_ROUTES = {
    "/api/telemetry-quality",
    "/api/telemetry-quality/detail",
    "/api/telemetry-quality/review",
    "/api/telemetry-quality/override",
}
QUALITY_PAGE_ROUTE = "/operator/telemetry-quality"


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def route_inventory(source: str) -> list[str]:
    return sorted(
        set(
            re.findall(
                r'''["'](/(?:api/[^"'?# ]+|healthz|login|logout|operator(?:/users)?|netsniper))["']''',
                source,
            )
        )
    )


def validate_route_transition(characterization: dict) -> None:
    source = (ROOT / characterization["module"]).read_text(encoding="utf-8")
    current = route_inventory(source)
    current_set = set(current)
    legacy_routes = sorted(current_set - ADDED_API_ROUTES)
    encoded_legacy = json.dumps(legacy_routes, separators=(",", ":"))

    check(
        len(legacy_routes) == characterization["route_inventory"]["count"],
        "legacy route count changed outside the approved Quality Center extension",
    )
    check(
        digest(encoded_legacy) == characterization["route_inventory"]["sha256"],
        "legacy route inventory changed outside the approved extension",
    )
    check(
        current_set - set(legacy_routes) == ADDED_API_ROUTES,
        "unexpected API route was added with the Quality Center",
    )
    check(
        source.count(QUALITY_PAGE_ROUTE) >= 2,
        "protected Quality Center page route is missing",
    )


def main() -> int:
    print("DeltaAegis v0.45 / v0.44 Web Route Transition Validator")
    print("===========================================================")
    characterization = legacy.load_characterization()
    legacy.validate_ownership(characterization)
    print("PASS: unchanged v0.44 web ownership and facade contracts")
    legacy.validate_rendering(characterization)
    print("PASS: unchanged characterized v0.44 renderers")
    validate_route_transition(characterization)
    print("PASS: old route inventory preserved with four approved APIs")
    legacy.validate_response_and_bind_boundaries()
    print("PASS: unchanged disconnect and bind boundaries")
    print("PASS: protected Quality Center page route is present")
    print("PASS: DeltaAegis v0.45 intentional Stage 8 route transition")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
