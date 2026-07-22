#!/usr/bin/env python3
"""Validate the additive stable API transition from the v0.45 web boundary."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from deltaaegis_core import api_v1  # noqa: E402
from tools import validate_v0_44_stage8_web as legacy  # noqa: E402


QUALITY_ROUTES = {
    "/api/telemetry-quality",
    "/api/telemetry-quality/detail",
    "/api/telemetry-quality/review",
    "/api/telemetry-quality/override",
}
STABLE_DOMAIN_ACTION_LITERALS = {
    # The v0.45 action already exists in the root domain facade. Stage 2 calls
    # it directly from the stable adapter, so its established action selector
    # now appears in web.py without registering a new private route.
    "/api/site-create",
}


def check(condition: object, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def route_inventory(source: str) -> set[str]:
    return set(
        re.findall(
            r'''["'](/(?:api/[^"'?# ]+|healthz|login|logout|operator(?:/users)?|netsniper))["']''',
            source,
        )
    )


def normalize_stable_routes(routes: set[str]) -> set[str]:
    normalized: set[str] = set()
    for route in routes:
        if route == "/api/v1/":
            normalized.add("/api/v1")
        elif route == "/api/v1/assets/([^/]+)":
            normalized.add("/api/v1/assets/{asset_key}")
        elif route == "/api/v1/telemetry-quality/decisions/([^/]+)":
            normalized.add("/api/v1/telemetry-quality/decisions/{decision_id}")
        elif route == "/api/v1/detections/([^/]+)":
            normalized.add("/api/v1/detections/{result_id}")
        elif route == "/api/v1/detections/([^/]+)/reviews":
            normalized.add("/api/v1/detections/{result_id}/reviews")
        else:
            normalized.add(route)
    return normalized


def main() -> int:
    characterization = legacy.load_characterization()
    legacy.validate_ownership(characterization)
    legacy.validate_rendering(characterization)

    source = (ROOT / characterization["module"]).read_text(encoding="utf-8")
    current = route_inventory(source)
    stable_literals = {route for route in current if route.startswith("/api/v1")}
    expected_stable = {endpoint.template for endpoint in api_v1.API_V1_ENDPOINTS}
    check(
        normalize_stable_routes(stable_literals) == expected_stable,
        "web stable-route inventory differs from the authoritative API inventory",
    )

    legacy_routes = sorted(
        current - QUALITY_ROUTES - STABLE_DOMAIN_ACTION_LITERALS - stable_literals
    )
    encoded = json.dumps(legacy_routes, separators=(",", ":"))
    check(
        len(legacy_routes) == characterization["route_inventory"]["count"],
        "private v0.44 route count changed outside approved transitions",
    )
    check(
        digest(encoded) == characterization["route_inventory"]["sha256"],
        "private v0.44 route inventory changed outside approved transitions",
    )
    check(
        current - set(legacy_routes) - stable_literals
        == QUALITY_ROUTES | STABLE_DOMAIN_ACTION_LITERALS,
        "unexpected private route was added after v0.45",
    )
    legacy.validate_response_and_bind_boundaries()
    api_v1.validate_openapi_document(api_v1.openapi_document())

    print(
        "[PASS] v1/v0.45 web transition: characterized private routes and "
        "renderers preserved; stable routes exactly match the OpenAPI inventory"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"[FAIL] v1/v0.45 web transition: {exc}", file=sys.stderr)
        raise SystemExit(1)
