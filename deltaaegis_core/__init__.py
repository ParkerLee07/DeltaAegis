"""Internal implementation package for DeltaAegis.

The public compatibility surface remains the repository-root ``deltaaegis.py``
module after the v0.44 extraction and through the additive v1 Stage 1–5
transition. Internal modules live under this non-conflicting package so
``import deltaaegis`` continues to resolve exactly as it did before
modularization began. The v1 Stage 3-5 modules remain internal owners behind
that same compatibility facade.
"""

from __future__ import annotations

__all__ = (
    "api_v1",
    "auth",
    "config",
    "current_state",
    "detection",
    "db",
    "identity",
    "ingest",
    "jobs",
    "migrations",
    "operations",
    "reports",
    "sites",
    "telemetry_quality",
    "web",
)
