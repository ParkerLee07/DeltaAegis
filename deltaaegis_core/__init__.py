"""Internal implementation package for DeltaAegis.

The public compatibility surface remains the repository-root ``deltaaegis.py``
module after the v0.44 extraction and through the additive v1 Stage 1–2
transition. Internal modules live under this non-conflicting package so
``import deltaaegis`` continues to resolve exactly as it did before
modularization began.
"""

from __future__ import annotations

__all__ = (
    "api_v1",
    "auth",
    "config",
    "current_state",
    "db",
    "ingest",
    "jobs",
    "migrations",
    "reports",
    "sites",
    "telemetry_quality",
    "web",
)
