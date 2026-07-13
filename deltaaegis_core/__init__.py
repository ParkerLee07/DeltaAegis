"""Internal implementation package for DeltaAegis.

The public compatibility surface remains the repository-root ``deltaaegis.py``
module throughout the v0.44 extraction.  Internal modules live under this
non-conflicting package so ``import deltaaegis`` continues to resolve exactly
as it did before modularization began.
"""

from __future__ import annotations

__all__ = ("config", "db")
