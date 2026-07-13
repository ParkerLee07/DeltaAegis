"""Low-level SQLite connection policy for DeltaAegis.

Schema bootstrap and compatibility additions deliberately remain in
``deltaaegis.py`` until the forward-only migration ledger is introduced.  This
module creates only the connection and its row contract; it does not initialize
or mutate application schema.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path


def open_database_connection(db_path: Path) -> sqlite3.Connection:
    """Open a local SQLite database using the historical row configuration."""

    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


__all__ = ("open_database_connection",)
