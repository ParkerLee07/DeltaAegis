"""DeltaAegis runtime path defaults.

This module owns default-path construction.  The root ``deltaaegis`` module
re-exports the resulting constants as a compatibility facade for existing
callers, validators, launchers, and operator scripts.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RuntimePaths:
    """Resolved default locations for one DeltaAegis runtime home."""

    database: Path
    backups: Path
    restore_rehearsals: Path
    runs: Path
    netsniper: Path
    scan_logs: Path
    trueaegis: Path
    trueaegis_logs: Path
    events: Path
    reports: Path
    telemetry_evidence: Path


def runtime_paths(home: Path | None = None) -> RuntimePaths:
    """Return defaults rooted at *home* without reading application state."""

    root = Path.home() if home is None else Path(home)
    deltaaegis_root = root / "DeltaAegis"
    return RuntimePaths(
        database=deltaaegis_root / "data" / "deltaaegis.db",
        backups=deltaaegis_root / "backups",
        restore_rehearsals=deltaaegis_root / "restore-rehearsals",
        runs=root / "NetSniper" / "runs",
        netsniper=root / "NetSniper" / "netsniper.sh",
        scan_logs=deltaaegis_root / "scan-logs",
        trueaegis=root / "TrueAegis" / "trueaegis.py",
        trueaegis_logs=deltaaegis_root / "trueaegis-logs",
        events=deltaaegis_root / "events" / "events.jsonl",
        reports=deltaaegis_root / "reports",
        telemetry_evidence=deltaaegis_root / "telemetry-evidence",
    )


_DEFAULTS = runtime_paths()

DEFAULT_DB = _DEFAULTS.database
DEFAULT_BACKUPS = _DEFAULTS.backups
DEFAULT_RESTORE_REHEARSALS = _DEFAULTS.restore_rehearsals
DEFAULT_RUNS = _DEFAULTS.runs
DEFAULT_NETSNIPER = _DEFAULTS.netsniper
DEFAULT_SCAN_LOGS = _DEFAULTS.scan_logs
DEFAULT_TRUEAEGIS = _DEFAULTS.trueaegis
DEFAULT_TRUEAEGIS_LOGS = _DEFAULTS.trueaegis_logs
DEFAULT_EVENTS = _DEFAULTS.events
DEFAULT_REPORTS = _DEFAULTS.reports
DEFAULT_TELEMETRY_EVIDENCE = _DEFAULTS.telemetry_evidence


__all__ = (
    "DEFAULT_BACKUPS",
    "DEFAULT_DB",
    "DEFAULT_EVENTS",
    "DEFAULT_NETSNIPER",
    "DEFAULT_REPORTS",
    "DEFAULT_TELEMETRY_EVIDENCE",
    "DEFAULT_RESTORE_REHEARSALS",
    "DEFAULT_RUNS",
    "DEFAULT_SCAN_LOGS",
    "DEFAULT_TRUEAEGIS",
    "DEFAULT_TRUEAEGIS_LOGS",
    "RuntimePaths",
    "runtime_paths",
)
