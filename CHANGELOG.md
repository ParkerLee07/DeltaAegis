# Changelog

## [v0.2] - 2026-06-12

### Added
- `netsniper-run-v2` ingestion with exact scan-profile compatibility checks.
- Identity classes: `GLOBAL_MAC`, `LOCAL_MAC`, and `IP_ONLY`.
- Ephemeral identity events for locally administered MAC addresses.
- Three-accepted-scan threshold before stable assets become removed.
- `ASSET_REAPPEARED` and stable-MAC `IP_CHANGED` events.
- Stateful operator-facing alerts with `OPEN`, `ACKNOWLEDGED`, `RESOLVED`, and `SUPPRESSED` states.
- Interactive CLI screens for alerts, asset history, snapshot health, and baseline approval.

### Fixed
- Excluded unusable subnet network and broadcast addresses from asset storage.
- Prevented profile changes from generating misleading service-opened or service-closed deltas.

## [v0.1] - 2026-06-12

### Added
- Initial SQLite-backed NetSniper bundle ingestion.
- Historical snapshot storage.
- IP-level observation and monitored-service delta events.
- Append-only JSONL event export.
