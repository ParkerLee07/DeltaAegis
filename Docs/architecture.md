# DeltaAegis Architecture

## Data Sources

DeltaAegis `v0.2` ingests NetSniper immutable run bundles.

- `manifest.json`: telemetry schema, scan profile, fingerprint, target, timestamps, counts, and file pointers.
- `discovery.xml`: discovery evidence and MAC addresses when available.
- `neighbors.txt`: archived IP-to-MAC fallback enrichment.
- `services.xml`: authoritative protocol, port, state, and service observations.
- `analysis.json`: NetSniper interpreted findings.

## Trust Model

DeltaAegis separates raw observations from conclusions.

```text
Observation
  What a sensor recorded at a point in time

Snapshot
  A normalized representation of accepted observations

Delta event
  An immutable explanation of a meaningful change

Alert
  Operator-facing workflow state derived from events
```

## Identity Classes

```text
GLOBAL_MAC
  Usually suitable for durable local asset tracking

LOCAL_MAC
  Potentially randomized, virtual, or manually configured
  Preserved as lower-confidence ephemeral telemetry

IP_ONLY
  Lowest-confidence fallback
```

## Snapshot Quality

Only accepted snapshots advance stable-asset lifecycle state. Review-required snapshots are preserved but do not trigger misleading removals.

## Scan-Profile Compatibility

`netsniper-run-v2` manifests contain an exact monitored-port contract and SHA-256 fingerprint. DeltaAegis quarantines incompatible profile changes until an operator approves a new baseline.
