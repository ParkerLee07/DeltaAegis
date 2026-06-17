# DeltaAegis Architecture

<!-- DELTAAEGIS_V085_ARCHITECTURE_START -->
## v0.8.5 Intelligence Pipeline

DeltaAegis v0.8.5 extends the original snapshot comparison model with NetSniper classification intelligence and role-aware investigation context.

### Current pipeline

    NetSniper scan
      -> immutable telemetry bundle
      -> DeltaAegis ingestion
      -> accepted snapshot storage
      -> asset lifecycle update
      -> classification intelligence storage
      -> snapshot comparison and delta events
      -> classification delta events
      -> alert/risk register
      -> dashboard and Markdown report

### Classification intelligence model

NetSniper classification data is stored with each asset observation when available. DeltaAegis tracks:

- classification type
- primary type
- confidence
- confidence label
- decision
- method
- evidence
- contradictions
- candidate roles

This model allows DeltaAegis to distinguish between confirmed, possible, unknown, contradictory, and weak classifications.

### Risk and recommendation layer

DeltaAegis v0.8.5 uses classification intelligence as conservative context in the risk register. The goal is not to blindly trust classification output. The goal is to make risk explanations more useful by accounting for likely asset role.

Examples:

- printer exposure on `tcp/631` or `tcp/9100`
- camera/NVR exposure on `tcp/554`
- container or orchestration exposure on management ports
- database listener exposure
- domain-controller or identity-infrastructure candidates
- unknown assets with exposed services

Role-aware recommended actions are generated from the same context, so reports and dashboard guidance explain what an operator should verify next.
<!-- DELTAAEGIS_V085_ARCHITECTURE_END -->

## Data Sources

DeltaAegis `v0.8.5` ingests NetSniper immutable run bundles and NetSniper classification intelligence.

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
