# DeltaAegis v1 Stage 3–5 fixtures

These deterministic fixtures exercise the boundaries added by the combined
Stage 3–5 upgrade:

- the same CIDR under two enrolled sensors remains isolated;
- identical sensor evidence is idempotent while a conflicting digest for the
  same sensor run is rejected;
- unknown sensors fail closed;
- older evidence cannot replace the current scope head; and
- versioned detections replay to the same immutable result identifiers.

The contract versions match the pinned NetSniper v2.1.0 integration boundary.
The combined validator also consumes the tracked TrueAegis validation fixture.
