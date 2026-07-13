# ADR 0004: Separate sensor, scope, and asset identity

- Status: Accepted
- Date: 2026-07-13
- Applies to: identity work beginning in v0.47

## Context

v0.42 uses canonical private CIDR `network_scope` values as the technical boundary and logical sites as operator groupings. That is safe for one observation domain but cannot distinguish the same CIDR observed by different sensors or locations. MAC addresses are also not universally stable.

## Decision

DeltaAegis will introduce durable `sensor_id` and `scope_id` identities. A scope belongs to a sensor/trust domain and carries the observed CIDR as an attribute. Asset identity is evaluated within that scope unless evidence explicitly supports a stronger cross-scope correlation.

Logical-site membership references scope identity and remains a presentation/ownership grouping. It never becomes evidence identity. Existing `network_scope` remains the v0.42 compatibility key and is migrated without guessing across overlapping networks.

Sensor enrollment, scan UUID rules, replay protection, and bundle trust metadata are coordinated with NetSniper v2.1.0. No multi-sensor inference is implemented before those contracts and migrations are approved.

## Consequences

- Reused CIDRs cannot leak assets, events, or jobs across sensors.
- Existing single-sensor data receives an explicit legacy/default sensor during migration.
- One active scan is enforced per sensor rather than globally after the new identity exists.
- Cross-scope asset correlation remains explainable and confidence-bearing, never an irreversible merge.
