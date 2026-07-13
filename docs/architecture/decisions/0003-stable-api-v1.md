# ADR 0003: Introduce a versioned `/api/v1` contract

- Status: Accepted
- Date: 2026-07-13
- Applies to: API and security work beginning in v0.46

## Context

The dashboard currently uses many unversioned `/api/*` routes. They are authenticated local implementation interfaces but have accumulated different payload shapes and mutation semantics. Treating all of them as permanently stable would freeze accidental behavior and make security hardening difficult.

## Decision

The supported programmatic API will live under `/api/v1`. It will publish an OpenAPI description, explicit request/response schemas, consistent error envelopes, pagination rules, authentication requirements, RBAC permissions, and mutation idempotency behavior.

Unversioned endpoints remain dashboard implementation interfaces until individually mapped. They are not promoted by implication. During transition, the browser may use compatibility adapters, but stable API handlers and core services must share authorization and domain logic rather than proxying through browser routes.

## Consequences

- v0.46 defines and tests the first stable surface.
- API tokens are scoped and server-derived actors remain mandatory.
- Breaking `/api/v1` changes require the deprecation process in ADR 0009 or a major version.
- HTML structure and internal endpoints may evolve independently when their focused compatibility tests pass.
