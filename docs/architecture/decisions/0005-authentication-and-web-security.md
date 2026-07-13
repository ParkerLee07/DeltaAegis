# ADR 0005: Keep local authentication and harden the web boundary

- Status: Accepted
- Date: 2026-07-13
- Applies to: current controls and v0.46 hardening

## Context

DeltaAegis is self-hosted and already provides local password users, sessions, API tokens, roles, and access audit. The dashboard can launch privileged local workflows, so browser transport and server-side authorization must remain separate trust boundaries.

## Decision

v1.0 retains local accounts as the required authentication baseline. Passwords use the existing adaptive derivation contract, sessions and API tokens are revocable and bounded, roles are evaluated server-side for every protected action, and the audit actor always comes from the authenticated principal.

The dashboard defaults to loopback. Explicit LAN binding requires active authentication. v0.46 adds CSRF protection for cookie-authenticated mutations, secure cookie attributes appropriate to the deployment, origin/host validation, restrictive security headers, request-size limits, and documented token scopes.

GET remains read-only. Caller-supplied actor, role, PID, filesystem path, or authorization claims are ignored or rejected.

## Consequences

- Enterprise SSO is outside v1.0 scope.
- A reverse proxy may add TLS, but proxy trust configuration must be explicit.
- Security controls receive route-level and real-HTTP regression tests.
- Emergency revocation and last-admin invariants remain atomic database operations.
