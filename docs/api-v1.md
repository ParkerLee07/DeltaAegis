# DeltaAegis `/api/v1` contract

Status: implemented and release-gated in the combined v1.0 Stage 1–2 candidate. The complete v1.0 definition of done still includes later identity, detection, operations, performance, and integration stages.

The machine-readable OpenAPI 3.1 contract is available at [`contracts/v1/openapi.json`](../contracts/v1/openapi.json) and from `GET /api/v1/openapi.json` while the dashboard is running.

## Stable endpoint inventory

| Method | Path | Required scope | Notes |
|---|---|---|---|
| GET | `/api/v1` | Public | Discovery document |
| GET | `/api/v1/openapi.json` | Public | Raw OpenAPI 3.1 document |
| GET | `/api/v1/session` | `session.read` | Current server-derived principal |
| GET | `/api/v1/summary` | `dashboard.read` | Current summary; optional `scope` |
| GET | `/api/v1/scopes` | `dashboard.read` | Paginated scope inventory |
| GET | `/api/v1/sites` | `dashboard.read` | Paginated logical sites |
| POST | `/api/v1/sites` | `sites.write` | Idempotent logical-site creation |
| GET | `/api/v1/assets` | `dashboard.read` | Paginated assets; optional scope/state/identity filters |
| GET | `/api/v1/assets/{asset_key}` | `dashboard.read` | Asset detail |
| GET | `/api/v1/events` | `dashboard.read` | Paginated events |
| GET | `/api/v1/alerts` | `dashboard.read` | Paginated alerts |
| GET | `/api/v1/scan-jobs` | `dashboard.read` | Paginated durable scan jobs |
| GET | `/api/v1/validations` | `dashboard.read` | Paginated TrueAegis observations |
| GET | `/api/v1/telemetry-quality/decisions` | `dashboard.read` | Paginated quality decisions |
| GET | `/api/v1/telemetry-quality/decisions/{decision_id}` | `dashboard.read` | One quality decision |

Only this table is stable. Existing unversioned `/api/*` routes remain private dashboard compatibility interfaces. They are not promoted by implication and may evolve with their focused compatibility tests.

## Compatibility and deprecation

At v1.0 GA, compatible fields and operations may be added within `/api/v1`, but an incompatible request, response, authentication, or behavior change requires a new major API version. Normal deprecations are recorded in the cumulative changelog and this contract, identify a replacement, and remain available for at least two minor releases and normally 180 days. A security or data-integrity emergency may shorten that window only with a documented reason and migration action, as defined by ADR 0009.

## Authentication and authorization

Programmatic clients send one scoped token:

```http
Authorization: Bearer da_...
```

The private `X-DeltaAegis-Token` header and the dashboard `--token` value do not authenticate `/api/v1`. Supplying both credential transports is rejected as ambiguous.

New API tokens expire after 30 days by default and may not exceed 365 days. A token's role cannot exceed its user's current role, and its scopes cannot exceed its token role. Authorization always uses the user's current active state and role, so user demotion, deactivation, token revocation, expiration, malformed scope storage, and missing scope all fail closed.

Create a token with the smallest required scopes:

```bash
python3 deltaaegis.py api-token-create \
  automation \
  --name inventory-reader \
  --role VIEWER \
  --scope dashboard.read \
  --scope session.read
```

Raw token values are shown only at creation. Store them outside logs and reports.

Browser sessions use `deltaaegis_session` with `HttpOnly` and `SameSite=Strict`. Every cookie-authenticated mutation additionally requires:

- the readable `deltaaegis_csrf` cookie;
- an identical `X-DeltaAegis-CSRF` header;
- a match to the server-stored session CSRF hash; and
- a same-origin `Origin` matching the validated request `Host` and port.

For HTTPS proxy deployment, configure the browser-facing origin explicitly, for example `dashboard --host 127.0.0.1 --secure-cookies --public-origin https://deltaaegis.example`. This adds `Secure` to both cookies. The proxy must preserve that authority in `Host`; DeltaAegis compares it with the configured origin and does not trust forwarded host or client-address headers. `--secure-cookies` fails closed without an HTTPS `--public-origin`.

## Envelopes and request IDs

Except for the raw OpenAPI document, successful stable responses use:

```json
{
  "api_version": "v1",
  "ok": true,
  "data": {},
  "meta": {"request_id": "req_..."}
}
```

Errors use:

```json
{
  "api_version": "v1",
  "ok": false,
  "error": {
    "code": "invalid_request",
    "message": "The request could not be accepted.",
    "details": {}
  },
  "meta": {"request_id": "req_..."}
}
```

A valid 8–128 character `X-Request-ID` containing letters, numbers, `.`, `_`, `:`, or `-` is preserved. Otherwise the server creates a new request ID. The same value is returned in the envelope and response header. Unexpected exceptions return a bounded generic error and never a traceback.

## Pagination

List endpoints accept integer `limit` and `offset`. `limit` is 1–200 and defaults to 50; `offset` is 0–10,000,000 and defaults to 0. Pagination metadata reports the returned count, whether another page exists, and the next offset.

## Mutation idempotency

Every stable mutation requires an `Idempotency-Key` of 8–128 characters from the documented character set. Keys are isolated by authenticated principal, method, and route and retained for 24 hours.

- The first request stores a canonical SHA-256 of the method, route, and JSON body.
- An exact retry replays the original status and envelope and adds `Idempotency-Replayed: true`.
- Reusing the key with a different body returns `409 idempotency_key_conflict`.
- A concurrent duplicate returns the completed replay or `409 idempotency_request_in_progress`; it never duplicates the domain mutation.
- Domain data and the completed idempotency record commit in the same SQLite transaction.
- Failed domain requests are recorded and replayed consistently.

## HTTP boundary

Stable JSON mutations require exactly one non-negative `Content-Length`, UTF-8 `application/json`, a JSON object, and a body no larger than 65,536 bytes. Transfer encoding is rejected. Unsupported stable methods return a versioned `405` envelope.

Every DeltaAegis JSON, HTML, text, and redirect response includes no-store caching plus CSP, frame denial, MIME-sniffing denial, referrer, permissions, and cross-origin-opener policy headers. The dashboard defaults to loopback and validates `Host`; explicit LAN binding retains the existing authentication prerequisite.

## Validation

```bash
python3 tools/validate_v1_stage2_api_security.py
```

The validator starts a real threaded HTTP server on a temporary loopback port and exercises the OpenAPI inventory, every list route, envelopes, pagination, request IDs, scoped tokens, demotion/revocation, private-interface separation, strict request parsing, security headers, host/origin rejection, browser login cookies, CSRF, logout semantics, exact/failed/concurrent idempotency, and final SQLite integrity.
