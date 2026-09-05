# Web & API Security

## Architecture

The Web & API Security capability foundation mirrors the `recon/` architecture:

- **`blackforge/webapi/engine.py`** (`WebApiEngine`) — orchestrates the full pipeline: request validation → scope/authorization check → mock transport execution → normalization → evidence persistence → World Model materialization → best-effort memory link.
- **`blackforge/webapi/capabilities.py`** — ten typed `WebApiCapability` instances, each bound to a mock transport method and a normalization adapter. `build_webapi_capabilities()` returns all ten; `build_webapi_meta()` returns their metadata.
- **`blackforge/webapi/mock.py`** (`MockWebTransport`) — deterministic, mock-only HTTP transport. Known demo hosts use a fixed dataset; unknown hosts yield a stable hash-derived dataset. Never touches the network.
- **`blackforge/webapi/normalization.py`** — ten `WebToolAdapter` subclasses (one per capability) that parse mock raw output into typed `Observation` models. `WebNormalizedOutput` carries an optional `error` dict for handled negative outcomes.
- **`blackforge/webapi/evidence.py`** — `artifact_evidence()` and `observation_evidence()` construct evidence records; `observation_confidence()` implements the confidence policy; `evidence_dedup_key_for()` and `existing_evidence_id()` enable idempotent reruns.
- **`blackforge/webapi/materializer.py`** (`WebWorldMaterializer`) — maps typed observations into World Model records: APPLICATION entities (named by hostname), ENDPOINT/API entities (named by URL), CONTAINS relationships, and analysis assertions bound to the appropriate entity.
- **`blackforge/webapi/redaction.py`** — `redact_secret()` (sha-256 one-way hash), `redact_headers()` (secret-like header values replaced with `REDACTED:<16hex>`), `redact_document()` (recursive).
- **`blackforge/webapi/models.py`** — `WebApiMode`, `WebObservationKind`, `WebApiStatus`, ten observation models discriminated by `"kind"`, `WebApiRequest`, `WebApiResult`.
- **`blackforge/webapi/engine.py`** (`METHOD_TO_CAPABILITY`, `_ERROR_KIND_TO_STATUS`) — maps tool names to capability IDs and error kinds to statuses.

## Capabilities

| ID | Name | Mode | Risk | Produces |
|---|---|---|---|---|
| `webapi.application_discovery` | Application Discovery | ACTIVE | LOW | APPLICATION |
| `webapi.endpoint_enumeration` | Endpoint Enumeration | ACTIVE | MEDIUM | ENDPOINT |
| `webapi.api_surface_discovery` | API Surface Discovery | PASSIVE | LOW | API |
| `webapi.security_header_analysis` | Security-Header Analysis | PASSIVE | LOW | SECURITY_HEADER |
| `webapi.cookie_analysis` | Cookie Analysis | PASSIVE | LOW | COOKIE |
| `webapi.cors_analysis` | CORS Analysis | PASSIVE | LOW | CORS |
| `webapi.auth_surface_observation` | Authentication-Surface Observation | PASSIVE | LOW | AUTH_SURFACE |
| `webapi.openapi_review` | OpenAPI Review | PASSIVE | LOW | OPENAPI |
| `webapi.graphql_discovery` | GraphQL Discovery | PASSIVE | LOW | GRAPHQL |
| `webapi.request_response_observation` | Request/Response Observation | ACTIVE | MEDIUM | REQUEST_RESPONSE |

Registry counts: defaults-only → 1, recon + defaults → 7, + webapi → **17**.

## Transport Abstraction

`MockWebTransport` is the only transport. It never touches the network. Each capability method (e.g. `discover_web_applications`) returns a JSON record. Error records carry an `error` dict with a `kind` field. The engine maps `kind` to `WebApiStatus`:

- `rate_limited` → RATE_LIMITED
- `unauthorized` → UNAUTHORIZED
- `malformed`, `malformed_response` → MALFORMED_RESPONSE
- anything else → REQUEST_FAILED

Known hosts use fixed datasets; unknown hosts yield deterministic hash fallback (public test IP ranges only).

## Observation Models

All observations are discriminated unions keyed on `"kind"`:

- `WebApplicationObservation` (kind=application) — url, host, title, technologies, scheme, tls_version
- `EndpointObservation` (kind=endpoint) — url, host, method, status_code, content_type, title, scheme, tls_version, http_version
- `ApiObservation` (kind=api) — url, host, style, kind_label, docs_url
- `SecurityHeaderObservation` (kind=security_header) — url, host, header_name, present, finding, value
- `CookieObservation` (kind=cookie) — url, host, name, **value_hashed** (sha-256), domain, path, flags, secure, httponly, samesite
- `CorsObservation` (kind=cors) — url, host, allow_origins, allow_methods, allow_headers, expose_headers, allow_credentials, wildcard_origin, note
- `AuthSurfaceObservation` (kind=auth_surface) — url, host, scheme, scheme_type, parameter_name, note
- `OpenApiObservation` (kind=openapi) — url, host, spec_version, document_title, operation_count, path_count, security_schemes
- `GraphQlObservation` (kind=graphql) — url, host, introspection_enabled, type_count, query_count, mutation_count, operation_names
- `RequestOutcomeObservation` (kind=request_response) — url, host, method, status_code, http_version, tls_version, server_header, content_type, rtt_ms, **redacted_headers**

## Redaction

- `redact_secret(value)` — deterministic sha-256 hexdigest; plaintext never persisted.
- `redact_headers(headers)` — header names preserved; secret-like values (`authorization`, `cookie`, `set-cookie`, `proxy-authorization`, `x-api-key`, `api_key`, `apikey`, `access_token`, `refresh_token`, `token`, `password`, `passwd`, `client_secret`, `secret`, `credentials`, `apikeyvalue`) replaced with `REDACTED:<16hex>`.
- `redact_document(document)` — recursive traversal; secret-like keys at any depth have values hashed.

## Evidence

- `artifact_evidence()` — raw mock output as ARTIFACT evidence (confidence=HIGH, reference=target).
- `observation_evidence()` — typed OBSERVATION evidence (confidence per policy, raw_data=JSON dump of observation model).
- `existing_evidence_id()` — dedup check via `evidence_dedup_key_for()`; duplicate reruns return the same evidence IDs.
- Each observation evidence record links to its artifact via `EvidenceRelation.DERIVED_FROM`.

## Memory Integration

The engine calls `_materialize_memory()` after world materialization, linking observation evidence to memory via `EvidenceMemoryBridge`. Exceptions are caught and logged as warnings (best-effort).

## World Model

### Identity Rules

- **APPLICATION** entities are named by **hostname** because canonical `_NAME_NORMALIZERS[EntityType.APPLICATION] == "hostname"`. This is a canonical rule; do not change it.
- **ENDPOINT** entities are named by **URL**.
- **API** entities are named by **URL**.

### Mapping

| Observation kind | World Model target |
|---|---|
| application | APPLICATION entity (name=host, url/tech/tls in properties) |
| endpoint | ENDPOINT entity (name=url) + APPLICATION CONTAINS ENDPOINT |
| api | API entity (name=url) + APPLICATION CONTAINS API |
| security_header, cookie, cors, auth_surface, openapi, graphql | ASSERTIONS on the host's APPLICATION entity |
| request_response | ASSERTIONS on the observed ENDPOINT entity + APPLICATION CONTAINS ENDPOINT |

Analysis observations become **assertions** (not entity properties) so reruns never churn entity versions. Entities only change when the direct surface observations change.

### No Attack-Graph Relationship Types

No `EXPLOITS`, `CAN_COMPROMISE`, `LEADS_TO`, or `ENABLES` relationship types are introduced. Only `CONTAINS` is used.

## Confidence Policy

| Mode / Kind | Confidence |
|---|---|
| PASSIVE (all kinds) | LOW |
| ACTIVE + application/endpoint/request_response | HIGH |
| ACTIVE + security_header/cookie/cors/auth_surface/api/openapi/graphql | MEDIUM |

The LLM must not override this policy.

## Authorization

`WebApiEngine._enforce_authorization()` calls `AuthorizationBoundary.authorize()` **before** transport execution. It raises `AuthorizationError` on `"denied"` or `"requires_approval"` decisions. Scope validation (`TargetScope`) checks allowed targets and allowed capabilities.

## Safety Controls

- GET-only request/response observation; no payloads, credentials, or mutating requests.
- Response-size limits enforced via `max_observations` (default 500, max 10,000).
- Timeouts enforced via `timeout_seconds` (default 30.0).
- Rate limiting enforced via mock `error` kind → `RATE_LIMITED` status.
- Sensitive headers redacted at the mock boundary.
- Secret-like values never persisted anywhere (evidence, memory, world model).
- Mock transport cannot accidentally become an arbitrary network client (no `socket`, `requests`, `http.client`, etc.).
- No generic shell executor (`execute_command`, `shell`, `run_command` absent).
- Unknown capabilities rejected with `WebApiExecutionError`.
- Out-of-scope targets rejected via `_target_type_allowed` and authorization.

## Failure Statuses

| Condition | Status |
|---|---|
| Successful complete observation | SUCCESS |
| Warnings with observations | PARTIAL |
| Truncation (max_observations reached) | LIMITED |
| No observations + warnings | NO_EVIDENCE |
| `rate_limited` error kind | RATE_LIMITED |
| `unauthorized` error kind | UNAUTHORIZED |
| `malformed`/`malformed_response` error kind | MALFORMED_RESPONSE |
| Other error kinds | REQUEST_FAILED |
| Connection refused | REQUEST_FAILED |

Exceptional paths raise (not silently convert): `AuthorizationError`, `WebApiNormalizationError`, `WebApiTimeoutError`, `WebApiExecutionError`.

## Current Limitations

- All capabilities use the deterministic mock transport; no real HTTP.
- No authentication/credential attack probing (GET-only, no brute-force, no injection).
- No attack-graph relationship types.
- Phase 6 validation is **local only**; actual Google Colab validation remains pending user execution.
