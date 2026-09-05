# Authentication & Authorization

## Architecture

The Authentication & Authorization capability foundation mirrors the `webapi/` architecture:

- **`blackforge/auth/engine.py`** (`AuthEngine`) — orchestrates the full pipeline: request validation → scope/authorization check → test-identity enforcement → mock transport execution → normalization → evidence persistence → World Model materialization → best-effort memory link. `METHOD_TO_CAPABILITY` maps tool methods to capability IDs; `_ERROR_KIND_TO_STATUS` maps error kinds to statuses.
- **`blackforge/auth/capabilities.py`** — eleven typed `AuthCapability` instances, each bound to a mock transport method and a normalization adapter. `build_auth_capabilities()` returns all eleven; `build_auth_meta()` returns their metadata.
- **`blackforge/auth/transport.py`** (`MockAuthTransport`) — deterministic, mock-only authentication/authorization transport. Known demo hosts use a fixed dataset; unknown hosts yield a stable hash-derived dataset. Never touches the network and never returns real credentials.
- **`blackforge/auth/normalization.py`** — eleven `AuthToolAdapter` subclasses (one per capability) that parse mock raw output into typed observation models. `adapter_for_tool()` routes each transport method to its adapter; strict `_access_from_document()` parsing ensures a redirect never yields ALLOWED and a network error never yields DENIED.
- **`blackforge/auth/evidence.py`** — `artifact_evidence()` and `observation_evidence()` construct evidence records; `observation_confidence()` implements the confidence policy; `evidence_dedup_key_for()` and `existing_evidence_id()` enable idempotent reruns.
- **`blackforge/auth/materializer.py`** (`AuthWorldMaterializer`) — maps typed observations into World Model records: APPLICATION (named by hostname), AUTHENTICATION (named by scheme, namespaced by host), ENDPOINT **REQUIRES** AUTHENTICATION, and the IDENTITY --HAS_ROLE--> ROLE --HAS_PERMISSION--> PERMISSION --APPLIES_TO--> RESOURCE chain. Analysis assertions are bound to the host APPLICATION or IDENTITY.
- **`blackforge/auth/redaction.py`** — credential-like keys are force-redacted to the literal `REDACTED` marker; session/token *values* render as one-way sha-256 digests. Re-exports `blackforge.webapi.redaction` helpers (`redact_secret`, `redact_document`, `redact_headers`).
- **`blackforge/auth/models.py`** — `AuthMode`, `AuthStatus`, eleven observation models discriminated by `"kind"`, `AuthRequest`, `AuthResult`. `AuthRequest` carries `test_identities` for controlled access validation.
- **`blackforge/core/errors.py`** — `AuthError`, `AuthNormalizationError`, `AuthExecutionError`, `AuthTimeoutError`.

## Capabilities

| ID | Name | Mode | Risk | Produces |
|---|---|---|---|---|
| `auth.authentication_surface` | Authentication-Surface Observation | ACTIVE | LOW | AUTH_SURFACE |
| `auth.session_observation` | Session Observation | ACTIVE | MEDIUM | SESSION |
| `auth.authentication_scheme_detection` | Scheme Detection | PASSIVE | LOW | AUTH_SCHEME |
| `auth.oauth_metadata_observation` | OAuth Metadata Observation | PASSIVE | LOW | OAUTH_METADATA |
| `auth.oidc_metadata_observation` | OIDC Metadata Observation | PASSIVE | LOW | OIDC_METADATA |
| `auth.mfa_surface_observation` | MFA Surface Observation | ACTIVE | MEDIUM | MFA_SURFACE |
| `auth.authorization_surface` | Authorization-Surface Observation | PASSIVE | MEDIUM | AUTHORIZATION_SURFACE |
| `auth.role_observation` | Role Observation | PASSIVE | MEDIUM | ROLE |
| `auth.permission_observation` | Permission Observation | PASSIVE | MEDIUM | PERMISSION |
| `auth.resource_access_observation` | Resource-Access Validation | ACTIVE | HIGH | RESOURCE_ACCESS |
| `auth.access_control_comparison` | Access-Control Comparison | ACTIVE | HIGH | ACCESS_CONTROL |

Registry counts: defaults-only → 1, recon + defaults → 7, + webapi → **17**, + auth → **28**.

## Transport Abstraction

`MockAuthTransport` is the only transport. It never touches the network and never guesses, submits, or brute-forces credentials. Each capability method returns a JSON record. Error records carry an `error` dict with a `kind` field. The engine maps `kind` to `AuthStatus`:

- `rate_limited` → RATE_LIMITED
- `unauthorized` → UNAUTHORIZED
- `malformed`, `malformed_response` → MALFORMED_RESPONSE
- `connection_refused` → REQUEST_FAILED
- anything else → REQUEST_FAILED

Known demo hosts use fixed datasets (`web.example.com`, `api.example.com`, `auth.example.com`, `legacy.example.com`, `mail.example.com`, `throttled.example.com`, `unreachable.example.com`); unknown hosts yield a deterministic hash fallback using public test IP ranges.

## Observation Models

All observations are discriminated unions keyed on `"kind"`:

- `AuthSurfaceObservation` (kind=auth_surface) — url, host, scheme, scheme_type, parameter_name, note
- `SessionObservation` (kind=session) — url, host, name, **value_hashed** (sha-256 digest), domain, path, flags, secure, httponly, samesite, expires, note
- `AuthenticationSchemeObservation` (kind=auth_scheme) — url, host, scheme, present, password_policy, password_policy_observed, session_timeout_minutes, note
- `OAuthMetadataObservation` (kind=oauth_metadata) — url, host, authorization_endpoint, token_endpoint, grant_types, scopes, pkce_supported, note
- `OidcMetadataObservation` (kind=oidc_metadata) — url, host, issuer, jwks_uri, discovery_url, userinfo_endpoint, subject_type, id_token_signing_alg, note
- `MfaSurfaceObservation` (kind=mfa_surface) — url, host, mfa_status, factors, prompt_observed, note
- `AuthorizationSurfaceObservation` (kind=authorization_surface) — url, host, authz_model, enforcement, note
- `RoleObservation` (kind=role) — url, host, role, description, scope, note
- `PermissionObservation` (kind=permission) — url, host, identity, role, permission, resource, granted, credential_used, credential_type, **credential_value** (literal `REDACTED`)
- `ResourceAccessObservation` (kind=resource_access) — url, host, identity, role, resource, access, credential_used, credential_type, **credential_value** (literal `REDACTED`)
- `AccessControlObservation` (kind=access_control) — url, host, identity, role, resource, access, expected_access, consistent, credential_used, credential_type, **credential_value** (literal `REDACTED`)

## Redaction

- Credential-like keys (`credential_value`, `password`, `token`, `authorization`, `cookie`, `set-cookie`, `secret`, `api_key`, `apikey`, `access_token`, `refresh_token`, `client_secret`, `credentials`) are force-replaced with the literal `REDACTED` marker — never a hash, so redaction is unambiguous.
- Session cookie and token *values* are rendered as one-way sha-256 digests (`value_hashed`) or `REDACTED:<16hex>`; plaintext never reaches evidence, memory, or world model layers.
- `redact_credential_fields()` (recursive) and `redact_nested_credential_values()` (recursive value sweep) are applied at the mock boundary on raw documents.
- `blackforge.auth.redaction` re-exports `redact_secret`, `redact_document`, and `redact_headers` from `blackforge.webapi.redaction` for callers needing a unified redaction surface.
- Tests assert no plaintext credential ever appears in raw output or persisted evidence.

## Evidence

- `artifact_evidence()` — raw mock output as ARTIFACT evidence (confidence=HIGH, reference=target).
- `observation_evidence()` — typed OBSERVATION evidence (confidence per policy, raw_data=JSON dump of observation model).
- `existing_evidence_id()` — dedup check via `evidence_dedup_key_for()`; duplicate reruns return the same evidence IDs.
- Each observation evidence record links to its artifact via `EvidenceRelation.DERIVED_FROM`.

## Memory Integration

The engine calls `_materialize_memory()` after world materialization, linking observation evidence to memory via `EvidenceMemoryBridge`. Exceptions are caught and logged as warnings (best-effort).

## World Model

### Identity Rules

- **APPLICATION** entities are named by **hostname** (canonical rule). **ENDPOINT** entities are named by **URL**.
- **AUTHENTICATION** entities are named by the **scheme** (e.g. `session_cookie`) and **namespaced by host**.
- **IDENTITY**, **ROLE**, **PERMISSION**, **RESOURCE** entities are all **namespaced by host** (canonical `_NAME_NORMALIZERS` rules); PERMISSION names use `permission::resource`.

### Mapping

| Observation kind | World Model target |
|---|---|
| auth_surface | AUTHENTICATION entity (name=scheme, ns=host) + ENDPOINT **REQUIRES** AUTHENTICATION (root endpoint `https://{host}/` if none exists, with APPLICATION CONTAINS ENDPOINT) + assertion on APPLICATION |
| role | ROLE entity (ns=host) + APPLICATION RUNS ROLE |
| permission | IDENTITY --HAS_ROLE--> ROLE --HAS_PERMISSION--> PERMISSION --APPLIES_TO--> RESOURCE (all ns=host) |
| session, auth_scheme, oauth_metadata, oidc_metadata, mfa_surface, authorization_surface | ASSERTIONS on the host's APPLICATION entity |
| resource_access, access_control | ASSERTIONS on the IDENTITY entity (VALIDATED epistemic status) |

Analysis observations become **assertions** (not entity properties) so reruns never churn entity versions. Exercised access results are recorded as **VALIDATED** assertions; observation-derived findings stay **OBSERVED** on the application.

### No Attack-Graph Relationship Types

Only `HAS_ROLE`, `HAS_PERMISSION`, `APPLIES_TO`, `REQUIRES`, `CONTAINS`, and `RUNS` are used. No `EXPLOITS`, `CAN_COMPROMISE`, `LEADS_TO`, or `ENABLES`.

## Confidence Policy

| Mode / Kind | Confidence |
|---|---|
| PASSIVE (all kinds) | LOW |
| ACTIVE + auth_surface / auth_scheme / session / oauth_metadata / oidc_metadata / mfa_surface / authorization_surface | HIGH |
| ACTIVE + role / permission (derived identity facts) | MEDIUM |
| ACTIVE + resource_access / access_control (validated outcomes) | HIGH |

The LLM must not override this policy.

## Authorization

`AuthEngine._enforce_authorization()` calls `AuthorizationBoundary.authorize()` **before** transport execution. It raises `AuthorizationError` on `"denied"` or `"requires_approval"` decisions. A strict `AuthorizationBoundary` is used; scope (`TargetScope`) checks allowed targets and allowed capabilities.

`_enforce_test_identities()` requires **explicit authorized test identities** for `auth.resource_access_observation` and `auth.access_control_comparison` — supplied via request `test_identities` or per-call `params`. A missing set raises `AuthExecutionError` ("requires explicit authorized test identities"); no default guessing ever occurs. Comparisons evaluate only the explicitly listed identities.

## Safety Controls

- Observation-only by design: no credential submission, guessing, forgery, escalation, or brute force is possible through this surface.
- Every `credential_value` is the literal `REDACTED` marker; session/token values are one-way digests; plaintext is never persisted or logged.
- Access results are fixed data; the transport never derives NEW access from an error or a redirect (redirect never ALLOWED, network error never DENIED).
- Timeouts enforced via `timeout_seconds` (default 30.0); response-size limits via `max_observations` (default 500, max 10,000).
- Rate limiting via mock `error` kind → `RATE_LIMITED`.
- Mock transport cannot become an arbitrary network client (no `socket`, `requests`, `http.client`, etc.).
- No generic shell executor and no auth-bypass method surface (scanned by tests).
- Unknown capabilities rejected with `AuthExecutionError`; out-of-scope targets denied via `_target_type_allowed` + authorization.

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
| `connection_refused` or other error kinds | REQUEST_FAILED |

Exceptional paths raise (not silently convert): `AuthorizationError`, `AuthNormalizationError`, `AuthTimeoutError`, `AuthExecutionError`.

## Current Limitations

- All capabilities use the deterministic mock transport; no real authentication/authorization probing.
- Access validation is limited to explicitly listed, pre-authorized test identities; no uncontrolled enumeration.
- No attack-path or escalation reasoning (relationship types stay non-offensive).
- Phase 7 validation is **local only**; actual Google Colab validation remains pending user execution.