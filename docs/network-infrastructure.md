# Network & Infrastructure

## Architecture

The Network & Infrastructure Capability Foundation mirrors the `recon/` /
`webapi/` / `auth/` / `business_logic/` architecture: a typed engine, typed
capabilities, a deterministic mock-only transport, normalization adapters,
evidence persistence, and World Model materialization — with **no real network
traffic, no free-form execution, and no offensive semantics**. Every probe is
observation-only against a fixed internal fixture.

- **`blackforge/network/engine.py`** (`NetworkEngine`) — guards and orchestrates
  the full pipeline: request validation → scope/authorization → bounded port
  validation → mock transport → normalization → evidence persistence (artifact +
  typed observations) → World Model materialization → best-effort memory link.
  `METHOD_TO_CAPABILITY` maps the eleven tool methods to capability IDs;
  `_ERROR_KIND_TO_STATUS` maps transport error kinds to `NetworkStatus`;
  `_PORTS_CAPABILITIES` identifies the five probe capabilities that take a
  bounded port list.
- **`blackforge/network/capabilities.py`** — eleven typed `NetworkCapability`
  instances, each bound to a transport method, a normalization adapter, and
  capability metadata. `build_network_capabilities()` builds all eleven;
  `build_network_meta()` builds their metadata.
- **`blackforge/network/transport.py`** (`MockNetworkTransport`) — deterministic,
  mock-only transport over the `internal.example` fixture topology (TEST-NET-2
  `192.0.2.0/24`, all addresses reserved documentation range). Never touches a
  network; port probing and banner captures iterate a fixed in-process dataset.
- **`blackforge/network/normalization.py`** — eleven `NetworkToolAdapter`
  subclasses that parse mock raw output into typed observation models.
  `adapter_for_tool()` routes each transport method to its adapter.
- **`blackforge/network/evidence.py`** — `artifact_evidence()` and
  `observation_evidence()` construct evidence records; `observation_confidence()`
  implements the confidence policy; the network mode is embedded in each stored
  raw payload so a PASSIVE observation never dedups onto (and silently inherits
  the confidence of) an ACTIVE record while repeated same-mode runs still
  coalesce; `evidence_dedup_key_for()` / `existing_evidence_id()` enable idempotent
  reruns.
- **`blackforge/network/materializer.py`** (`NetworkWorldMaterializer`) — maps
  typed observations into World Model records with a fixed, deterministic mapping.
  **No offensive edge types (EXPLOITS / CAN_COMPROMISE / LEADS_TO / ENABLES) are
  ever emitted.**
- **`blackforge/network/redaction.py`** — credential-like keys are force-redacted
  to the literal `REDACTED` marker (recursive field sweep + `credential_value`
  defense-in-depth + JSON banner redaction). Re-exports
  `blackforge.webapi.redaction` helpers (`redact_secret`, `redact_document`,
  `redact_headers`).
- **`blackforge/network/models.py`** — `NetworkMode` (PASSIVE/ACTIVE),
  `NetworkStatus` (twelve failure-aware outcomes), `PortState` (open/closed/
  filtered/unknown), `NetworkObservationKind`, eleven typed observation models
  discriminated by `"kind"`, `NetworkRequest`, `NetworkResult`.
- **`blackforge/core/errors.py`** — `NetworkError`,
  `NetworkNormalizationError`, `NetworkExecutionError`, `NetworkTimeoutError`.

## Capabilities

| ID | Name | Mode | Risk | Produces |
|---|---|---|---|---|
| `network.host_discovery` | Host Discovery | PASSIVE | LOW | HOST |
| `network.port_discovery` | Port Discovery | ACTIVE | MEDIUM | PORT |
| `network.service_observation` | Service Observation | ACTIVE | MEDIUM | SERVICE |
| `network.protocol_identification` | Protocol Identification | ACTIVE | MEDIUM | PROTOCOL |
| `network.banner_observation` | Banner Observation | ACTIVE | MEDIUM | BANNER |
| `network.dns_observation` | DNS Observation | PASSIVE | LOW | DNS |
| `network.tls_observation` | TLS Observation | ACTIVE | MEDIUM | TLS |
| `network.network_exposure_analysis` | Exposure Analysis | PASSIVE | LOW | EXPOSURE |
| `network.infrastructure_modeling` | Infrastructure Modeling | PASSIVE | LOW | INFRASTRUCTURE |
| `network.service_application_correlation` | Service-Application Correlation | PASSIVE | LOW | SERVICE_APPLICATION |
| `network.network_evidence_collection` | Network Evidence Collection | PASSIVE | MEDIUM | NETWORK_EVIDENCE |

Registry counts: defaults-only → 1, recon → 7, + webapi → 17, + auth → 28,
+ business logic → 39, + network → **50** (`network_ready`, eleven typed
capabilities).

## Safety Model

Every capability runs the identical guarded pipeline:

1. **Scope** — the target must be inside `TargetScope.allowed_targets`;
   otherwise an `AuthorizationError` is raised **before** any transport work.
2. **Bounded probes, fail-closed** — `NetworkRequest.ports` must be an explicit
   list of integers in `1..65535` for the five probe capabilities
   (`_PORTS_CAPABILITIES`). Non-list, empty, out-of-range, non-integer, or
   oversized port lists are rejected before transport.
3. **Deterministic mock transport** — the only transport iterates the
   `internal.example` fixture (reserved `192.0.2.0/24`). No real network traffic
   is ever produced; UDP probing is limited to the single mock DNS service;
   banners are size-capped and credential-redacted.
4. **Evidence integrity** — every observation persists with `OBSERVED`
   provenance and DERIVED_FROM links to its run's artifact; evidence is **never
   elevated** (no VALIDATED path in this phase), and a PASSIVE run produces
   LOW confidence records independent of any earlier ACTIVE run on the same
   target (mode is part of the stored payload, so dedup cannot cross modes).
5. **World Model** — descriptive/structural edges only; no offensive
   relationship types are materialized.
6. **Failure-aware statuses** — negative outcomes (unreachable, rate limited,
   filtered, malformed, unauthorized, out of scope, timeout, no evidence) are
   recorded as structured `NetworkStatus` results, never silent failures, and
   never become findings.

## Transport Abstraction

`MockNetworkTransport` is the only transport. The demo topology:

- Five functional hosts (`web`, `api`, `dns`, `mail`, `quiet`) on
  `internal.example`, three network devices (`gateway` `192.0.2.1`,
  `core-switch` `192.0.2.2`, `firewall` `192.0.2.3`) in the `internal`
  segment, and one quiet host with no open/documented ports (a warning
  `no open or documented ports for the target`, NO_EVIDENCE).
- Seven fixed negative-outcome hosts, each carrying an `error` dict whose
  `kind` is mapped to a status by the engine:

| Error host | `error.kind` | Status |
|---|---|---|
| `refused…` (192.0.2.21) | `connection_refused` | REQUEST_FAILED |
| `slow…` (192.0.2.22) | `timeout` | TIMEOUT |
| `throttled…` (192.0.2.23) | `rate_limited` | RATE_LIMITED |
| `filtered…` (192.0.2.24) | `filtered` | FILTERED |
| `malformed…` (192.0.2.25) | `malformed_response` | MALFORMED_RESPONSE |
| `unauthorized…` (192.0.2.26) | `unauthorized` | UNAUTHORIZED |
| `others…` (192.0.2.27) | `out_of_scope` | OUT_OF_SCOPE |

Any unmodeled target yields a stable `connection_refused` error document.

Deterministic fixture behavior (verified by tests and the validation notebook):

- `discover_hosts("192.0.2.0/24")` → 5 host observations (excludes the quiet
  host's host row semantics by listing functional hosts).
- Bounded probing: `discover_ports("web.internal.example", ports=[22,80,443])`
  → 3 port observations; services 3; protocols 3; banners 3; tls 1.
- `observe_dns` → 8 DNS records; `analyze_exposure` → 2; `model_infrastructure`
  → 4; `correlate_service_applications` → 3; `collect_network_evidence` → 1.

## Observation Models

All observations are discriminated unions keyed on `"kind"`:

- `HostObservation` (kind=host) — host, ip, domain, is_network_device, role, operating_system
- `PortObservation` (kind=port) — host, ip, port, transport, **state** (`open`/`closed`/`filtered`/`unknown`), service
- `ServiceObservation` (kind=service) — host, ip, port, transport, service, version
- `ProtocolObservation` (kind=protocol) — host, ip, port, transport, protocol
- `BannerObservation` (kind=banner) — host, ip, port, transport, service, banner, **truncated**
- `DnsObservation` (kind=dns) — server, name, record_type, value, ttl
- `TlsObservation` (kind=tls) — host, ip, port, version, certificate_subject, certificate_issuer, certificate_expiry, cipher_suite
- `ExposureObservation` (kind=exposure) — host, ip, interface, exposed, public
- `InfrastructureObservation` (kind=infrastructure) — host, infrastructure, role, network_device
- `ServiceApplicationObservation` (kind=service_application) — host, ip, service, application, port
- `NetworkEvidenceObservation` (kind=network_evidence) — host, ip, detail

The mock dataset demonstrates the whole flow end to end: `web` runs
SSH/HTTP/HTTPS with a TLSv1.3 certificate; `api` runs HTTP + a TLSv1.3 gateway
with a JSON banner containing `access_token`, `api_key`, and
`credentials.api_password` values (the redaction demo target) and an
`inventory_api` service; `mail` runs SMTP; exposure marks internal interfaces;
the three devices and DNS/secrets infrastructure are modeled; and
`service_application_correlation` maps `web`→`web_app`, `api`→`api_gateway`,
`inventory`→`inventory_api`.

## World Model Semantics

The mapping is fixed and deterministic:

- HOST --HAS_PORT--> PORT --RUNS_SERVICE--> SERVICE --USES_PROTOCOL--> PROTOCOL
  (from host/port/service/protocol observation). Hosts are named by IP and
  namespaced by hostname (canonical), e.g. `host|web.internal.example|192.0.2.10`.
- HOST --HAS_INTERFACE--> INTERFACE (from exposure observations);
  HOST --MEMBER_OF--> NETWORK/INFRASTRUCTURE (from infrastructure observations,
  e.g. all devices in the `internal` segment); SERVICE --SERVES--> APPLICATION
  (from service-application correlation).
- Banner/TLS/DNS/evidence outcomes become assertions on the host so a re-run
  never churns entity versions: `banner.<port>`, `banner_truncated.<port>`,
  `tls.<port>`, `tls_cert.<port>`, `network_evidence.<host>`.
- Provenance is preserved: entities, relationships, and assertions carry their
  evidence links; every evidence row is linked to its run's artifact via
  DERIVED_FROM. No attack-graph relationship types are ever materialized.

## Confidence Policy

- PASSIVE mode → LOW confidence (observation/inference only, applied
  unconditionally).
- ACTIVE direct observations (host/port/service/protocol/banner/dns/tls) → HIGH.
- Derived kinds (exposure/infrastructure/service_application/network_evidence)
  → MEDIUM (`observation_confidence` lowers PASSIVE to LOW before any kind rule).

## Redaction

Credential-like keys (`password`, `passwd`, `token`, `access_token`,
`refresh_token`, `id_token`, `client_secret`, `secret`, `authorization`,
`cookie`, `api_key`, `apikey`, `key`, `mfa_code`, `otp`, `totp`,
`credential`, `credential_value`, ...) are force-replaced with the literal
`REDACTED` marker — never a hash, so redaction is unambiguous.
`redact_credential_fields()` (recursive) and `redact_nested_credential_values()`
(recursive `credential_value` sweep) run at the redaction boundary;
`redact_banner_text()` parses JSON banners and applies the same key-level
redaction before re-serializing. The auth/webapi `redact_secret` /
`redact_document` / `redact_headers` helpers are re-exported. Tests assert no
plaintext credential-like value ever appears in raw output or persisted evidence
(artifact payloads, observation rows, and world-model assertions alike).