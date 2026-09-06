# Blackforge Phase Validation Record

Chronological record of per-phase validation. **Validation type matters:**
- **GOOGLE COLAB** — executed on a real Google Colab runtime (recorded results below).
- **LOCAL ONLY** — the same notebook cells executed on the development machine (inside
  the project's venv via a local nbconvert runner, with cells that require a repo clone,
  install, and Colab-only paths skipped). A local PASS proves the notebook logic and the
  package; it is **not** a Google Colab execution and is never labeled as one.

| Phase | Name | Commit | Validation type | Test result | Colab result | Notes / limitations |
|---|---|---|---|---|---|---|
| 0 | Foundation & Rules | `4587ebe` | LOCAL ONLY | foundation tests pass | — | validated by `notebooks/blackforge_bootstrap.ipynb` |
| 1 | Runtime LLM Infrastructure | `1e54de4` | LOCAL + GOOGLE COLAB (free-tier CPU, Python 3.13, Sept 2026) | 177 tests pass | PASS — real HF inference (`Qwen/Qwen2.5-0.5B`, float32) | hardware-aware model selection; see Phase 1 section below |
| 2 | Persistent Memory | `43d63b6` | LOCAL ONLY | full suite pass | — | lightweight notebook; no torch required |
| 3 | Evidence & Memory Integration | `9041d57` | LOCAL ONLY | full suite pass | — | no-fake-authority semantics corrected vs Phase 2 notebook |
| 4 | World Model Foundation | `c2c7191` | LOCAL ONLY | full suite pass | — | offensive edge types rejected at enum layer |
| 5 | Reconnaissance Capability Foundation | `c9c2e67` | LOCAL ONLY | full suite pass (438 passed, 3 skipped at this phase) | — | mock adapters only; no network I/O |
| 6 | Web & API Security | `6705276` | LOCAL ONLY | full suite pass (192 passed, 2 skipped) | — | mock transport only; GET-only; redaction at boundary |
| 7 | Authentication & Authorization | `20bea56` | LOCAL ONLY | full suite pass (681 passed, 5 skipped at this phase) | — | observation-only; redaction at boundary (literal `REDACTED`/digests); explicit test identities required |
| 8 | Business Logic & Attack Paths | `10c54f6` | LOCAL ONLY | full suite pass (765 passed, 5 skipped at this phase) | — | deterministic workflow/rule/role modeling; explicit test identities; fail-closed replay gating; VALIDATED only via validation; no attack-graph relationship types |
| 9 | Network & Infrastructure | `5bf7d8b` | LOCAL ONLY | full suite pass (830 passed, 5 skipped at this phase) | — | deterministic mock topology (`internal.example`, reserved `192.0.2.0/24`); bounded fail-closed port probes; size-capped + credential-redacted banners; mode-aware evidence dedup (PASSIVE never inherits ACTIVE confidence); failure-aware statuses; no attack-graph relationship types |
| 10 | Identity / Active Directory | `835f0de` | LOCAL ONLY | full suite pass (881 passed, 5 skipped at this phase) | — | deterministic mock directory (`AELIONIX-CORP`, no real queries, no mutation); identity/group/role/permission/resource inventories + membership/role/permission/relationship/metadata observations; credential-material redaction (literal `REDACTED`) before any evidence row or world record; duplicates deterministically collapsed; metadata contradictions surfaced (authoritative OBSERVED vs correlated INFERRED); mode-aware evidence dedup (PASSIVE never inherits CONTROLLED confidence); failure-aware statuses incl. UNSUPPORTED_DIRECTORY / NO_EVIDENCE; identity entities namespaced by directory; no attack-graph relationship types |

Latest committed phase at the time of writing: **Phase 10** (`835f0de`).

---

## Phase 1 Colab Validation

## How to Open

Click the **Open in Colab** badge in the repository README, or manually open the notebook:

```
notebooks/blackforge_phase1_colab.ipynb
```

in Google Colab: https://colab.research.google.com

## What It Validates

The notebook performs a sequential, deterministic validation of the entire Phase 1 runtime:

| Stage | What it checks |
|---|---|
| Repository | Clones/updates repo, verifies commit history |
| Dependencies | Installs `blackforge[dev,llm]` (plus `hatchling` build backend) |
| Imports | All 24 Blackforge backend modules load cleanly |
| Tests | Full `pytest -q` suite (177 tests) |
| Bootstrap | `BlackforgeApp.healthy()` and `verify()` pass |
| Hardware | GPU/CPU detection via PyTorch + nvidia-smi |
| Real inference | HuggingFace model loads and generates output through provider abstraction |
| Structured output | JSON extraction, schema validation, parsed result |
| Tool-call flow | LLM → ToolCall → CapabilityRegistry → CapabilityResult → ChatContext |
| ModelRouter | All 6 TaskCategory routes + custom routing rules + health check |

## Expected Successful Output

The final cell prints:

```
============================================================
BLACKFORGE PHASE 1 VALIDATION
============================================================
Repository              PASS
Imports                 PASS
Automated tests         PASS
Bootstrap               PASS
Hardware                PASS
Real inference          PASS
Structured output       PASS
Tool-call flow          PASS
Model router            PASS
============================================================
OVERALL RESULT: PASS
============================================================
```

## What a Failed Test Means

- **Repository FAIL** — Git clone failed or repo structure changed
- **Imports FAIL** — A required module has a broken import (check `importlib` error)
- **Tests FAIL** — One or more pytest tests failed (check stderr above)
- **Bootstrap FAIL** — `BlackforgeApp` health check failed (config or LLM provider issue)
- **Hardware FAIL** — Should not happen (CPU fallback always works)
- **Real inference FAIL** — Model failed to load or generate output (memory, network, or transformers issue)
- **Structured output FAIL** — Model output could not be parsed as JSON matching the schema
- **Tool-call flow FAIL** — ToolCall normalization or CapabilityRegistry issue
- **Model router FAIL** — Routing rule or health check failure

## GPU Recommendations

The notebook auto-detects hardware and selects the model accordingly:

| Runtime | Model | Dtype | Notes |
|---|---|---|---|
| GPU (T4+) | Qwen/Qwen2.5-3B-Instruct | float16 | Default, works well |
| GPU (L4/A100) | Qwen/Qwen3-8B | float16 | Better quality (manual override) |
| No GPU (CPU) | Qwen/Qwen2.5-0.5B-Instruct | float32 | Auto-fallback, ~1 GB — fits free-tier RAM |

A 3B model in float32 (~6.7 GB) on a CPU-only runtime can OOM-kill the kernel; the notebook avoids this by picking the 0.5B model when no CUDA is detected.

## Important Notes

1. **First run downloads the model.** Qwen2.5-3B-Instruct is approximately 6 GB (GPU runtimes). CPU runtimes download Qwen2.5-0.5B-Instruct (~1 GB). Subsequent runs use the cached model.
2. **No offensive security actions.** The notebook runs a harmless validation prompt only.
3. **No secrets required.** The notebook uses local models only — no API keys needed.
4. **Rerunnable.** Safe to re-run on the same Colab instance. Cached model and installed packages are reused.
5. **CPU runtimes are slow but work.** Expect real inference to take several seconds on CPU vs sub-second on a T4.
6. **Avoid upgrading Colab's kernel packages.** The `colab` extra pulls in `ipython`/`jupyterlab`/`notebook`, which conflict with Google's pinned versions and can make the runtime unstable (stuck reconnects, random SIGKILL). If this happens, do **Runtime → Disconnect and delete runtime** and re-run from the top.

## Colab Execution Result

Executed on a free-tier **CPU** runtime (Python 3.13), September 2026:

```
============================================================
BLACKFORGE PHASE 1 VALIDATION
============================================================
Repository                PASS
Imports                   PASS
Automated tests           PASS
Bootstrap                 PASS
Hardware                  PASS
Real inference            PASS
Structured output         PASS
Tool-call flow            PASS
Model router              PASS
============================================================
OVERALL RESULT: PASS
============================================================
```

Real HuggingFace inference ran end-to-end on CPU with `Qwen/Qwen2.5-0.5B-Instruct` (float32), through the full provider abstraction chain.

## Known Fixes Applied During Validation

| Issue | Fix |
|---|---|
| Silent install failure (`--quiet \| tail -5` hid errors) | Install cell shows full `pip` output |
| `hatchling` not present before editable install | Explicit `pip install hatchling` first |
| Invalid PyPI classifier `Intended Audience :: Information Technology Industry` | Removed — broke metadata generation for editable installs |
| OOM kernel kill on CPU (3B float32) | Hardware-aware model selection: 0.5B on CPU, 3B float16 on GPU |
| `verify_inference()` missing `provider` key | Added `"provider": "huggingface"` to the diagnostics dict |

## Phase 2 Validation Notebook

`notebooks/blackforge_phase2_colab.ipynb` validates the Phase 2 persistent
memory foundation. It installs only `blackforge[dev]` (no torch/transformers,
so it is lightweight and OOM-free on CPU runtimes) and checks:

| Stage | What it checks |
|---|---|
| Import health | All memory/evidence/bootstrap modules load cleanly |
| Automated tests | Full `pytest -q` suite |
| Bootstrap | `app.healthy()` and `memory_ready` health check |
| Restart persistence | Write → close → reopen → retrieve on a fresh SQLite connection |
| Deduplication | Idempotent writes return the same ID, no duplicate rows |
| Logical versioning | Content change supersedes v1, creates v2 atomically |
| Structured search | Mission/session/status/lifecycle/source/confidence/tags/keyword filters |
| Transaction atomicity | Mid-transaction failure rolls back everything |
| Evidence integration | Memory references evidence by ID; hashes match the EvidenceStore |
| In-memory parity | `in_memory` backend behaves identically |

Expected final output:

```
============================================================
BLACKFORGE PHASE 2 VALIDATION (PERSISTENT MEMORY)
============================================================
Repository                   PASS
...
OVERALL RESULT: PASS
============================================================
```

See `docs/memory.md` for the full memory architecture.

## Phase 3 Validation Notebook

`notebooks/blackforge_phase3_colab.ipynb` validates the Phase 3
Evidence ↔ Memory Integration & Evidence Lifecycle subsystem. Like Phase 2 it
installs only `blackforge[dev]` (no torch/transformers), so it is lightweight
and OOM-free on CPU runtimes.

| Stage | What it checks |
|---|---|
| Import health | All evidence/memory/bootstrap modules load cleanly |
| Automated tests | Full `pytest -q` suite (evidence lifecycle + bridge included) |
| Bootstrap | `app.healthy()`, `evidence_store_ready`, `evidence_memory_link_ready` |
| No fake authority | LLM claim → `HYPOTHESIZED`; direct `VALIDATED` creation rejected; only `add_validation` reaches `VALIDATED` (+ `VALIDATES` link) |
| Status transitions | Legal moves applied, illegal downgrades raise, confidence changes audited and status-independent |
| Lifecycle | Supersede marks the old record without rewriting its status/history |
| Relationships | Typed links incl. `CORROBORATES` filter retrieval |
| Contradiction | Both records stay `ACTIVE`, linked by `CONTRADICTS`, nothing deleted |
| Dedup | Identical evidence same ID, distinct evidence separate IDs |
| Evidence ↔ memory | Materialize memory referencing evidence; reverse lookups both ways |
| Restart persistence | Evidence + relationships + linked memory survive close/reopen on fresh SQLite connections |
| Compensation boundary | Failing memory write leaves no dangling memory record (evidence remains authoritative) |

Expected final output:

```
============================================================
BLACKFORGE PHASE 3 VALIDATION (EVIDENCE <-> MEMORY INTEGRATION)
============================================================
Repository                             PASS
...
OVERALL RESULT: PASS
============================================================
```

See `docs/evidence.md` for the full evidence architecture.

> **Behavioral change vs Phase 2:** the Phase 2 notebook's Evidence Integration
> cell creates `VALIDATED` evidence directly. Phase 3 intentionally forbids
> that (no fake authority). The Phase 2 notebook is kept as-is for historical
> record; the Phase 3 notebook demonstrates the corrected workflow.

## Phase 4 Validation Notebook

`notebooks/blackforge_phase4_colab.ipynb` validates the Phase 4
**World Model Foundation** subsystem. Like Phase 2/3 it installs only
`blackforge[dev]` (no torch/transformers), so it is lightweight and OOM-free
on CPU runtimes.

| Stage | What it checks |
|---|---|
| Import health | All world model modules load cleanly |
| Automated tests | Full `pytest -q` suite (world model included) |
| Bootstrap | `app.healthy()` + new `world_model_ready` flag |
| Identity & dedup | Deterministic canonical keys; same identity corroborates to one record; similar names never merged; namespaces scope identity |
| No fake authority | `OBSERVED` without evidence rejected; materializer floors status at `HYPOTHESIZED`; only evidence raises it |
| Direction rules | Directed `A→B` ≠ `B→A`; symmetric `CONNECTS_TO` dedups order-insensitively; self-loops and cross-mission edges rejected |
| Provenance | Evidence linked to relationships/entities, merged on corroboration, queryable in both directions |
| Confidence | Corroboration raises to maximum, never lowers; repetition alone never increases |
| Contradiction | Weaker claim → assertion, authoritative record untouched; inferred disagreement never overwrites |
| Supersession | Authoritative change supersedes, version + `supersedes` + full history preserved |
| Mission/session isolation | Same identity in another mission is a distinct record; session context narrows reads |
| Neighborhood | Bounded, deterministic, depth ≤ 2 — no pathfinding |
| Restart persistence | Entities, relationships, assertions and evidence links survive close/reopen on fresh SQLite connections |
| Rule integrity | Rule failures leave no partial state; health probes are self-cleaning |

Expected final output:

```
PHASE 4 VALIDATION SUMMARY
============================================================
  [PASS] repository
  [PASS] phase4_modules
  ...
  [PASS] restart_persistence
============================================================
RESULT: 15 passed, 0 failed

PHASE 4 VALIDATION: OVERALL PASS
```

See `docs/world-model.md` for the full world model architecture.

> **Scope note:** the world model stores *what is known and how it is known*.
> Offensive edge types (`LEADS_TO`, `ENABLES`, `EXPLOITS`, `CAN_COMPROMISE`,
> privilege-escalation paths) are rejected at the enum layer. An Attack Graph
> layer is explicitly out of scope for Phase 4.

## Phase 5 Validation Notebook

`notebooks/blackforge_phase5_colab.ipynb` validates the Phase 5
**Reconnaissance Capability Foundation** subsystem. It installs only
`blackforge[dev]` (no torch/transformers), so it is lightweight and OOM-free
on CPU runtimes.

| Stage | What it checks |
|---|---|
| Import health | All `blackforge.recon.*` modules load cleanly (27 modules total) |
| Automated tests | Full `pytest -q` suite (recon included) |
| Bootstrap | `app.healthy()` + new `recon_ready` flag (engine present, exactly 6 capabilities) |
| Capability surface | Six typed recon capabilities registered with expected ids |
| Pipeline | Capability → mock tool → normalization → evidence → world model → memory, per capability |
| Evidence integrity | Every observation row links `derived_from` its run's artifact; dedup keys stable |
| World materialization | Host→ASSET, service→SERVICE+exposes, technology→USES, HTTP/TLS→ENDPOINT |
| Idempotent reruns | Rerun returns identical evidence ids and unchanged world state |
| No generic executor | Only the six typed capability contracts exist |
| Scope authorization | Out-of-scope targets denied before tool execution |
| Capability authorization | Capabilities outside `allowed_capabilities` denied |
| Mission isolation | A second mission's run is fully disjoint in evidence and world state |
| Restart persistence | Fresh SQLite connections see the same evidence and world facts |

Expected final output (standard checklist structure shared with the Phase 1 notebook):

```
============================================================
BLACKFORGE PHASE 5 VALIDATION
============================================================
Repository                    PASS
Python                        PASS
Hardware                      PASS
Installation                  PASS
Imports                       PASS
Automated tests               PASS
Bootstrap                     PASS
Phase-specific tests          PASS
Security checks               PASS
============================================================
OVERALL RESULT: PASS
============================================================
```

`Phase-specific tests` aggregates the 13 reconnaissance checks (repository integrity,
phase-5 modules, imports, bootstrap `recon_ready`, no generic executor, capability
surface, pipeline evidence, world materialization, idempotent reruns, scope
authorization, capability authorization, mission isolation, restart persistence).
`Security checks` covers scope and capability authorization denial *before* tool execution.

Current Phase 5 notebook result: **executed locally, PASS.** No Google Colab execution
has been recorded for Phase 5 yet.

See `docs/reconnaissance.md` for the full reconnaissance architecture.

> **Scope note:** reconnaissance describes the environment (mock tool data, metadata only)
> and produces evidence-backed facts. It never exploits, never touches credentials, and
> never uses network I/O. Attack path reasoning remains out of scope.

---

## Phase 6 — Web & API Security

**Notebook:** `notebooks/blackforge_phase6_colab.ipynb`

**Validation type:** LOCAL ONLY

**Test result:** full suite pass (192 passed, 2 skipped)

**Colab result:** —

**Notes / limitations:** mock transport only; GET-only request/response behavior; redaction/hashing at boundary; failure-aware statuses (RATE_LIMITED, REQUEST_FAILED, NO_EVIDENCE, LIMITED, PARTIAL, SUCCESS); confidence policy enforced; no attack-graph relationship types; APPLICATION entities named by hostname (canonical).

### What Phase 6 Validates

- Ten typed web/api security capabilities registered and executable
- Full pipeline: capability → mock transport → normalization → evidence (artifact + DERIVED_FROM) → World Model → memory
- Authorization enforced before transport execution
- Unknown capabilities rejected; out-of-scope targets rejected
- Redaction: cookie values, Authorization headers, OpenAPI passwords hashed
- World Model: APPLICATION by hostname, ENDPOINT/API by URL, CONTAINS relationships, analysis assertions bound to correct entity
- Failure states: NO_EVIDENCE, RATE_LIMITED, REQUEST_FAILED, LIMITED all produce correct statuses
- Confidence policy: PASSIVE→LOW, direct ACTIVE→HIGH, document kinds→MEDIUM
- No network dependencies or banned imports in blackforge/webapi

See `docs/web-api-security.md` for the full architecture documentation.

---

## Phase 7 — Authentication & Authorization

**Notebook:** `notebooks/blackforge_phase7_colab.ipynb`

**Validation type:** LOCAL ONLY

**Test result:** full suite pass (681 passed, 5 skipped at this phase)

**Colab result:** —

**Notes / limitations:** observation-only (no credential guessing/forgery/escalation/brute force); redaction at boundary (literal `REDACTED` marker + one-way digests); explicit authorized test identities required for access-validation capabilities; strict authorization before transport execution; failure-aware statuses (NO_EVIDENCE, RATE_LIMITED, REQUEST_FAILED, LIMITED, PARTIAL, SUCCESS); confidence policy enforced; ENDPOINT REQUIRES AUTHENTICATION + IDENTITY→ROLE→PERMISSION→RESOURCE chain; no attack-graph relationship types.

### What Phase 7 Validates

- Eleven typed auth/authorization capabilities registered and executable
- Full pipeline: capability → mock transport → normalization → evidence (artifact + DERIVED_FROM) → World Model → memory
- Authorization enforced before transport execution; unknown capabilities rejected
- `auth_ready` bootstrap flag equal to 11 typed capabilities
- Redaction: session/token values as sha-256 digests; every `credential_value` literal `REDACTED`; no plaintext in raw output or evidence
- Explicit `test_identities` required for `auth.resource_access_observation` / `auth.access_control_comparison`; missing identities rejected
- World Model: APPLICATION by hostname, AUTHENTICATION by scheme (namespaced), ENDPOINT REQUIRES AUTHENTICATION, IDENTITY HAS_ROLE ROLE HAS_PERMISSION PERMISSION APPLIES_TO RESOURCE
- Assertions bound correctly: analysis → APPLICATION (OBSERVED), exercised access → IDENTITY (VALIDATED)
- No attack-graph relationship types (only has_role/has_permission/applies_to/requires/contains/runs)
- Failure states: NO_EVIDENCE, RATE_LIMITED, REQUEST_FAILED, LIMITED all produce correct statuses
- Confidence policy: PASSIVE→LOW, direct ACTIVE→HIGH, derived roles/permissions→MEDIUM, validated access→HIGH
- Mission isolation and restart persistence across fresh SQLite connections

See `docs/authentication-authorization.md` for the full architecture documentation.

---

## Phase 8 — Business Logic & Attack Paths

**Notebook:** `notebooks/blackforge_phase8_colab.ipynb`

**Validation type:** LOCAL ONLY

**Test result:** full suite pass (765 passed, 5 skipped at this phase)

**Colab result:** —

**Notes / limitations:** deterministic workflow/rule/role modeling; no free-form execution, no credential use, no autonomous identity discovery; explicit authorized test identities required for ownership/role-boundary/replay/validation capabilities; fail-closed replay gating (unknown actions and actions with unknown safety profiles are refused before transport); hypothesis evidence stays HYPOTHESIZED and only `business_logic_validation` elevates to VALIDATED; evidence rows DERIVED_FROM their run's artifact; WORKFLOW/STATE/ACTION/IDENTITY/ROLE/PERMISSION/RESOURCE materialized with has_workflow/has_state/has_action/transitions_to/operates_on/belongs_to/has_permission/applies_to only — no attack-graph relationship types.

### What Phase 8 Validates

- Eleven typed business-logic capabilities registered and executable
- Full pipeline: capability → mock transport → normalization → evidence (artifact + DERIVED_FROM) → World Model → memory
- Authorization enforced before transport execution; unknown capabilities rejected
- `business_logic_ready` bootstrap flag equal to 11 typed capabilities
- Scope denial before transport; explicit `test_identities` required (no guessing, no unauthorized identities)
- Fail-closed replay: PROHIBITED/unknown actions refused before transport; actions classified `bounded` only
- Mock dataset: anomalous `created -> shipped` transition detected, `only_paid_orders_ship` broken, `cancel_after_payment` elevated to validated
- Evidence elevation: HYPOTHESIZED records; VALIDATED only via validation; artifact rows never VALIDATED
- World Model: WORKFLOW + APPLICATION (has_workflow), STATES (has_state), ACTIONS with OPERATES_ON, TRANSITIONS_TO edges, RESOURCE --BELONGS_TO--> IDENTITY, ROLE --HAS_PERMISSION--> PERMISSION --APPLIES_TO--> RESOURCE; assertions with rule/invariant/replay/hypothesis/validation prefixes across the workflow revision chain
- No attack-graph relationship types materialized (EXPLOITS/CAN_COMPROMISE/LEADS_TO/ENABLES absent)
- Failure states: RATE_LIMITED, REQUEST_FAILED, MALFORMED_RESPONSE, TIMEOUT, LIMITED all produce correct statuses
- Mission isolation and restart persistence across fresh SQLite connections

See `docs/business-logic.md` for the full architecture documentation.

---

## Phase 9 — Network & Infrastructure

**Notebook:** `notebooks/blackforge_phase9_colab.ipynb`

**Validation type:** LOCAL ONLY

**Test result:** full suite pass (830 passed, 5 skipped at this phase)

**Colab result:** —

**Notes / limitations:** deterministic mock topology (`internal.example` on
reserved TEST-NET-2 `192.0.2.0/24`) — no real network traffic, no free-form
execution; bounded fail-closed port probes (explicit integer list in
`1..65535`, oversized/empty/non-integer/out-of-range rejected before
transport); size-capped + credential-redacted banners (literal `REDACTED`
marker, never a hash); **mode-aware evidence dedup** — PASSIVE observations
are LOW confidence and can never inherit an earlier ACTIVE record's HIGH
confidence (mode is part of the stored evidence payload), while repeated
same-mode runs still coalesce; failure-aware statuses (FILTERED, TIMEOUT,
RATE_LIMITED, MALFORMED_RESPONSE, UNAUTHORIZED, OUT_OF_SCOPE, REQUEST_FAILED,
NO_EVIDENCE); evidence rows DERIVED_FROM their run's artifact; hosts/ports/
services/protocols/interfaces/infrastructure/applications materialized with
has_port/runs_service/uses_protocol/has_interface/member_of/serves only — no
attack-graph relationship types.

### What Phase 9 Validates

- Eleven typed network capabilities registered and executable; `network_ready`
  bootstrap flag equal to 11 typed capabilities (registry total 50)
- Full pipeline: capability → mock transport → normalization → evidence
  (artifact + DERIVED_FROM) → World Model → memory
- Authorization enforced before transport execution; unknown capabilities and
  out-of-scope targets rejected
- Bounded port validation: `ports=[22]*70000` rejected before transport;
  non-list/empty/out-of-range ports rejected
- Scope denial before transport; metadata-scan CIDR hosts observed only
- Redaction: `access_token` / `api_key` / `credentials.api_password` values
  never appear in banner raw output, artifact payloads, observation rows, or
  world-model assertions
- World Model: HOST named by IP namespaced by hostname; PORT/SERVICE/PROTOCOL
  chain (has_port/runs_service/uses_protocol), HAS_INTERFACE from exposure,
  MEMBER_OF into the INFRASTRUCTURE segment, SERVICE --SERVES--> APPLICATION;
  banner/tls_cert/network_evidence assertions bound to the correct host
- Confidence policy: PASSIVE→LOW, direct ACTIVE→HIGH, derived→MEDIUM; mode-aware
  dedup verified (PASSIVE run after ACTIVE still LOW)
- No attack-graph relationship types materialized (EXPLOITS/CAN_COMPROMISE/
  LEADS_TO/ENABLES absent)
- Failure states: FILTERED, TIMEOUT, RATE_LIMITED, MALFORMED_RESPONSE,
  UNAUTHORIZED, OUT_OF_SCOPE, REQUEST_FAILED, NO_EVIDENCE all produce correct
  statuses; quiet host → NO_EVIDENCE + warning
- Mission isolation and restart persistence across fresh SQLite connections

See `docs/network-infrastructure.md` for the full architecture documentation.

---

## Phase 10 — Identity / Active Directory

**Notebook:** `notebooks/blackforge_phase10_colab.ipynb`

**Validation type:** LOCAL ONLY

**Test result:** full suite pass (881 passed, 5 skipped at this phase)

**Colab result:** —

**Notes / limitations:** deterministic mock directory (`AELIONIX-CORP` /
`AELIONIX-CORP.LOCAL`) — no real directory is ever queried or mutated, no
free-form execution; credential-material redaction at the boundary (literal
`REDACTED` marker, never a hash — `password_hash` / `session_token` /
`credentials.api_key` demo fields exist only to prove it); duplicates
deterministically collapsed (`observe_membership` emits duplicate rows, 1
observation out, PARTIAL + warning); metadata contradictions surfaced as
assertions (authoritative directory feed OBSERVED, correlated feed INFERRED,
`assertions_contradicted` counted) instead of silent overwrite; **mode-aware
evidence dedup** — PASSIVE observations are LOW confidence and can never
inherit an earlier CONTROLLED record's HIGH confidence; failure-aware statuses
(TIMEOUT, RATE_LIMITED, UNAUTHORIZED, MALFORMED_RESPONSE,
UNSUPPORTED_DIRECTORY, PARTIAL, NO_EVIDENCE); evidence rows DERIVED_FROM their
run's artifact; directory/identity/group/role/permission/resource materialized
with contains/member_of/has_role/has_permission/applies_to only — no attack-graph
relationship types.

### What Phase 10 Validates

- Eleven typed identity capabilities registered and executable; `identity_ready`
  bootstrap flag equal to 11 typed capabilities (registry total 61)
- Full pipeline: capability → mock transport → normalization → evidence
  (artifact + DERIVED_FROM) → World Model → memory
- Authorization enforced before transport execution; unknown capabilities,
  out-of-scope targets (`MINECORP`), and unsupported target types (IP) rejected
- Directory-aware scope matching: `AELIONIX-CORP` covers `AELIONIX-CORP.LOCAL`,
  UPN identities, down-level identities, and DNS sub-objects
- Redaction: `build-service.password_hash` / `session_token` and
  `api-service.credentials.api_key` values never appear in raw output, artifact
  payloads, observation rows, or world-model assertions
- World Model: DIRECTORY --CONTAINS--> identity/group/role/permission/resource;
  IDENTITY --MEMBER_OF--> GROUP, --HAS_ROLE--> ROLE; ROLE --HAS_PERMISSION-->
  PERMISSION; PERMISSION --APPLIES_TO--> RESOURCE; identity entities namespaced
  by directory (`identity|aelionix-corp|alice`)
- Metadata contradiction surfaced: `department=engineering` OBSERVED +
  `department=sales` INFERRED both persisted, contradiction recorded
- Confidence policy: PASSIVE→LOW, direct CONTROLLED→HIGH, relationship
  analysis→MEDIUM, correlated metadata feed→MEDIUM; mode-aware dedup verified
- No attack-graph relationship types materialized (EXPLOITS/CAN_COMPROMISE/
  LEADS_TO/ENABLES absent)
- Failure states: TIMEOUT, RATE_LIMITED, UNAUTHORIZED, MALFORMED_RESPONSE,
  UNSUPPORTED_DIRECTORY all produce correct statuses on synthetic error
  directories; unknown identity → NO_EVIDENCE; duplicates collapsed (PARTIAL)
- Mission isolation and restart persistence across fresh SQLite connections

See `docs/identity-directory-security.md` for the full architecture documentation.
