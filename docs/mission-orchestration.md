# Real Mission Integration & Mission Orchestration

Phase 14.1 introduces a **bounded mission orchestration layer** that turns the
static, capability-based engine into a deterministic, evidence-gathering
mission loop. It is an *authorized, descriptive planning and observation*
surface — explicitly **not** an exploitation layer and **not** a system that
issues arbitrary commands.

The mission orchestrator is the **only** component allowed to decide whether a
planner proposal may execute. Nothing in the loop trusts the planner: every
proposed investigation passes, in order:

1. **registration gate** — the capability exists and the router maps it to an
   engine / adapter binding,
2. **authorization gate** — `AuthorizationBoundary` grants the call for the
   mission's scope,
3. **scope gate** — the target and capability are within the mission's
   `TargetScope`,
4. **adapter gate** — mock vs real-controlled selection is conditioned on the
   mission policy (`allow_real_controlled`) and the assessment profile,
5. **typed request construction** and bounded transport execution,
6. **normalization** into evidence, memory, world model and attack graph.

A real adapter never executes untrusted logic: it asks the OS resolver, talks
TLS, and reads bounded HTTP response metadata — all std-lib, read-only, and
never following redirects.

## Architecture

```
                 Development Console (UI)         <-- blackforge/ui
                          |
                          v
              DevelopmentConsoleService           <-- application/service API
                          |
                          v
                MissionOrchestrator               <-- the only decision maker
                          |
            +-------------+-------------+
            |             |             |          (reuses existing core)
   Authorization      TargetScope   CapabilityRouter
            |             |             |
   [mission scope]   [bounded]   [engine/real-adapter bindings]
                          |
              evidence -> memory -> world model -> attack graph
```

The orchestrator reuses the existing mission manager, authorization boundary,
capability registry, evidence store, world model and attack graph components —
it introduces **no parallel authorization system**.

## Mission Lifecycle

A mission is created from a validated **seed target** and a bounded
`TargetScope` built around it:

* the seed target must be non-empty and a single host (no spaces, no shell
  metacharacters),
* the scope authorizes **no capability by default** — capabilities become
  usable only after the authorization and risk gates pass,
* the assessment profile (`authorized_assessment` / `controlled_demonstration`)
  caps risk; `controlled_demonstration` forces real-controlled adapters off,
* the execution budget (`MissionPolicy`) sets deterministic stop conditions.

## Execution Modes (MOCK / REAL / AUTO)

Every mission declares an **execution mode** in its `MissionPolicy`. The mode
is never inferred or silently upgraded/downgraded at runtime:

* **MOCK** — only deterministic mock transports run; real-controlled adapters
  are refused.
* **REAL** — a real, read-only transport is required. If the operator-level
  `allow_real_controlled` flag, the mission policy, or the assessment profile
  do not all permit a real transport, the loop stops with
  `REAL_MODE_GUARD` — it **never silently falls back to mock**.
* **AUTO** — real transport is preferred when authorized; when it is not, the
  loop falls back to the deterministic mock path and the fallback is recorded
  explicitly on the mission's LLM status (`invocation=FALLBACK`, `health=FAIL`).

The planner mode is declared separately (`mock` / `rule` / `llm`); requesting
`llm` with a mock-only provider is coerced to `rule` and recorded as
`invocation=NOT_USED`, never assumed. A real LLM provider that answers records
`invocation=REAL` (`health=PASS`); one that fails under AUTO is reported as a
fallback (`invocation=FALLBACK`, `health=FAIL`); under REAL mode a provider
failure fails the loop — no invisible downgrade is possible.

## Fail-Closed Planning

Planners return a single typed `PlannerDecision` that names a **registered
capability** and an **in-scope target**. It can never name a shell command, a
URL to fetch, or an unregistered capability. Unknown capabilities and
out-of-scope targets fail closed; repeated invalid plans or planner
infrastructure failures stop the loop deterministically.

## Deterministic Stop Conditions

The loop terminates on any of:

* `MAX_STEPS`
* `MAX_CAPABILITY_CALLS`
* `MAX_RUNTIME`
* `MAX_REPLANS`
* `REPEATED_INVALID_PLANNER`
* `DUPLICATE_EVICTION`
* `EVIDENCE_SATURATION`
* `REAL_MODE_GUARD` — REAL asked for but no real transport is authorized
* `CANCELLED`
* a planner-requested stop (`NO_ACTIONS_REMAIN`)

## Real-Controlled Read-Only Observation

Four bounded, std-lib adapters are installed on the orchestrator:

* `recon.dns`
* `recon.tls_metadata`
* `recon.http_metadata`
* `webapi.security_header_analysis`

They only fire when the mission policy **and** the operator-level
`allow_real_controlled` flag are both set and the profile permits it. Their
output is normalized into **redaction-safe** evidence (secret-like headers are
hashed before anything is returned), and every real observation row is
provenance-tagged `REAL` so mock and real evidence can never be confused.

## Evidence-Backed Findings

After a run, the orchestrator materializes mission **findings**: instance-level
conclusions derived deterministically from the mission's evidence rows. Each
finding:

* is ranked by an **epistemic status** (`observed` / `inferred` /
  `hypothesized` / `validated`) chosen from the evidence's confidence and mode,
* records its **source capability**, target, and the confidence it was derived
  from,
* is **never self-validated** — a finding cannot be its own authority; the
  `validation_state` field asserts this,
* feeds the mission report rendered by the Development Console.

## Module Layout

* `blackforge/evidence/models.py` — owns `EvidenceSource` (the evidence
  package stays a leaf; `orchestration.models` re-exports it)
* `blackforge/orchestration/models.py` — typed contracts (planner decisions,
  policy, execution modes, capability view, findings, mission runtime state)
* `blackforge/orchestration/orchestrator.py` — the deterministic loop, gates,
  mode enforcement, and invocation recording
* `blackforge/orchestration/planner.py` — `MockPlanner`, `RuleBasedPlanner`,
  `LLMPlanner`, fail-closed wrappers
* `blackforge/orchestration/routing.py` — capability registry -> engine/adapter
  routing and mission-aware capability views
* `blackforge/orchestration/adapters.py` — real-controlled read-only adapters

## Safety Model

* The UI can never bypass the orchestrator (see
  [Development Console](development-console.md)).
* The orchestrator never spawns a process, evals code, or runs a generic shell
  command — an AST security scan asserts this.
* Plan steps are evidence-gathering suggestions, never exploitability claims.
