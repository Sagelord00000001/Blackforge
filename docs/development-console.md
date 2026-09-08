# Development Console (Temporary UI)

The **Development Console** is a *temporary* Blackforge UI used to prove the
Phase 14.1 mission-orchestration experience end-to-end: a target goes in, and
evidence-backed, redaction-safe results come out, all through the bounded
mission loop.

The console is deliberately thin. It provides no logic of its own about
security, scope, evidence storage, or the world model — it only **renders
read-only status** from the service layer and **requests** mission actions
through it.

## Layers & Separation

```
                 Development Console (UI)         <- blackforge/ui/console.py
                          |
                          v
             DevelopmentConsoleService             <- blackforge/ui/service.py
                          |
                          v
                 MissionOrchestrator               <- blackforge/orchestration
                          |
                          v
                     Blackforge core
```

* The **UI** (`DevelopmentConsole`) talks only to the **service**
  (`DevelopmentConsoleService`).
* The **service** is the single application API surface; every
  mission-creating and mission-running call funnels through the
  `MissionOrchestrator`, which enforces registration, authorization, scope and
  adapter gates.
* The UI/service layers expose **no method** to write evidence, mutate the
  world model, or bypass authorization/scope. They hold no handle to raw
  storage or a transport.

## Access Gating

The console is a *temporary* surface, so before it accepts any mission it
requires an **access token** (`AccessGate`):

* the token may be supplied via the `BLACKFORGE_CONSOLE_TOKEN` environment
  variable,
* if unset, a per-process random token is generated and printed by the console
  so an operator can unlock the running instance,
* the raw token is never written to disk or logs; comparison is constant-time,
* a **locked** console raises `ConsoleAccessDenied` before any work happens.

This gate prevents accidental ambient exposure of the temporary UI. It is
**not** a substitute for the orchestrator's own authorization/scope gates,
which remain authoritative.

## HTTP Server & Temporary Public URL

The console can be exposed over HTTP by a thin built-in server
(`blackforge/ui/server.py`):

* `GET /health` is **public** and returns `200 OK` so load balancers, tunnel
  health probes and notebooks can verify liveness,
* every other endpoint (e.g. `GET /api/status`) requires the console token via
  an `Authorization: Bearer <token>` header, checked against the same
  `AccessGate` as the local console,
* the server binds `127.0.0.1` and prints its local `base_url`.

To exercise the real **temporary public URL** requirement, the console server
is published through a tunnel (`blackforge/runtime/tunnel.py`) that tries, in
order, `cloudflared`, `ngrok`, and `localtunnel` — whichever binary is
available:

* the tunnel wraps the **local** console server (the tunnel binary needs no
  Blackforge knowledge), so the orchestrator, access gate and redaction layers
  are all still in the path of every request,
* `start_tunnel(port)` returns a `TunnelSession` whose `public_url` the
  notebook health-probes over the public internet,
* if no tunnel binary is available the tunnel helper raises
  `TunnelUnavailableError` and the validation notebook fails loudly — the
  temporary public URL is a required remediation, never silently skipped.

## Mission Workflow

Through the console an operator can:

1. **create** a mission from a seed target, name, objective, assessment
   profile, and an execution budget,
2. select an explicit planner (`mock`, `rule`, or `llm` with a provider),
3. **run** the mission through the orchestrator and watch progress,
4. render a read-only report with:
   * **capabilities** — registered/applicable/authorized counts and a
     mission-aware capability table with mode (mock vs real-controlled),
     applicability, authorization and execution counts,
   * **assets** — world-model entities with a classification
     (`in_scope` / `candidate` / `out_of_scope`) and an authorization flag,
   * **evidence** — redaction-safe evidence summaries,
   * **attack graph** — a descriptive, evidence-backed graph summary with open
     gaps,
   * **findings** — evidence-backed conclusions with an epistemic status
     (`observed` / `inferred` / `hypothesized` / `validated`) that are never
     self-validated.

## Mission-Aware Capability View

The service exposes a capability view computed by the router for a *specific
mission*: it marks whether each capability is applicable to the seed target
type, whether it is authorized under the mission's scope, whether it has been
executed, and which adapter mode backs it. This is the view the operator and
the planner share.

## Security Guarantees (covered by tests)

* a locked console refuses mission creation/execution,
* the console and service do not expose raw storage / transport / engine
  handles (they cannot bypass the orchestrator),
* reports are redaction-safe — no raw secret-like material (passwords, API
  keys, bearer tokens) surfaces,
* real-controlled adapters are read-only, bounded, and fire only when policy +
  profile permit.

## Module Layout

* `blackforge/ui/access.py` — `AccessGate` (temporary access token gating)
* `blackforge/ui/service.py` — `DevelopmentConsoleService` (application API)
* `blackforge/ui/console.py` — `DevelopmentConsole` (thin rendering UI)
* `blackforge/ui/server.py` — token-gated HTTP server (`/health` public,
  `Bearer`-gated API)
* `blackforge/runtime/tunnel.py` — temporary public URL via cloudflared / ngrok /
  localtunnel (whichever binary is available)
