# AELIONIX BLACKFORGE

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Sagelord00000001/Blackforge/blob/master/notebooks/blackforge_phase5_colab.ipynb)

Blackforge is a modular, provider-agnostic **evidence-driven security assessment platform**. It separates concerns into clear architectural layers — configuration, authorization, mission/scope management, evidence handling, capability orchestration, LLM abstraction, persistent memory, and a world model of known facts. It is **pre-alpha** and safe-by-default: mock mode is the default, nothing attacks anything by default, and every analysis path is gated by a programmatic authorization boundary.

> Latest completed phase: **Phase 5 — Reconnaissance Capability Foundation** (`c9c2e67`).
> Next phase: **Phase 6 — Web & API Security**.

---

## Current Status

| Phase | Name | Status | Commit |
|---|---|---|---|
| 0 | Foundation & Rules | ✅ COMPLETE | `4587ebe` |
| 1 | Runtime LLM Infrastructure | ✅ COMPLETE | `1e54de4` |
| 2 | Persistent Memory | ✅ COMPLETE | `43d63b6` |
| 3 | Evidence & Memory Integration | ✅ COMPLETE | `9041d57` |
| 4 | World Model Foundation | ✅ COMPLETE | `c2c7191` |
| 5 | Reconnaissance Capability Foundation | ✅ COMPLETE | `c9c2e67` |
| 6 | Web & API Security | ⏳ NEXT | — |
| 7 | Authentication & Authorization | 🔲 PLANNED | — |
| 8 | Business Logic & Attack Paths | 🔲 PLANNED | — |
| 9 | Network & Infrastructure | 🔲 PLANNED | — |
| 10 | Identity / Active Directory | 🔲 PLANNED | — |
| 11 | Cloud Security | 🔲 PLANNED | — |
| 12 | Containers / Kubernetes | 🔲 PLANNED | — |
| 13 | Source & Runtime Correlation | 🔲 PLANNED | — |
| 14 | Attack Graph & Autonomous Planner | 🔲 PLANNED | — |
| 15 | Multi-Agent Architecture | 🔲 PLANNED | — |
| 16 | Adversary Emulation | 🔲 PLANNED | — |
| 17 | Evaluation & Benchmarking | 🔲 PLANNED | — |
| 18 | Experience / Learning | 🔲 PLANNED | — |
| 19 | Production Hardening | 🔲 PLANNED | — |

Machine-readable copy of this status: `blackforge/project_status.yaml`.

## What Blackforge Can Do Now

In plain language, with the currently implemented foundation:

- **Authorize everything** — every capability request is checked against a `TargetScope` (allowed targets, allowed capabilities, mission context) *before* any tool or capability runs.
- **Manage assessments** — missions and sessions with a lifecycle state machine and typed scope targets.
- **Run LLM infrastructure** — provider-agnostic inference (mock / Ollama / HuggingFace), hardware-aware model loading, model router with fallback, token budgeting, and structured output parsing.
- **Persist episodic memory** — a SQLite-backed agent memory with deduplication, logical versioning, structured search, transactions, and evidence references.
- **Record evidence rigorously** — an evidence store with provenance (observed / inferred / hypothesized / validated), a status lifecycle, typed relationships, confidence, contradiction, supersession, and a *no-fake-authority* rule.
- **Maintain a world model** — typed entities, relationships, and assertions derived from evidence, with mission isolation, provenance tracking, and bounded neighborhood queries.
- **Run reconnaissance** — six typed capabilities (host discovery, service enumeration, technology identification, DNS, HTTP metadata, TLS metadata) that produce normalized observations, attach them to evidence artifacts, materialize them into the world model, and do it all **idempotently** and **deterministically**.

**What it cannot do yet (by design):**

- **No real scanning or network I/O.** Reconnaissance uses *mock adapters* over deterministic fixtures. Nothing touches a network.
- **No exploitation.** There are no exploit paths, no credential use, and no post-exploitation. Offensive edge types (`LEADS_TO`, `ENABLES`, `EXPLOITS`, `CAN_COMPROMISE`, privilege-escalation paths) are rejected at the enum layer of the world model.
- **No attack graph and no autonomous planning.** Attack-path reasoning is Phase 14, not now.
- **No autonomous pentesting engine, no multi-agent orchestration.** Those are future phases.
- **No production hardening.** This is a pre-alpha foundation for a platform, not a shipping security product.

## Architecture

```
blackforge/
├── __init__.py
├── core/
│   ├── config.py          # Centralized configuration (LLM + infra fields)
│   ├── logging.py         # Structured logging setup
│   ├── errors.py          # Error hierarchy (incl. authorization + recon errors)
│   └── types.py           # IDs, enums, foundational types
├── mission/
│   ├── models.py          # Mission model with state machine
│   └── manager.py         # Mission lifecycle management
├── scope/
│   ├── models.py          # TargetScope, Target, target detection
│   └── validator.py       # Scope validation
├── authorization/
│   └── __init__.py       # Authorization boundary (programmatic, first-class)
├── evidence/
│   ├── models.py          # Evidence + provenance + relationship models
│   ├── store.py           # Evidence store
│   ├── repository.py      # Evidence persistence (SQLite / in-memory)
│   └── bridge.py          # Evidence ↔ memory integration
├── memory/
│   ├── base.py            # Memory interface
│   ├── models.py          # Memory backends (SQLite / in-memory)
│   ├── repository.py      # Persistent memory repository
│   └── manager.py         # Memory manager
├── capabilities/
│   ├── models.py          # Capability metadata
│   ├── interface.py       # Capability protocol
│   ├── registry.py        # Capability registry
│   └── mock.py            # Mock capability for testing
├── world_model/
│   ├── models.py          # Entities, relationships, assertions
│   ├── canonical.py       # Canonical entity keys + target type mapping
│   ├── rules.py           # Direction/validity/dedup rules
│   ├── query.py           # Neighborhood + relationship queries
│   ├── repository.py      # World model persistence (SQLite)
│   ├── store.py           # WorldModelStore
│   └── materializer.py    # Evidence → world model materialization
├── recon/
│   ├── models.py          # ReconMode, ReconRequest, observations
│   ├── capabilities.py    # Six typed recon capability definitions
│   ├── mock.py            # Deterministic mock adapters (no network I/O)
│   ├── normalization.py   # Tool output → normalized observations
│   ├── evidence.py        # Observation → evidence artifact/rows
│   ├── materializer.py    # Observation → world model facts
│   └── engine.py          # ReconEngine (capability orchestration + auth)
├── intelligence/
│   ├── llm/
│   │   ├── base.py        # LLM provider ABC, LLMRequest, LLMResponse
│   │   ├── mock.py        # Mock LLM for testing
│   │   ├── huggingface.py # HuggingFace transformers provider
│   │   ├── ollama.py      # Ollama HTTP provider
│   │   └── loader.py      # Model loading, device resolution
│   ├── routing/
│   │   └── router.py      # Model router with fallback
│   ├── context.py         # ChatContext (multi-turn message tracking)
│   ├── tokens.py          # TokenBudget (token counting and enforcement)
│   └── structured.py      # Structured output parsing and validation
└── runtime/
    ├── bootstrap.py       # Application entry point (providers, components)
    └── hardware.py        # Hardware detection (GPU/CPU)

project_status.yaml       # Single source of truth for phase status
notebooks/                # Colab validation notebooks (one per phase + bootstrap)
docs/                     # Phase documentation + validation record
tests/                    # Test suite (current: 438 passed, 3 skipped)
```

## Core Model

- **Evidence model** (`docs/evidence.md`) — facts with provenance (`OBSERVED` / `INFERRED` / `HYPOTHESIZED` / `VALIDATED`), a status lifecycle (`ACTIVE` / `SUPERSEDED` / `CONTRADICTED`), confidence, typed relationships, dedup, and a no-fake-authority rule (claims from an LLM alone are `HYPOTHESIZED`, never `VALIDATED`).
- **Memory** (`docs/memory.md`) — a persistent, episodic agent memory that references evidence by ID and survives restarts.
- **World model** (`docs/world-model.md`) — what is *known* and *how it is known*: typed entities, directed relationships with provenance and confidence, mission isolation, and bounded queries. Offensive edge types are excluded at the enum layer.
- **Reconnaissance** (`docs/reconnaissance.md`) — a typed, deterministic, authorization-gated capability surface that normalizes tool output into evidence-backed observations and materializes them into the world model, idempotently.

## Security & Authorization Boundary

- **Authorization is programmatic, not a prompt instruction.** Every capability invocation passes through `AuthorizationBoundary`, which denies out-of-scope targets and out-of-scope capabilities *before* anything runs.
- **No real attack execution** — nothing in the codebase launches attacks, exploits, or credential use.
- **No network I/O in recon** — adapters are mocks over deterministic fixtures (responses use reserved documentation IP ranges).
- **No command execution** — no `os.system`/`subprocess`-based tooling in the analysis paths; no destructive operations.
- **No hardcoded secrets.**
- **Safe defaults** — mock LLM mode by default; real providers opt in via environment variables; torch/transformers are lazily imported and optional.

## Validation Status

| Item | Result |
|---|---|
| Latest completed-phase commit | `c9c2e67` (Phase 5) |
| Full test suite | **438 passed, 3 skipped, 0 failed** (`python -m pytest tests/ -q`) |
| Bootstrap | `app.healthy()` + `memory_ready`, `evidence_store_ready`, `evidence_memory_link_ready`, `world_model_ready`, `recon_ready` all PASS |
| Phase notebooks | Phase 1–5 notebooks executed; Phase 5 last run locally: **PASS** (all checks green, disposable DBs self-cleaned) |
| Google Colab | Phase 1 executed on a real free-tier CPU runtime (PASS — recorded in `docs/colab-validation.md`). **Phases 2–5 have been validated locally only; no Colab execution is claimed for them.** |
| Ruff | Clean on `blackforge/recon/`, `blackforge/runtime/bootstrap.py`, and `tests/test_recon_phase5.py`; remaining findings are pre-existing in untouched legacy files/notebooks |
| Security review | No execution surface, no secrets, no network I/O; authorization enforced before tool execution |

## Roadmap

- **Phase 0** — Foundation & Rules ✅
- **Phase 1** — Runtime LLM Infrastructure ✅
- **Phase 2** — Persistent Memory ✅
- **Phase 3** — Evidence & Memory Integration ✅
- **Phase 4** — World Model Foundation ✅
- **Phase 5** — Reconnaissance Capability Foundation ✅
- **Phase 6** — Web & API Security ⏳ next
- **Phase 7** — Authentication & Authorization 🔲
- **Phase 8** — Business Logic & Attack Paths 🔲
- **Phase 9** — Network & Infrastructure 🔲
- **Phase 10** — Identity / Active Directory 🔲
- **Phase 11** — Cloud Security 🔲
- **Phase 12** — Containers / Kubernetes 🔲
- **Phase 13** — Source & Runtime Correlation 🔲
- **Phase 14** — Attack Graph & Autonomous Planner 🔲
- **Phase 15** — Multi-Agent Architecture 🔲
- **Phase 16** — Adversary Emulation 🔲
- **Phase 17** — Evaluation & Benchmarking 🔲
- **Phase 18** — Experience / Learning 🔲
- **Phase 19** — Production Hardening 🔲

## Development Setup

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install with dev dependencies (mock-only, no GPU required)
pip install -e ".[dev]"

# Install with LLM support (requires torch + transformers)
pip install -e ".[dev,llm]"

# Copy and configure environment
cp .env.example .env

# Run tests
python -m pytest tests/ -v
```

## LLM Configuration

| Variable | Default | Description |
|---|---|---|
| `BLACKFORGE_LLM_PROVIDER` | `mock` | Provider: `mock`, `ollama`, `huggingface` |
| `BLACKFORGE_LLM_MODEL` | `Qwen/Qwen2.5-3B-Instruct` | Model identifier |
| `BLACKFORGE_LLM_DEVICE` | `auto` | Device: `auto`, `cuda`, `cpu`, `mps` |
| `BLACKFORGE_LLM_DTYPE` | `auto` | Data type: `auto`, `float32`, `float16`, `bfloat16` |
| `BLACKFORGE_LLM_QUANTIZATION` | `null` | Quantization: `null` or `4bit` |
| `BLACKFORGE_LLM_CONTEXT_LENGTH` | `8192` | Context window size |
| `BLACKFORGE_MAX_TOKENS` | `2048` | Max output tokens |
| `BLACKFORGE_LLM_TEMPERATURE` | `0.7` | Generation temperature |
| `BLACKFORGE_LLM_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `BLACKFORGE_LLM_ALLOW_DOWNLOAD` | `true` | Allow model downloads |
| `BLACKFORGE_LLM_CACHE_DIR` | `null` | Model cache directory |

See `.env.example` for the full list.

## Provider Selection

```python
# Default: mock (no network, no model, deterministic)
BLACKFORGE_LLM_PROVIDER=mock

# Ollama: requires Ollama server running
BLACKFORGE_LLM_PROVIDER=ollama
BLACKFORGE_LLM_MODEL=llama3

# HuggingFace: requires torch + transformers installed
BLACKFORGE_LLM_PROVIDER=huggingface
BLACKFORGE_LLM_MODEL=Qwen/Qwen2.5-3B-Instruct
```

## Testing

```bash
# Full suite (current: 438 passed, 3 skipped)
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ -v --cov=blackforge

# Integration tests (requires torch + transformers)
python -m pytest tests/ -v -m integration

# Specific module
python -m pytest tests/test_recon_phase5.py -v
```

## Architecture Principles

1. **Programmatic boundaries** — Authorization is a first-class system concept, not a prompt instruction.
2. **Epistemological rigor** — Evidence distinguishes observed from inferred from hypothesized from validated.
3. **Provider agnosticism** — No dependency on any single LLM provider.
4. **Capability as abstraction** — Capabilities are standardized security actions, not raw tool calls.
5. **Separation of concerns** — Each module has a single responsibility.
6. **Testability** — Every component can be tested with mocks; no external targets required.
7. **Minimal core dependencies** — Only pydantic, structlog, pyyaml in core. torch/transformers are optional.
8. **Safe defaults** — Mock mode by default; real providers opt-in via environment variables.

## Security Review

- No real attack execution; no exploit paths; no credential use
- No external network calls in default/mock mode; no network I/O in reconnaissance
- No command execution; no destructive operations
- No hardcoded secrets
- Authorization is a first-class system concept, enforced before tool execution
- Offensive world-model edge types are rejected at the enum layer
- Safe to run locally without targeting any external system
- torch/transformers lazily imported — core works without GPU or heavy deps

## Limitations

- **Pre-alpha.** Nothing here is production hardening; interfaces may change between phases.
- **Mock reconnaissance only.** The Phase 5 adapters are deterministic fixtures, not real scanners. Real network/API reconnaissance is future work.
- **No autonomous behavior yet.** Recon runs under explicit capability authorization; there is no autonomous planner or attack-path engine.
- **Local validation only for recent phases.** Phases 2–5 notebooks have passed locally; only Phase 1 has been executed on a real Google Colab runtime to date.

## Repository Structure

See the layout under [Architecture](#architecture) and the [Roadmap](#roadmap) for the phase plan. Phase documentation lives in `docs/`; validation notebooks live in `notebooks/`.

## License

MIT