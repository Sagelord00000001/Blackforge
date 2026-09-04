# AELIONIX BLACKFORGE

**Phase 0 — Foundation & System Contracts**

> **Status:** Phase 0 complete. This is a foundation, not yet an autonomous pentesting engine.

---

## What Blackforge Is

Blackforge is a modular, provider-agnostic autonomous security assessment platform designed for serious commercial use. It separates concerns into clear architectural layers: configuration, authorization, evidence management, capability orchestration, LLM abstraction, and persistent memory.

## What Phase 0 Implements

Phase 0 establishes the **foundational architecture** that all later phases build upon:

- **Configuration system** — centralized, env-var-driven, pydantic-validated config
- **Structured logging** — structured log output with component context via structlog
- **Core types** — typed IDs, status enums, and foundational data models
- **Mission model** — mission lifecycle with validated state transitions
- **Scope model** — target/capability allowlisting with CIDR, domain, and URL matching
- **Authorization boundary** — programmatic authorization checks (not prompt-based)
- **Evidence model** — epistemological evidence tracking (observed/inferred/hypothesized/validated)
- **Evidence provenance** — traceable evidence lineage
- **Capability interface** — abstract capability protocol with metadata
- **Capability registry** — discoverable, inspectable capability registry
- **LLM provider abstraction** — provider-agnostic LLM interface
- **Model router** — deterministic task-category-to-provider routing
- **Persistent memory** — pluggable memory backend (SQLite + in-memory for testing)
- **Application bootstrap** — verified system initialization
- **Colab bootstrap** — reproducible notebook for environment preparation
- **Mock components** — safe mock LLM, mock capability for testing
- **Comprehensive tests** — 115 tests covering all foundation modules

## Project Structure

```
blackforge/
├── __init__.py
├── core/
│   ├── config.py          # Centralized configuration
│   ├── logging.py         # Structured logging setup
│   ├── errors.py          # Error hierarchy
│   └── types.py           # IDs, enums, foundational types
├── mission/
│   ├── models.py          # Mission model with state machine
│   └── manager.py         # Mission lifecycle management
├── scope/
│   ├── models.py          # Target scope, target detection
│   └── validator.py       # Scope validation
├── authorization/
│   └── __init__.py        # Authorization boundary
├── evidence/
│   ├── models.py          # Evidence + provenance models
│   └── store.py           # Evidence storage
├── capabilities/
│   ├── models.py          # Capability metadata
│   ├── interface.py       # Capability protocol
│   ├── registry.py        # Capability registry
│   └── mock.py            # Mock capability for testing
├── intelligence/
│   ├── llm/
│   │   ├── base.py        # LLM provider abstraction
│   │   └── mock.py        # Mock LLM for testing
│   └── routing/
│       └── router.py      # Model router
├── memory/
│   ├── base.py            # Memory interface
│   └── models.py          # SQLite + in-memory backends
└── runtime/
    └── bootstrap.py       # Application entry point
```

## Development Setup

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev]"

# Copy and configure environment
cp .env.example .env

# Run tests
python -m pytest tests/ -v
```

## Testing

```bash
# Full suite
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ -v --cov=blackforge

# Specific module
python -m pytest tests/test_mission.py -v
```

## Configuration

Configuration is loaded from environment variables, optionally via `.env` file:

| Variable | Default | Description |
|---|---|---|
| `BLACKFORGE_ENV` | `development` | Environment (development/staging/production) |
| `BLACKFORGE_LOG_LEVEL` | `INFO` | Log level |
| `BLACKFORGE_DATA_DIR` | `./data` | Data directory |
| `BLACKFORGE_LLM_PROVIDER` | `ollama` | LLM provider name |
| `BLACKFORGE_LLM_MODEL` | `llama3` | LLM model identifier |
| `BLACKFORGE_AUTH_MODE` | `strict` | Authorization mode |
| `BLACKFORGE_MEMORY_BACKEND` | `sqlite` | Memory backend |

See `.env.example` for the full list.

**Never commit `.env` or any file containing real secrets.**

## Colab Bootstrap

```bash
# Open the notebook
jupyter notebook notebooks/blackforge_bootstrap.ipynb
```

The notebook installs dependencies, validates the environment, runs tests, and reports system information.

## Architecture Principles

1. **Programmatic boundaries** — Authorization is a first-class system concept, not a prompt instruction.
2. **Epistemological rigor** — Evidence distinguishes observed from inferred from hypothesized from validated.
3. **Provider agnosticism** — No dependency on any single LLM provider.
4. **Capability as abstraction** — Capabilities are standardized security actions, not raw tool calls.
5. **Separation of concerns** — Each module has a single responsibility.
6. **Testability** — Every component can be tested with mocks; no external targets required.
7. **Minimal dependencies** — Only pydantic, structlog, pyyaml in core.

## Security Review (Phase 0)

- No real attack execution
- No external network calls in default/mock mode
- No hardcoded secrets
- No command execution
- No destructive operations
- Authorization is a first-class system concept
- Safe to run locally without targeting any external system

## Roadmap

- **Phase 0** — Foundation (current)
- **Phase 1** — TBD (provided separately)

## License

MIT
