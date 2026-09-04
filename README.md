# AELIONIX BLACKFORGE

**Phase 1 — Runtime LLM Infrastructure**

> **Status:** Phase 1 complete. Runtime LLM providers, hardware detection, token budgeting, and structured output parsing are operational. Safe mock mode remains the default.

---

## What Blackforge Is

Blackforge is a modular, provider-agnostic autonomous security assessment platform designed for serious commercial use. It separates concerns into clear architectural layers: configuration, authorization, evidence management, capability orchestration, LLM abstraction, and persistent memory.

## What Phase 1 Implements

Phase 1 extends the foundation with real, provider-agnostic LLM runtime infrastructure:

- **HuggingFace provider** — local model inference via `transformers` with hardware-aware loading, lazy imports, and GPU/CPU auto-detection
- **Ollama provider** — local model inference via Ollama HTTP API (stdlib only, no SDK dependency)
- **Hardware detection** — automatic GPU/CPU detection with nvidia-smi fallback and 1-hour caching
- **Model loader** — lazy-loading `AutoModelForCausalLM` + `AutoTokenizer` with dtype and quantization support
- **Token budgeting** — token counting, budget enforcement, and context-length management
- **Chat context** — multi-turn message tracking with system prompts, tool results, and serialization
- **Structured output** — JSON extraction, code-fence parsing, schema validation with bounded retries
- **Model router fallback** — primary model fails → fallback model activates with observable logging
- **Extended configuration** — device, dtype, quantization, context length, temperature, download control
- **Provider resolution** — `_resolve_provider()` factory maps config to provider with safe fallback to mock

## Project Structure

```
blackforge/
├── __init__.py
├── core/
│   ├── config.py          # Centralized configuration (LLM extended fields)
│   ├── logging.py         # Structured logging setup
│   ├── errors.py          # Error hierarchy (8 new LLM error classes)
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
│   │   ├── __init__.py    # Re-exports Message, ToolCall, Usage
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
├── memory/
│   ├── base.py            # Memory interface
│   └── models.py          # SQLite + in-memory backends
└── runtime/
    ├── bootstrap.py       # Application entry point (provider resolution)
    └── hardware.py        # Hardware detection (GPU/CPU)
```

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
# Full suite (177 tests)
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ -v --cov=blackforge

# Integration tests (requires torch + transformers)
python -m pytest tests/ -v -m integration

# Specific module
python -m pytest tests/test_structured.py -v
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

- No real attack execution
- No external network calls in default/mock mode
- No hardcoded secrets
- No command execution
- No destructive operations
- Authorization is a first-class system concept
- Safe to run locally without targeting any external system
- torch/transformers lazily imported — core works without GPU or heavy deps

## Roadmap

- **Phase 0** — Foundation ✅
- **Phase 1** — Runtime LLM Infrastructure ✅
- **Phase 2** — TBD

## License

MIT
