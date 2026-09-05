from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class LLMConfig(BaseModel):
    provider: str = "mock"
    model: str = "Qwen/Qwen2.5-3B-Instruct"
    base_url: str = "http://localhost:11434"
    api_key: str | None = None
    api_key_secondary: str | None = None
    timeout_seconds: int = 120
    max_retries: int = 2
    device: str = "auto"
    dtype: str = "auto"
    quantization: str | None = None
    context_length: int = 8192
    max_output_tokens: int = 2048
    temperature: float = 0.7
    allow_download: bool = True
    cache_dir: str | None = None


class AuthorizationConfig(BaseModel):
    mode: Literal["strict", "permissive", "disabled"] = "strict"
    require_approval_for_high_risk: bool = True


class ExecutionConfig(BaseModel):
    max_concurrent_tasks: int = 5
    task_timeout_seconds: int = 300
    max_evidence_items: int = 10_000


class MemoryConfig(BaseModel):
    backend: Literal["sqlite", "in_memory"] = "sqlite"
    db_path: str = "./data/memory.db"


class EvidenceConfig(BaseModel):
    backend: Literal["sqlite", "in_memory"] = "sqlite"
    db_path: str = "./data/evidence.db"


class MissionDefaults(BaseModel):
    default_confidence_threshold: float = 0.7


class BlackforgeConfig(BaseModel):
    app_name: str = "blackforge"
    environment: Literal["development", "staging", "production"] = "development"
    log_level: str = "INFO"
    data_dir: str = "./data"
    db_path: str = "./data/blackforge.db"

    llm: LLMConfig = Field(default_factory=LLMConfig)
    authorization: AuthorizationConfig = Field(default_factory=AuthorizationConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    mission_defaults: MissionDefaults = Field(default_factory=MissionDefaults)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)

    @field_validator("data_dir", mode="after")
    @classmethod
    def ensure_data_dir(cls, v: str) -> str:
        Path(v).mkdir(parents=True, exist_ok=True)
        return v

    def ensure_directories(self) -> None:
        Path(self.data_dir).mkdir(parents=True, exist_ok=True)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.memory.db_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.evidence.db_path).parent.mkdir(parents=True, exist_ok=True)


def _env(key: str, default: Any = None) -> Any:
    return os.environ.get(key, default)


def load_config(env_file: str | None = None) -> BlackforgeConfig:
    if env_file:
        _load_dotenv(env_file)

    config = BlackforgeConfig(
        app_name=_env("BLACKFORGE_APP_NAME", "blackforge"),
        environment=_env("BLACKFORGE_ENV", "development"),
        log_level=_env("BLACKFORGE_LOG_LEVEL", "INFO"),
        data_dir=_env("BLACKFORGE_DATA_DIR", "./data"),
        db_path=_env("BLACKFORGE_DB_PATH", "./data/blackforge.db"),
        llm=LLMConfig(
            provider=_env("BLACKFORGE_LLM_PROVIDER", "mock"),
            model=_env("BLACKFORGE_LLM_MODEL", "Qwen/Qwen2.5-3B-Instruct"),
            base_url=_env("BLACKFORGE_LLM_BASE_URL", "http://localhost:11434"),
            api_key=_env("BLACKFORGE_LLM_API_KEY"),
            api_key_secondary=_env("BLACKFORGE_LLM_API_KEY_SECONDARY"),
            timeout_seconds=int(_env("BLACKFORGE_LLM_TIMEOUT_SECONDS", 120)),
            max_retries=int(_env("BLACKFORGE_LLM_MAX_RETRIES", 2)),
            device=_env("BLACKFORGE_LLM_DEVICE", "auto"),
            dtype=_env("BLACKFORGE_LLM_DTYPE", "auto"),
            quantization=_env("BLACKFORGE_LLM_QUANTIZATION") or None,
            context_length=int(_env("BLACKFORGE_LLM_CONTEXT_LENGTH", 8192)),
            max_output_tokens=int(_env("BLACKFORGE_MAX_TOKENS", 2048)),
            temperature=float(_env("BLACKFORGE_LLM_TEMPERATURE", 0.7)),
            allow_download=_env("BLACKFORGE_LLM_ALLOW_DOWNLOAD", "true").lower() == "true",
            cache_dir=_env("BLACKFORGE_LLM_CACHE_DIR") or None,
        ),
        authorization=AuthorizationConfig(
            mode=_env("BLACKFORGE_AUTH_MODE", "strict"),
            require_approval_for_high_risk=_env(
                "BLACKFORGE_REQUIRE_APPROVAL_FOR_HIGH_RISK", "true"
            ).lower()
            == "true",
        ),
        execution=ExecutionConfig(
            max_concurrent_tasks=int(_env("BLACKFORGE_MAX_CONCURRENT_TASKS", 5)),
            task_timeout_seconds=int(_env("BLACKFORGE_TASK_TIMEOUT_SECONDS", 300)),
            max_evidence_items=int(_env("BLACKFORGE_MAX_EVIDENCE_ITEMS", 10_000)),
        ),
        memory=MemoryConfig(
            backend=_env("BLACKFORGE_MEMORY_BACKEND", "sqlite"),
            db_path=_env("BLACKFORGE_MEMORY_DB_PATH", "./data/memory.db"),
        ),
        evidence=EvidenceConfig(
            backend=_env("BLACKFORGE_EVIDENCE_BACKEND", "sqlite"),
            db_path=_env("BLACKFORGE_EVIDENCE_DB_PATH", "./data/evidence.db"),
        ),
        mission_defaults=MissionDefaults(
            default_confidence_threshold=float(
                _env("BLACKFORGE_DEFAULT_CONFIDENCE_THRESHOLD", 0.7)
            ),
        ),
    )

    config.ensure_directories()
    return config


def _load_dotenv(path: str) -> None:
    """Minimal .env loader. Does not override existing env vars."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value
