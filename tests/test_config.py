import os
from unittest.mock import patch

import pytest

from blackforge.core.config import BlackforgeConfig, load_config
from blackforge.core.errors import ConfigurationError


class TestBlackforgeConfig:
    def test_default_config_loads(self) -> None:
        config = BlackforgeConfig()
        assert config.app_name == "blackforge"
        assert config.environment == "development"
        assert config.log_level == "INFO"

    def test_llm_defaults(self) -> None:
        config = BlackforgeConfig()
        assert config.llm.provider == "mock"
        assert config.llm.device == "auto"
        assert config.llm.context_length == 8192
        assert config.llm.max_output_tokens == 2048
        assert config.llm.temperature == 0.7

    def test_llm_extended_fields(self) -> None:
        config = BlackforgeConfig()
        assert config.llm.dtype == "auto"
        assert config.llm.quantization is None
        assert config.llm.allow_download is True
        assert config.llm.cache_dir is None

    def test_execution_defaults(self) -> None:
        config = BlackforgeConfig()
        assert config.execution.max_concurrent_tasks == 5
        assert config.execution.task_timeout_seconds == 300

    def test_data_dir_created(self, tmp_path: object) -> None:
        data_dir = str(tmp_path) + "/test_data"
        config = BlackforgeConfig(data_dir=data_dir)
        assert os.path.isdir(data_dir)

    def test_authorization_defaults(self) -> None:
        config = BlackforgeConfig()
        assert config.authorization.mode == "strict"
        assert config.authorization.require_approval_for_high_risk is True

    def test_memory_defaults(self) -> None:
        config = BlackforgeConfig()
        assert config.memory.backend == "sqlite"


class TestLoadConfig:
    def test_load_from_env(self, tmp_path: object) -> None:
        env_file = str(tmp_path) + "/.env"
        with open(env_file, "w") as f:
            f.write("BLACKFORGE_APP_NAME=test_app\n")
            f.write("BLACKFORGE_ENV=staging\n")
            f.write("BLACKFORGE_LOG_LEVEL=DEBUG\n")
        with patch.dict(os.environ, {}, clear=False):
            config = load_config(env_file)
            assert config.app_name == "test_app"
            assert config.environment == "staging"
            assert config.log_level == "DEBUG"

    def test_missing_env_file(self, tmp_path: object) -> None:
        config = load_config(str(tmp_path / "nonexistent.env"))
        assert config.app_name == "blackforge"

    def test_env_vars_not_overridden(self, tmp_path: object) -> None:
        env_file = str(tmp_path) + "/.env"
        with open(env_file, "w") as f:
            f.write("BLACKFORGE_APP_NAME=from_file\n")
        with patch.dict(os.environ, {"BLACKFORGE_APP_NAME": "from_env"}):
            config = load_config(env_file)
            assert config.app_name == "from_env"
