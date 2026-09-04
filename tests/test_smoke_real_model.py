"""Real model smoke test — integration test.

This test downloads and loads a real model. It is slow and requires
torch+transformers to be installed.

Run separately:
    pytest tests/test_smoke_real_model.py -v --run-integration
"""
import pytest


# This test is skipped unless --run-integration is passed
pytestmark = pytest.mark.skipif(
    not pytest.config.getoption("--run-integration", default=False)
    if hasattr(pytest, "config")
    else True,
    reason="requires --run-integration flag",
)


class TestRealModelSmoke:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        try:
            import torch  # type: ignore[import-not-found]
            import transformers  # type: ignore[import-not-found]
        except ImportError:
            pytest.skip("torch/transformers not installed")

    def test_load_and_generate(self) -> None:
        from blackforge.core.config import LLMConfig
        from blackforge.intelligence.llm.huggingface import HuggingFaceProvider

        config = LLMConfig(
            provider="huggingface",
            model="Qwen/Qwen2.5-3B-Instruct",
            device="auto",
            dtype="float16",
            context_length=2048,
            max_output_tokens=64,
        )
        provider = HuggingFaceProvider(config)
        assert provider.health_check()
        result = provider.verify_inference("Say OK")
        assert result["success"] is True
        assert result["device"] in ("cuda", "cpu", "mps")
        assert result["latency_seconds"] > 0
        provider.close()
