from unittest.mock import patch, MagicMock

import pytest

from blackforge.core.config import LLMConfig
from blackforge.core.errors import LLMUnsupportedDeviceError
from blackforge.intelligence.llm.loader import (
    LLMModelLoader,
    resolve_device,
    ModelLoadResult,
    _resolve_dtype,
)
from blackforge.runtime.hardware import HardwareInfo


class TestResolveDevice:
    def test_auto_with_cuda(self) -> None:
        hw = HardwareInfo(device="cuda", cuda_available=True, cuda_version="12.4", gpu_name="T4",
                          gpu_memory_bytes=1e9, cpu_count=2, has_mps=False)
        assert resolve_device("auto", hw) == "cuda"

    def test_auto_cpu(self) -> None:
        hw = HardwareInfo(device="cpu", cuda_available=False, cuda_version=None, gpu_name=None,
                          gpu_memory_bytes=None, cpu_count=4, has_mps=False)
        assert resolve_device("auto", hw) == "cpu"

    def test_explicit_cuda(self) -> None:
        hw = HardwareInfo(device="cuda", cuda_available=True, cuda_version="12.4", gpu_name="T4",
                          gpu_memory_bytes=1e9, cpu_count=2, has_mps=False)
        assert resolve_device("cuda", hw) == "cuda"

    def test_explicit_cuda_unavailable(self) -> None:
        hw = HardwareInfo(device="cpu", cuda_available=False, cuda_version=None, gpu_name=None,
                          gpu_memory_bytes=None, cpu_count=4, has_mps=False)
        with pytest.raises(LLMUnsupportedDeviceError):
            resolve_device("cuda", hw)

    def test_unknown_device(self) -> None:
        hw = HardwareInfo(device="cpu", cuda_available=False, cuda_version=None, gpu_name=None,
                          gpu_memory_bytes=None, cpu_count=4, has_mps=False)
        with pytest.raises(LLMUnsupportedDeviceError):
            resolve_device("quantum", hw)


class TestResolveDtype:
    def test_auto_cpu(self) -> None:
        assert _resolve_dtype("auto", "cpu") == "float32"

    def test_auto_cuda(self) -> None:
        assert _resolve_dtype("auto", "cuda") == "float16"

    def test_explicit(self) -> None:
        assert _resolve_dtype("bfloat16", "cuda") == "bfloat16"


class TestModelLoadResult:
    def test_loaded_true(self) -> None:
        r = ModelLoadResult(pipeline=None, model=MagicMock(), tokenizer=MagicMock(), device="cpu", dtype="float32")
        assert r.loaded is True

    def test_loaded_false(self) -> None:
        r = ModelLoadResult(pipeline=None, model=None, tokenizer=None, device="cpu", dtype="float32")
        assert r.loaded is False
