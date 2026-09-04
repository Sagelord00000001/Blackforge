from unittest.mock import patch, MagicMock

from blackforge.runtime.hardware import HardwareInfo, detect_hardware, _get_cpu_count


class TestHardwareInfo:
    def test_to_dict_cuda(self) -> None:
        info = HardwareInfo(
            device="cuda",
            cuda_available=True,
            cuda_version="12.4",
            gpu_name="NVIDIA T4",
            gpu_memory_bytes=15_360 * 1024 * 1024,
            cpu_count=4,
            has_mps=False,
        )
        d = info.to_dict()
        assert d["device"] == "cuda"
        assert d["gpu_memory_gb"] == 15.0
        assert d["cuda_version"] == "12.4"

    def test_to_dict_cpu(self) -> None:
        info = HardwareInfo(
            device="cpu",
            cuda_available=False,
            cuda_version=None,
            gpu_name=None,
            gpu_memory_bytes=None,
            cpu_count=8,
            has_mps=False,
        )
        d = info.to_dict()
        assert d["gpu_memory_gb"] is None
        assert d["cpu_count"] == 8


class TestHardwareDetection:
    @patch("blackforge.runtime.hardware._get_gpu_name", return_value="MockGPU")
    @patch("blackforge.runtime.hardware._get_cuda_available", return_value=True)
    @patch("blackforge.runtime.hardware._get_gpu_memory_bytes", return_value=8 * 1024 ** 3)
    def test_cuda_path(self, mock_mem, mock_cuda, mock_name) -> None:
        detect_hardware.cache_clear()
        info = detect_hardware()
        assert info.cuda_available is True
        assert info.device == "cuda"
        assert info.gpu_name == "MockGPU"
        detect_hardware.cache_clear()

    def test_cpu_fallback(self) -> None:
        detect_hardware.cache_clear()
        with patch("blackforge.runtime.hardware._get_cuda_available", return_value=False), \
             patch("blackforge.runtime.hardware._get_mps_available", return_value=False):
            info = detect_hardware()
            assert info.device == "cpu"
        detect_hardware.cache_clear()

    def test_get_cpu_count(self) -> None:
        result = _get_cpu_count()
        assert result >= 1
