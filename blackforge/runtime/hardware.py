from __future__ import annotations

import subprocess
from functools import lru_cache
from typing import Any

from blackforge.core.logging import get_logger

log = get_logger("runtime.hardware")


class HardwareInfo:
    """Snapshot of detected compute hardware."""

    def __init__(
        self,
        device: str,
        cuda_available: bool,
        cuda_version: str | None,
        gpu_name: str | None,
        gpu_memory_bytes: int | None,
        cpu_count: int,
        has_mps: bool,
    ) -> None:
        self.device = device
        self.cuda_available = cuda_available
        self.cuda_version = cuda_version
        self.gpu_name = gpu_name
        self.gpu_memory_bytes = gpu_memory_bytes
        self.cpu_count = cpu_count
        self.has_mps = has_mps

    @property
    def gpu_memory_gb(self) -> float | None:
        if self.gpu_memory_bytes is None:
            return None
        return round(self.gpu_memory_bytes / (1024**3), 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device": self.device,
            "cuda_available": self.cuda_available,
            "cuda_version": self.cuda_version,
            "gpu_name": self.gpu_name,
            "gpu_memory_bytes": self.gpu_memory_bytes,
            "gpu_memory_gb": self.gpu_memory_gb,
            "cpu_count": self.cpu_count,
            "has_mps": self.has_mps,
        }


def _get_cuda_available() -> bool:
    try:
        import torch  # type: ignore[import-not-found]

        return bool(torch.cuda.is_available())
    except ImportError:
        return False


def _get_gpu_name() -> str | None:
    try:
        import torch  # type: ignore[import-not-found]

        if torch.cuda.is_available():
            return str(torch.cuda.get_device_name(0))
        return None
    except ImportError:
        return None


def _get_cuda_version() -> str | None:
    try:
        import torch  # type: ignore[import-not-found]

        if torch.cuda.is_available():
            return torch.version.cuda
        return None
    except ImportError:
        return None


def _get_gpu_memory_bytes() -> int | None:
    try:
        import torch  # type: ignore[import-not-found]

        if torch.cuda.is_available():
            return int(torch.cuda.get_device_properties(0).total_memory)
        return None
    except ImportError:
        return None


def _get_mps_available() -> bool:
    try:
        import torch  # type: ignore[import-not-found]

        return bool(getattr(torch.backends, "mps", None) and torch.backends.mps.is_available())
    except ImportError:
        return False


def _get_cpu_count() -> int:
    try:
        import os

        return os.cpu_count() or 1
    except Exception:
        return 1


def _nvidia_smi_gpu_name() -> str | None:
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().splitlines()[0]
    except Exception:
        pass
    return None


def _nvidia_smi_memory() -> int | None:
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,units"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            line = result.stdout.strip().splitlines()[0]
            # Format: "15472 MiB"
            try:
                return int(line.split()[0]) * 1024 * 1024
            except (ValueError, IndexError):
                return None
    except Exception:
        pass
    return None


@lru_cache(maxsize=1)
def detect_hardware() -> HardwareInfo:
    cuda = _get_cuda_available()

    gpu_name = _get_gpu_name()
    if not gpu_name:
        gpu_name = _nvidia_smi_gpu_name()

    gpu_mem = _get_gpu_memory_bytes()
    if not gpu_mem:
        gpu_mem = _nvidia_smi_memory()

    device = "cuda" if cuda else "mps" if _get_mps_available() else "cpu"

    info = HardwareInfo(
        device=device,
        cuda_available=cuda,
        cuda_version=_get_cuda_version(),
        gpu_name=gpu_name,
        gpu_memory_bytes=gpu_mem,
        cpu_count=_get_cpu_count(),
        has_mps=_get_mps_available(),
    )

    log.info(
        "hardware_detected",
        device=info.device,
        gpu_name=info.gpu_name,
        cuda_available=info.cuda_available,
        gpu_memory_gb=info.gpu_memory_gb,
    )
    return info