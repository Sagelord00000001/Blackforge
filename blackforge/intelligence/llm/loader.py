from __future__ import annotations

from typing import Any

from blackforge.core.errors import (
    LLMModelDownloadError,
    LLMModelNotFoundError,
    LLMUnsupportedDeviceError,
)
from blackforge.core.logging import get_logger
from blackforge.core.config import LLMConfig
from blackforge.runtime.hardware import HardwareInfo, detect_hardware

log = get_logger("intelligence.loader")


class ModelLoadResult:
    def __init__(self, pipeline: Any, model: Any, tokenizer: Any, device: str, dtype: str) -> None:
        self.pipeline = pipeline
        self.model = model
        self.tokenizer = tokenizer
        self.device = device
        self.dtype = dtype

    @property
    def loaded(self) -> bool:
        return self.model is not None and self.tokenizer is not None


def resolve_device(requested: str, hw: HardwareInfo | None = None) -> str:
    hw = hw or detect_hardware()
    if requested == "auto":
        return hw.device
    if requested == "cuda":
        if not hw.cuda_available:
            raise LLMUnsupportedDeviceError("CUDA requested but not available")
        return "cuda"
    if requested == "mps":
        if not hw.has_mps:
            raise LLMUnsupportedDeviceError("MPS requested but not available")
        return "mps"
    if requested == "cpu":
        return "cpu"
    raise LLMUnsupportedDeviceError(f"Unknown device: {requested}")


def _resolve_dtype(requested: str, device: str) -> str:
    if requested != "auto":
        return requested
    if device == "cpu":
        return "float32"
    if device in ("cuda", "mps"):
        return "float16"
    return "float32"


class LLMModelLoader:
    """Loads a transformers model based on configuration.

    Imports transformers/torch lazily so the rest of Blackforge works without
    them installed. Raises clear errors when the environment cannot load a model.
    """

    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        self.hardware: HardwareInfo | None = None

    def _imports(self) -> tuple[Any, Any]:
        try:
            import torch  # type: ignore[import-not-found]
            import transformers  # type: ignore[import-not-found]
        except ImportError as exc:
            raise LLMModelNotFoundError(
                "transformers/torch not installed. Install with: pip install '.[huggingface]'"
            ) from exc
        return torch, transformers

    def load(self) -> ModelLoadResult:
        hw = detect_hardware()
        self.hardware = hw

        try:
            device = resolve_device(self.config.device, hw)
        except LLMUnsupportedDeviceError:
            log.warning(
                "requested_device_unavailable_falling_back_to_cpu",
                requested=self.config.device,
                detected=hw.device,
            )
            device = "cpu"

        dtype = _resolve_dtype(self.config.dtype, device)
        torch, transformers = self._imports()

        dtype_map = {
            "float32": torch.float32,
            "float16": torch.float16,
            "bfloat16": torch.bfloat16,
        }
        torch_dtype = dtype_map.get(dtype, torch.float32)

        user_cache = self.config.cache_dir

        log.info(
            "model_loading",
            model=self.config.model,
            device=device,
            dtype=dtype,
            allow_download=self.config.allow_download,
        )

        try:
            tokenizer = transformers.AutoTokenizer.from_pretrained(
                self.config.model,
                cache_dir=user_cache,
            )
            model = transformers.AutoModelForCausalLM.from_pretrained(
                self.config.model,
                torch_dtype=torch_dtype,
                cache_dir=user_cache,
            )
        except transformer_model_errors() as exc:
            raise LLMModelNotFoundError(
                f"Could not load model: {self.config.model}. Error: {exc}"
            ) from exc

        if self.config.quantization:
            try:
                if self.config.quantization == "4bit":
                    from transformers import BitsAndBytesConfig  # type: ignore[import-not-found]

                    bnb = BitsAndBytesConfig(load_in_4bit=True)
                    model = transformers.AutoModelForCausalLM.from_pretrained(
                        self.config.model,
                        quantization_config=bnb,
                        cache_dir=user_cache,
                    )
                else:
                    log.warning(
                        "unsupported_quantization_using_fp",
                        quantization=self.config.quantization,
                    )
            except Exception as exc:
                log.warning(
                    "quantization_failed_using_fp",
                    quantization=self.config.quantization,
                    error=str(exc)[:200],
                )

        model.to(device)
        model.eval()

        log.info(
            "model_loaded",
            model=self.config.model,
            device=device,
            dtype=dtype,
        )
        return ModelLoadResult(
            pipeline=None,
            model=model,
            tokenizer=tokenizer,
            device=device,
            dtype=dtype,
        )


def transformer_model_errors() -> tuple[type, ...]:
    """Return transformers-specific exception types if importable; else generic."""
    try:
        import transformers  # type: ignore[import-not-found]

        return (transformers.utils.import_utils.HfHubHttpError, OSError, ValueError)
    except ImportError:
        return (OSError, ValueError)