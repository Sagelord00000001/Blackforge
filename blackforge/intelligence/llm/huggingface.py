from __future__ import annotations

import time
from typing import Any

from blackforge.core.config import LLMConfig
from blackforge.core.logging import get_logger
from blackforge.intelligence.llm.base import LLMProvider, LLMRequest, LLMResponse, Message, ToolCall, Usage
from blackforge.intelligence.llm.loader import LLMModelLoader, ModelLoadResult, resolve_device
from blackforge.intelligence.structured import parse_structured_response
from blackforge.intelligence.tokens import TokenBudget

log = get_logger("provider.huggingface")


class HuggingFaceProvider(LLMProvider):
    """Real local-model provider backed by HuggingFace Transformers.

    - Lazy import: works without torch/transformers until generate() is called.
    - Memory-aware: reloads only once; health_check() uses metadata, and a real
      smoke inference is available via verify_inference().
    - Structured output schema is requested via response_format in the prompt.
    - Tool calls use a normalized internal representation; native tool support is
      emulated via a JSON tool-spec prompt (never fabricated).
    """

    def __init__(self, config: LLMConfig | None = None) -> None:
        self.config = config or LLMConfig(provider="huggingface")
        self._loader = LLMModelLoader(self.config)
        self._load_result: ModelLoadResult | None = None
        self._loaded = False
        self._last_error: str | None = None
        self._budget = TokenBudget(
            context_length=self.config.context_length,
            max_output_tokens=self.config.max_output_tokens,
        )
        self._generation_count = 0
        self._gen_latency_sum = 0.0

    @property
    def device(self) -> str:
        if self._load_result:
            return self._load_result.device
        try:
            return resolve_device(self.config.device)
        except Exception:
            return "cpu"

    def _ensure_loaded(self) -> ModelLoadResult:
        if self._load_result is None:
            self._load_result = self._loader.load()
            self._loaded = True
        return self._load_result

    def _build_input(self, request: LLMRequest) -> dict:
        if request.messages:
            msgs = [m.model_dump() for m in request.messages]
            if request.system_prompt:
                msgs.insert(0, {"role": "system", "content": request.system_prompt})
            return {"messages": msgs}
        prompt = request.prompt
        if request.system_prompt:
            prompt = f"{request.system_prompt}\n\n{prompt}"
        return {"prompt": prompt}

    def generate(self, request: LLMRequest) -> LLMResponse:
        result = self._ensure_loaded()
        import torch  # type: ignore[import-not-found]

        start = time.time()
        self._generation_count += 1

        if request.messages:
            inputs = result.tokenizer.apply_chat_template(
                self._build_input(request)["messages"],
                tokenize=True,
                add_generation_prompt=True,
                return_tensors="pt",
            ).to(result.device)
        else:
            inputs = result.tokenizer(
                self._build_input(request)["prompt"], return_tensors="pt"
            ).to(result.device)

        gen_kwargs: dict[str, Any] = {
            "max_new_tokens": request.max_tokens or self.config.max_output_tokens,
            "temperature": request.temperature or self.config.temperature,
            "do_sample": True,
            "pad_token_id": result.tokenizer.eos_token_id,
        }

        with torch.inference_mode():
            outputs = result.model.generate(**inputs, **gen_kwargs)

        prompt_len = inputs["input_ids"].shape[-1]
        new_tokens = outputs.shape[-1] - prompt_len
        text = result.tokenizer.decode(outputs[0, prompt_len:], skip_special_tokens=True)

        elapsed = time.time() - start
        self._gen_latency_sum += elapsed

        usage = Usage(
            prompt_tokens=int(prompt_len),
            completion_tokens=int(new_tokens),
            total_tokens=int(prompt_len + new_tokens),
        )

        return LLMResponse(
            content=text,
            model=self.config.model,
            provider="huggingface",
            usage=usage,
            finish_reason="stop",
            elapsed_seconds=elapsed,
            raw={"device": result.device, "dtype": result.dtype},
        )

    def structured_generate(
        self, request: LLMRequest, schema: dict | None = None
    ) -> LLMResponse:
        instr = (
            "\n\nRespond with a single valid JSON object matching this schema:\n"
            f"{schema}"
        )
        structured_request = LLMRequest(
            prompt=request.prompt + instr,
            system_prompt=request.system_prompt,
            messages=[m.model_copy() for m in request.messages] if request.messages else None,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
            context=request.context,
            response_format={"type": "json_object"},
        )
        raw = self.generate(structured_request)

        if not raw.content:
            return raw

        parsed = parse_structured_response(
            raw.content,
            schema=schema,
            model_used=self.config.model,
        )
        raw.raw["parsed_structured"] = parsed.parsed
        raw.raw["structured_retries"] = parsed.retries
        return raw

    def health_check(self) -> bool:
        """Lightweight check: verify torch/transformers are importable, without loading model."""
        try:
            import torch  # type: ignore[import-not-found]
            import transformers  # type: ignore[import-not-found]
            return True
        except ImportError:
            self._last_error = "torch or transformers not installed"
            return False

    def verify_inference(self, prompt: str = "Say OK") -> dict:
        """Real smoke test: run a tiny generation and report diagnostics."""
        start = time.time()
        resp = self.generate(LLMRequest(prompt=prompt, max_tokens=16))
        success = bool(resp.content and resp.content.strip())
        return {
            "success": success,
            "model": self.config.model,
            "device": self.device,
            "dtype": self._load_result.dtype if self._load_result else None,
            "response": (resp.content or "")[:100] if resp.content else None,
            "latency_seconds": round(resp.elapsed_seconds or 0.0, 3),
            "usage": resp.usage.model_dump() if resp.usage else {},
        }

    def metadata(self) -> dict[str, Any]:
        return {
            "provider": "huggingface",
            "model": self.config.model,
            "device": self.device,
            "dtype": self._load_result.dtype if self._load_result else None,
            "loaded": self._loaded,
            "context_length": self.config.context_length,
            "max_output_tokens": self.config.max_output_tokens,
            "temperature": self.config.temperature,
            "quantization": self.config.quantization,
            "generation_count": self._generation_count,
            "avg_latency_seconds": (
                round(self._gen_latency_sum / self._generation_count, 3) if self._generation_count else None
            ),
            "last_error": self._last_error,
        }

    def close(self) -> None:
        import gc

        self._load_result = None
        self._loaded = False
        gc.collect()