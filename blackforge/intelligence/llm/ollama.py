from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from blackforge.core.config import LLMConfig
from blackforge.core.errors import (
    LLMInferenceError,
    LLMModelNotFoundError,
    LLMTimeoutError,
)
from blackforge.core.logging import get_logger
from blackforge.intelligence.llm.base import LLMProvider, LLMRequest, LLMResponse, Usage
from blackforge.intelligence.structured import parse_structured_response

log = get_logger("provider.ollama")


class OllamaProvider(LLMProvider):
    """Provider for Ollama (or any OpenAI-compatible local inference server).

    Uses stdlib urllib only — no external SDK dependency. Falls back gracefully
    when the server is unreachable.
    """

    def __init__(self, config: LLMConfig | None = None) -> None:
        self.config = config or LLMConfig(provider="ollama", model="llama3")
        self.base_url = self.config.base_url.rstrip("/")
        self._last_error: str | None = None

    def _post(self, path: str, payload: dict) -> dict:
        url = f"{self.base_url}{path}"
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, method="POST", headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise LLMModelNotFoundError(f"Model not found at {url}") from exc
            raise LLMInferenceError(f"HTTP {exc.code} from {url}") from exc
        except urllib.error.URLError as exc:
            raise LLMInferenceError(f"Could not reach {url}: {exc.reason}") from exc
        except TimeoutError:
            raise LLMTimeoutError(f"Request to {url} timed out") from None

    def _build_chat_payload(self, request: LLMRequest, format_json: bool = False) -> dict:
        system = request.system_prompt or "You are a security analyst."
        messages: list[dict] = []
        if request.messages:
            messages.extend(m.model_dump() for m in request.messages)
            if request.system_prompt:
                messages = [{"role": "system", "content": system}] + messages
        else:
            messages = [
                {"role": "system", "content": system},
                {"role": "user", "content": request.prompt},
            ]

        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": request.temperature or self.config.temperature,
                "num_predict": request.max_tokens or self.config.max_output_tokens,
                "num_ctx": self.config.context_length,
            },
        }
        if request.tools:
            payload["tools"] = request.tools
        if format_json:
            payload["format"] = "json"
        return payload

    def _parse_chat_response(self, data: dict) -> LLMResponse:
        content = data.get("message", {}).get("content")
        prompt_tokens = int(data.get("prompt_eval_count", 0) or 0)
        completion_tokens = int(data.get("eval_count", 0) or 0)
        usage = Usage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        )
        return LLMResponse(
            content=content,
            model=self.config.model,
            provider="ollama",
            usage=usage,
            finish_reason=data.get("done_reason", "stop"),
            raw=data,
        )

    def generate(self, request: LLMRequest) -> LLMResponse:
        start = time.time()
        payload = self._build_chat_payload(request)
        data = self._post("/api/chat", payload)
        resp = self._parse_chat_response(data)
        resp.elapsed_seconds = time.time() - start
        return resp

    def structured_generate(
        self, request: LLMRequest, schema: dict | None = None
    ) -> LLMResponse:
        start = time.time()
        payload = self._build_chat_payload(request, format_json=True)
        data = self._post("/api/chat", payload)
        resp = self._parse_chat_response(data)
        resp.elapsed_seconds = time.time() - start

        if resp.content:
            parsed = parse_structured_response(
                resp.content,
                schema=schema,
                model_used=self.config.model,
            )
            resp.raw["parsed_structured"] = parsed.parsed
            resp.raw["structured_retries"] = parsed.retries
        return resp

    def health_check(self) -> bool:
        try:
            data = self._post("/api/tags", {})
            models = data.get("models", [])
            names = [m.get("name") for m in models]
            configured = self.config.model
            available = configured in names or any(
                n.startswith(configured.split(":")[0]) for n in names
            )
            self._last_error = None
            return available
        except Exception as exc:
            self._last_error = str(exc)[:200]
            return False

    def metadata(self) -> dict[str, Any]:
        return {
            "provider": "ollama",
            "model": self.config.model,
            "base_url": self.base_url,
            "context_length": self.config.context_length,
            "max_output_tokens": self.config.max_output_tokens,
            "last_error": self._last_error,
        }