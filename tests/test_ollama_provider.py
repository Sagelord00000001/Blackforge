import json
from unittest.mock import patch, MagicMock
from http.client import HTTPResponse
import io

from blackforge.core.config import LLMConfig
from blackforge.intelligence.llm.ollama import OllamaProvider
from blackforge.intelligence.llm.base import LLMRequest


def _mock_response(data: dict, code: int = 200) -> MagicMock:
    body = json.dumps(data).encode()
    resp = MagicMock()
    resp.read.return_value = body
    resp.status = code
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


class TestOllamaProvider:
    def test_init(self) -> None:
        p = OllamaProvider(LLMConfig(provider="ollama", model="llama3"))
        assert p.base_url.endswith("11434")

    def test_health_check_server_unreachable(self) -> None:
        p = OllamaProvider()
        assert p.health_check() is False

    def test_metadata(self) -> None:
        p = OllamaProvider(LLMConfig(provider="ollama", model="test"))
        meta = p.metadata()
        assert meta["provider"] == "ollama"
        assert meta["model"] == "test"

    @patch("blackforge.intelligence.llm.ollama.urllib.request.urlopen")
    def test_generate_server_mock(self, mock_urlopen) -> None:
        mock_data = {"message": {"content": "hello from ollama"}, "done_reason": "stop"}
        mock_urlopen.return_value = _mock_response(mock_data)
        p = OllamaProvider(LLMConfig(provider="ollama", model="llama3"))
        resp = p.generate(LLMRequest(prompt="hi"))
        assert resp.content == "hello from ollama"
        assert resp.provider == "ollama"

    @patch("blackforge.intelligence.llm.ollama.urllib.request.urlopen")
    def test_structured_generate(self, mock_urlopen) -> None:
        mock_data = {"message": {"content": '{"status": "ok"}'}, "done_reason": "stop"}
        mock_urlopen.return_value = _mock_response(mock_data)
        p = OllamaProvider(LLMConfig(provider="ollama", model="llama3"))
        resp = p.structured_generate(LLMRequest(prompt="give me json"))
        assert resp.content == '{"status": "ok"}'
        assert "parsed_structured" in resp.raw

    @patch("blackforge.intelligence.llm.ollama.urllib.request.urlopen")
    def test_health_check_server_ok(self, mock_urlopen) -> None:
        mock_urlopen.return_value = _mock_response({"models": [{"name": "llama3"}, {"name": "mistral"}]})
        p = OllamaProvider(LLMConfig(provider="ollama", model="llama3"))
        assert p.health_check() is True
