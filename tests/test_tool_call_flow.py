"""Mock tool-call flow test.

Verifies the conceptual flow: LLM -> normalized tool call -> capability -> result -> context.
No real target, no real scanning.
"""
from blackforge.intelligence.llm.base import LLMRequest, LLMResponse, ToolCall, Usage
from blackforge.intelligence.llm.mock import MockLLMProvider
from blackforge.capabilities.registry import CapabilityRegistry
from blackforge.capabilities.mock import MockDiscoveryCapability
from blackforge.capabilities.interface import CapabilityResult
from blackforge.intelligence.context import ChatContext


class MockToolCallProvider(MockLLMProvider):
    """Mock that returns a normalized tool call."""

    def generate(self, request: LLMRequest) -> LLMResponse:
        if request.tools:
            return LLMResponse(
                content=None,
                tool_calls=[ToolCall(name="mock_discovery", arguments={"target": "example.com"}, id="call_001")],
                model=self._model,
                provider="mock",
                usage=Usage(prompt_tokens=10, completion_tokens=5, total_tokens=15),
                finish_reason="tool_calls",
            )
        return super().generate(request)


class TestMockToolCallFlow:
    def test_llm_to_tool_to_capability(self) -> None:
        # Step 1: LLM proposes a tool call
        llm = MockToolCallProvider("mock")
        registry = CapabilityRegistry()
        registry.register(MockDiscoveryCapability())

        request = LLMRequest(
            prompt="scan example.com",
            tools=[{"name": "mock_discovery", "parameters": {"target": {"type": "string"}}}],
        )
        llm_resp = llm.tool_call(request, tools=[{"name": "mock_discovery"}])

        assert llm_resp.tool_calls is not None
        assert len(llm_resp.tool_calls) == 1
        tc = llm_resp.tool_calls[0]
        assert tc.name == "mock_discovery"

        # Step 2: Resolve capability
        assert registry.has(tc.name)
        cap = registry.get(tc.name)

        # Step 3: Execute capability
        cap_result: CapabilityResult = cap.execute(target=tc.arguments["target"])
        assert cap_result.success is True

        # Step 4: Feed result back into context
        ctx = ChatContext(system_prompt="You are a security analyst.")
        ctx.add_user("scan example.com")
        ctx.add_assistant("calling tool", tool_calls=[tc])
        ctx.add_tool_result(
            tool_call_id=tc.id or "",
            name=tc.name,
            output=str(cap_result.output),
        )

        # Verify context has the full trace (system + user + assistant + tool = 4)
        messages = ctx.to_dict()
        assert len(messages) == 4
        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"
        assert messages[2]["role"] == "assistant"
        assert messages[3]["role"] == "tool"

    def test_no_tool_call_when_no_tools_provided(self) -> None:
        llm = MockToolCallProvider("mock")
        resp = llm.generate(LLMRequest(prompt="hello"))
        assert resp.tool_calls is None
        assert resp.content is not None
