from blackforge.intelligence.context import ChatContext
from blackforge.intelligence.llm.base import ToolCall


class TestChatContext:
    def test_system_prompt(self) -> None:
        ctx = ChatContext(system_prompt="You are helpful.")
        ctx.add_user("hello")
        d = ctx.to_dict()
        assert d[0]["role"] == "system"
        assert d[1]["role"] == "user"

    def test_add_user_assistant(self) -> None:
        ctx = ChatContext()
        ctx.add_user("question")
        ctx.add_assistant("answer")
        assert len(ctx) == 2

    def test_add_tool_result(self) -> None:
        ctx = ChatContext()
        ctx.add_user("run scan")
        tc = ToolCall(name="mock_discovery", arguments={"target": "example.com"}, id="t1")
        ctx.add_assistant("calling tool", tool_calls=[tc])
        ctx.add_tool_result(tool_call_id="t1", name="mock_discovery", output="OK")
        assert len(ctx) == 3
        d = ctx.to_dict()
        assert d[2]["role"] == "tool"
        assert d[2]["tool_call_id"] == "t1"

    def test_clear(self) -> None:
        ctx = ChatContext()
        ctx.add_user("hello")
        ctx.clear()
        assert len(ctx) == 0

    def test_to_messages(self) -> None:
        ctx = ChatContext()
        ctx.add_user("msg")
        msgs = ctx.to_messages()
        assert len(msgs) == 1
