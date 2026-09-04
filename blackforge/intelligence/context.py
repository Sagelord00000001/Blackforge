from __future__ import annotations

from blackforge.intelligence.llm.base import Message, ToolCall


class ChatContext:
    """Minimal conversation context abstraction.

    Holds system instructions, message history, and tool results so the runtime
    can reconstruct a full prompt/context without hardcoding any model's format.
    """

    def __init__(self, system_prompt: str | None = None) -> None:
        self.system_prompt = system_prompt
        self.messages: list[Message] = []
        self.tool_results: list[dict] = []

    def add_user(self, content: str) -> None:
        self.messages.append(Message(role="user", content=content))

    def add_assistant(self, content: str, tool_calls: list[ToolCall] | None = None) -> None:
        self.messages.append(Message(role="assistant", content=content, tool_calls=tool_calls))

    def add_tool_result(self, tool_call_id: str, name: str, output: str) -> None:
        self.messages.append(
            Message(role="tool", content=output, tool_call_id=tool_call_id, name=name)
        )
        self.tool_results.append({"tool_call_id": tool_call_id, "name": name, "output": output})

    def to_messages(self) -> list[Message]:
        return list(self.messages)

    def to_dict(self) -> list[dict]:
        result: list[dict] = []
        if self.system_prompt:
            result.append({"role": "system", "content": self.system_prompt})
        for msg in self.messages:
            entry: dict = {"role": msg.role, "content": msg.content}
            if msg.tool_calls:
                entry["tool_calls"] = [tc.to_dict() for tc in msg.tool_calls]
            if msg.tool_call_id:
                entry["tool_call_id"] = msg.tool_call_id
            result.append(entry)
        return result

    def clear(self) -> None:
        self.messages.clear()
        self.tool_results.clear()

    def __len__(self) -> int:
        return len(self.messages)