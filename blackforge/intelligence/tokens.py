from __future__ import annotations

from typing import Protocol


class Tokenizer(Protocol):
    """Minimal tokenizer protocol used for token estimation."""

    def encode(self, text: str) -> list[int]:
        ...


class TokenBudget:
    """Runtime token budgeting abstraction.

    Where an exact tokenizer is available it should be used; otherwise a
    character-based estimate is used and marked as approximate.
    """

    def __init__(
        self,
        context_length: int,
        max_output_tokens: int,
        tokenizer: Tokenizer | None = None,
        reserved_for_output: int | None = None,
    ) -> None:
        self.context_length = context_length
        self.max_output_tokens = max_output_tokens
        self._tokenizer = tokenizer

        # Reserve part of the context for the output if not explicitly given.
        self.reserved_for_output = reserved_for_output if reserved_for_output else max_output_tokens

        if self.max_output_tokens >= self.context_length:
            raise ValueError(
                f"max_output_tokens ({max_output_tokens}) must be < context_length ({context_length})"
            )

    @property
    def input_budget(self) -> int:
        return self.context_length - self.reserved_for_output

    @property
    def output_budget(self) -> int:
        return self.max_output_tokens

    @property
    def total_context_budget(self) -> int:
        return self.context_length

    def count_tokens(self, text: str) -> tuple[int, bool]:
        """Return (token_count, is_approximate). Uses tokenizer if available."""
        if self._tokenizer is not None:
            try:
                return len(self._tokenizer.encode(text)), False
            except Exception:
                pass
        return _approximate_tokens(text), True

    def estimate_input_tokens(self, messages: list[dict] | str) -> tuple[int, bool]:
        if isinstance(messages, str):
            return self.count_tokens(messages)
        total, approximate = 0, False
        for m in messages:
            count, approx = self.count_tokens(str(m.get("content", "")))
            total += count
            approximate = approximate or approx
            # rough per-message overhead
            total += 4
        return total, approximate

    def would_exceed_budget(self, input_tokens: int) -> bool:
        return input_tokens > self.input_budget


def _approximate_tokens(text: str) -> int:
    # Rough heuristic: ~4 characters per token for English text.
    if not text:
        return 0
    return max(1, len(text) // 4)