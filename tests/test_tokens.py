import pytest

from blackforge.intelligence.tokens import TokenBudget, _approximate_tokens


class TestApproximateTokens:
    def test_empty(self) -> None:
        assert _approximate_tokens("") == 0

    def test_short(self) -> None:
        assert _approximate_tokens("hi") >= 1

    def test_longer(self) -> None:
        count = _approximate_tokens("hello world, this is a test of token estimation")
        assert count >= 1


class TestTokenBudget:
    def test_basic(self) -> None:
        b = TokenBudget(context_length=8192, max_output_tokens=2048)
        assert b.input_budget == 8192 - 2048
        assert b.output_budget == 2048
        assert b.total_context_budget == 8192

    def test_invalid(self) -> None:
        with pytest.raises(ValueError):
            TokenBudget(context_length=100, max_output_tokens=100)

    def test_count_tokens_with_tokenizer(self) -> None:
        class FakeTokenizer:
            def encode(self, text: str) -> list[int]:
                return list(range(len(text.split())))

        b = TokenBudget(context_length=4096, max_output_tokens=1024, tokenizer=FakeTokenizer())
        count, approx = b.count_tokens("hello world foo bar")
        assert count == 4
        assert approx is False

    def test_count_tokens_without_tokenizer(self) -> None:
        b = TokenBudget(context_length=4096, max_output_tokens=1024)
        count, approx = b.count_tokens("hello world")
        assert count >= 1
        assert approx is True

    def test_would_exceed_budget(self) -> None:
        b = TokenBudget(context_length=100, max_output_tokens=20)
        assert b.would_exceed_budget(80) is False
        assert b.would_exceed_budget(81) is True

    def test_estimate_input_tokens(self) -> None:
        b = TokenBudget(context_length=4096, max_output_tokens=1024)
        msgs = [{"role": "user", "content": "hello"}]
        count, approx = b.estimate_input_tokens(msgs)
        assert count >= 4  # ~4 base overhead + content tokens
        assert approx is True
