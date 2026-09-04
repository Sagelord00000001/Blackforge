import pytest

from blackforge.core.errors import LLMMalformedStructuredResponseError
from blackforge.intelligence.structured import (
    extract_json,
    validate_against_schema,
    parse_structured_response,
    StructuredOutput,
)


class TestExtractJson:
    def test_valid_json_object(self) -> None:
        result = extract_json('{"key": "value"}')
        assert result == {"key": "value"}

    def test_valid_json_array(self) -> None:
        result = extract_json('[1, 2, 3]')
        assert result == [1, 2, 3]

    def test_json_in_code_fence(self) -> None:
        text = 'Here is the result:\n```json\n{"key": "val"}\n```\n'
        result = extract_json(text)
        assert result == {"key": "val"}

    def test_json_surrounded_by_text(self) -> None:
        text = 'The output is: {"answer": 42} and that is it.'
        result = extract_json(text)
        assert result == {"answer": 42}

    def test_invalid_json(self) -> None:
        with pytest.raises(LLMMalformedStructuredResponseError):
            extract_json("not json at all")

    def test_empty_string(self) -> None:
        with pytest.raises(LLMMalformedStructuredResponseError):
            extract_json("")


class TestValidateAgainstSchema:
    def test_valid_object(self) -> None:
        schema = {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}
        assert validate_against_schema({"name": "Alice"}, schema) is True

    def test_missing_required(self) -> None:
        schema = {"type": "object", "required": ["name"]}
        assert validate_against_schema({}, schema) is False

    def test_wrong_type(self) -> None:
        schema = {"type": "object", "properties": {"count": {"type": "integer"}}}
        assert validate_against_schema({"count": "not_int"}, schema) is False

    def test_no_schema(self) -> None:
        assert validate_against_schema({"anything": True}, None) is True

    def test_array_type(self) -> None:
        schema = {"type": "array"}
        assert validate_against_schema([1, 2], schema) is True
        assert validate_against_schema("not_array", schema) is False


class TestParseStructuredResponse:
    def test_valid_json(self) -> None:
        out = parse_structured_response('{"key": "value"}', schema=None, model_used="test")
        assert out.parsed == {"key": "value"}
        assert out.retries == 0

    def test_json_in_fences(self) -> None:
        out = parse_structured_response(
            '```\n{"status": "ok"}\n```',
            schema={"type": "object", "required": ["status"]},
        )
        assert out.parsed["status"] == "ok"

    def test_schema_validation_failure_no_retry(self) -> None:
        with pytest.raises(LLMMalformedStructuredResponseError):
            parse_structured_response(
                '{"wrong": true}',
                schema={"type": "object", "required": ["must_exist"]},
                max_retries=0,
            )

    def test_retry_fn_called(self) -> None:
        call_count = 0

        def retry_fn(attempt: int) -> str:
            nonlocal call_count
            call_count += 1
            return '{"retried": true}'

        out = parse_structured_response(
            "not json",
            schema=None,
            max_retries=2,
            retry_fn=retry_fn,
        )
        assert out.parsed == {"retried": True}
        assert call_count == 1
