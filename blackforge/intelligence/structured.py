from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel

from blackforge.core.errors import LLMMalformedStructuredResponseError
from blackforge.core.logging import get_logger

log = get_logger("intelligence.structured")


class StructuredOutput(BaseModel):
    parsed: Any
    model_used: str = ""
    retries: int = 0


def extract_json(text: str) -> dict | list:
    """Extract JSON from a model response, tolerating wrapping text/code fences."""
    text = text.strip()

    # Strip code fences if present
    fence_match = re.search(r"```(?:json)?\s*(.+?)\s*```", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1).strip()

    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try to find the first {...} or [...] block
    for open_char, close_char in (("{", "}"), ("[", "]")):
        start = text.find(open_char)
        if start == -1:
            continue
        end = text.rfind(close_char)
        if end == -1 or end <= start:
            continue
        candidate = text[start : end + 1]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue

    raise LLMMalformedStructuredResponseError("Could not extract valid JSON from model output")


def validate_against_schema(parsed: Any, schema: dict | None) -> bool:
    """Lightweight schema validation for JSON Schema 'type' and required fields."""
    if not schema:
        return True
    schema_type = schema.get("type")

    if schema_type == "object":
        if not isinstance(parsed, dict):
            return False
        required = schema.get("required", [])
        for field in required:
            if field not in parsed:
                return False
        properties = schema.get("properties", {})
        # type-check present object properties that declare a type
        for key, value in parsed.items():
            prop = properties.get(key)
            if not prop:
                continue
            prop_type = prop.get("type")
            if prop_type == "string" and not isinstance(value, str):
                return False
            if prop_type in ("integer", "number") and not isinstance(value, (int, float)):
                return False
            if prop_type == "boolean" and not isinstance(value, bool):
                return False
            if prop_type == "array" and not isinstance(value, list):
                return False
    elif schema_type == "array":
        if not isinstance(parsed, list):
            return False
    elif schema_type == "string":
        if not isinstance(parsed, str):
            return False
    return True


def parse_structured_response(
    content: str,
    schema: dict | None = None,
    max_retries: int = 2,
    retry_fn: Any = None,
    model_used: str = "",
) -> StructuredOutput:
    """Parse and validate structured output from a model, with bounded retries.

    `retry_fn` is an optional callable that returns a new content string when the
    first parse/validate fails (used for controlled regeneration).
    """
    current = content
    attempts = 0

    while True:
        try:
            parsed = extract_json(current)
        except LLMMalformedStructuredResponseError as exc:
            if attempts >= max_retries or retry_fn is None:
                raise exc
            attempts += 1
            log.warning("structured_retry", attempt=attempts)
            current = retry_fn(attempts)  # type: ignore[misc]
            continue

        if not validate_against_schema(parsed, schema):
            if attempts >= max_retries or retry_fn is None:
                raise LLMMalformedStructuredResponseError(
                    f"Parsed output failed schema validation: {schema}"
                )
            attempts += 1
            log.warning("structured_retry_validation", attempt=attempts)
            current = retry_fn(attempts)  # type: ignore[misc]
            continue

        return StructuredOutput(parsed=parsed, model_used=model_used, retries=attempts)