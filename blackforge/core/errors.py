from __future__ import annotations


class BlackforgeError(Exception):
    """Base exception for all Blackforge errors."""

    def __init__(self, message: str = "", details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConfigurationError(BlackforgeError):
    """Raised when configuration is invalid or missing."""


class AuthorizationError(BlackforgeError):
    """Raised when an action is not authorized."""


class ScopeError(BlackforgeError):
    """Raised when a target is outside the authorized scope."""


class MissionError(BlackforgeError):
    """Raised on mission-level failures."""


class TaskError(BlackforgeError):
    """Raised on task-level failures."""


class EvidenceError(BlackforgeError):
    """Raised on evidence-related failures."""


class CapabilityError(BlackforgeError):
    """Raised on capability-related failures."""


class LLMProviderError(BlackforgeError):
    """Raised on LLM provider failures."""


class MemoryError(BlackforgeError):
    """Raised on memory system failures."""


class ValidationError(BlackforgeError):
    """Raised when input validation fails."""
