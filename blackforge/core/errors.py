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


class EvidenceRuleError(EvidenceError):
    """Raised when evidence violates a transition/rule boundary.

    For example an unauthorized request to create or transition evidence to
    ``VALIDATED`` without going through a validation workflow.
    """


class CapabilityError(BlackforgeError):
    """Raised on capability-related failures."""


class LLMProviderError(BlackforgeError):
    """Raised on LLM provider failures."""


class LLMModelNotFoundError(LLMProviderError):
    """Raised when a configured model cannot be located or downloaded."""


class LLMModelDownloadError(LLMProviderError):
    """Raised when model weight download fails."""


class LLMInsufficientMemoryError(LLMProviderError):
    """Raised when a model cannot be loaded due to memory constraints."""


class LLMUnsupportedDeviceError(LLMProviderError):
    """Raised when the requested device is not supported."""


class LLMInferenceError(LLMProviderError):
    """Raised when inference fails."""


class LLMMalformedStructuredResponseError(LLMProviderError):
    """Raised when structured output cannot be parsed/validated."""


class LLMTimeoutError(LLMProviderError):
    """Raised when an inference call times out."""


class LLMFallbackActivated(LLMProviderError):
    """Raised when the primary provider fails and fallback is used."""


class MemoryError(BlackforgeError):
    """Raised on memory system failures."""


class WorldError(BlackforgeError):
    """Raised on world model failures."""


class WorldRuleError(WorldError):
    """Raised when a world model operation violates an identity/rule boundary.

    For example an unnormalizable canonical name, a relationship whose
    endpoints do not exist or belong to another mission, or an entity marked
    ``VALIDATED`` without any supporting evidence.
    """


class ValidationError(BlackforgeError):
    """Raised when input validation fails."""


class ReconError(BlackforgeError):
    """Raised on reconnaissance capability failures."""


class ReconNormalizationError(ReconError):
    """Raised when a reconnaissance tool's raw output cannot be parsed/validated."""


class ReconExecutionError(ReconError):
    """Raised when a reconnaissance adapter fails to execute."""


class ReconTimeoutError(ReconError):
    """Raised when a reconnaissance adapter exceeds its execution time budget."""


class ReconLimitError(ReconError):
    """Raised when a reconnaissance observation or result limit is exceeded."""
