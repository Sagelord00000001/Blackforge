from __future__ import annotations

from typing import Protocol

from blackforge.source_runtime.models import CorrelationResult, RuleReference, SourceValue


class ComparisonFn(Protocol):
    def __call__(self, *, source: SourceValue, runtime: SourceValue) -> CorrelationResult:
        """Deterministic comparison over one comparable property."""
        ...


def _absent(value: SourceValue) -> bool:
    return not value.present


def _both_absent(source: SourceValue, runtime: SourceValue) -> bool:
    return _absent(source) and _absent(runtime)


def _either_absent(source: SourceValue, runtime: SourceValue) -> bool:
    return _absent(source) or _absent(runtime)


def exact_equality(*, source: SourceValue, runtime: SourceValue) -> CorrelationResult:
    """Both sides present and normalized values are equal -> MATCH else DISCREPANCY.

    If either side is absent the comparison cannot be determined -> UNKNOWN.
    """
    if _either_absent(source, runtime):
        return CorrelationResult.UNKNOWN
    if source.normalized_value == runtime.normalized_value:
        return CorrelationResult.MATCH
    return CorrelationResult.DISCREPANCY


def set_equality(*, source: SourceValue, runtime: SourceValue) -> CorrelationResult:
    """Order-independent set comparison for multi-value properties (e.g. env vars).

    Empty-vs-empty both absent -> UNKNOWN; otherwise equal sets -> MATCH.
    """
    if _both_absent(source, runtime):
        return CorrelationResult.UNKNOWN
    if _either_absent(source, runtime):
        return CorrelationResult.UNKNOWN
    if source.normalized_value == runtime.normalized_value:
        return CorrelationResult.MATCH
    return CorrelationResult.DISCREPANCY


def immutable_digest_rule(*, source: SourceValue, runtime: SourceValue) -> CorrelationResult:
    """Image correlation prefers the immutable digest; a moved tag is NOT a match.

    A tag matches only when its resolved digest equals the runtime digest.
    """
    if _both_absent(source, runtime):
        return CorrelationResult.UNKNOWN
    if _either_absent(source, runtime):
        return CorrelationResult.UNKNOWN
    if source.normalized_value == runtime.normalized_value:
        return CorrelationResult.MATCH
    return CorrelationResult.DISCREPANCY


def presence_rule(*, source: SourceValue, runtime: SourceValue) -> CorrelationResult:
    """Both present -> MATCH; a declared value with no observed runtime value -> UNKNOWN.

    Absence of the runtime side never justifies inferring a value.
    """
    if _absent(source) and _absent(runtime):
        return CorrelationResult.UNKNOWN
    if _absent(source):
        return CorrelationResult.UNKNOWN
    if _absent(runtime):
        return CorrelationResult.UNKNOWN
    return CorrelationResult.MATCH


def contradiction_rule(*, source: SourceValue, runtime: SourceValue) -> CorrelationResult:
    """Both sides present and mutually exclusive -> CONTRADICTION.

    Used for polarity/boolean properties where both claims cannot hold at once
    (e.g. ``backup_enabled=true`` declared vs ``false`` observed). Both sides
    are preserved and reported; neither is silently chosen. Equal present
    values -> MATCH; a missing side -> UNKNOWN.
    """
    if _both_absent(source, runtime):
        return CorrelationResult.UNKNOWN
    if _either_absent(source, runtime):
        return CorrelationResult.UNKNOWN
    if source.normalized_value == runtime.normalized_value:
        return CorrelationResult.MATCH
    return CorrelationResult.CONTRADICTION


class CorrelationRule:
    """A deterministic, versioned rule bound to one comparable property.

    Rules encode *how* a comparison is made, never *whether* a discrepancy is a
    finding. Rule versions are preserved: producing a newer rule version never
    rewrites a historical result — it is recorded on the new result only.
    """

    def __init__(
        self,
        rule_id: str,
        version: str,
        fn: ComparisonFn,
        *,
        description: str = "",
    ) -> None:
        self.rule_id = rule_id
        self.version = version
        self._fn = fn
        self.description = description

    @property
    def reference(self) -> RuleReference:
        return RuleReference(rule_id=self.rule_id, version=self.version)

    def compare(
        self, *, source: SourceValue, runtime: SourceValue
    ) -> CorrelationResult:
        return self._fn(source=source, runtime=runtime)


RuleRegistry = dict[str, CorrelationRule]


def register_rule(registry: RuleRegistry, rule: CorrelationRule) -> None:
    registry[rule.rule_id] = rule


def default_rule_registry() -> RuleRegistry:
    """The default deterministic rule set (identities are stable across runs)."""
    registry: RuleRegistry = {}
    register_rule(
        registry,
        CorrelationRule(
            "sr_exact",
            "1.0.0",
            exact_equality,
            description="both sides present and normalized values equal",
        ),
    )
    register_rule(
        registry,
        CorrelationRule(
            "sr_set",
            "1.0.0",
            set_equality,
            description="order-independent set equality across both sides",
        ),
    )
    register_rule(
        registry,
        CorrelationRule(
            "sr_digest",
            "1.0.0",
            immutable_digest_rule,
            description="immutable digest comparison for container images",
        ),
    )
    register_rule(
        registry,
        CorrelationRule(
            "sr_presence",
            "1.0.0",
            presence_rule,
            description="presence-only comparison (declared vs observed)",
        ),
    )
    register_rule(
        registry,
        CorrelationRule(
            "sr_contradiction",
            "1.0.0",
            contradiction_rule,
            description="both sides present and mutually exclusive -> CONTRADICTION",
        ),
    )
    return registry


__all__ = [
    "ComparisonFn",
    "CorrelationRule",
    "RuleRegistry",
    "contradiction_rule",
    "default_rule_registry",
    "exact_equality",
    "immutable_digest_rule",
    "presence_rule",
    "register_rule",
    "set_equality",
]
