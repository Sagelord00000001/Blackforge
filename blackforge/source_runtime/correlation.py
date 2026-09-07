from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from blackforge.source_runtime.identity import (
    build_correlation_identity,
    same_correlation_identity,
)
from blackforge.source_runtime.models import (
    CorrelationComparison,
    CorrelationOutcome,
    CorrelationResult,
    RuleReference,
    Side,
    SourceValue,
)

if TYPE_CHECKING:
    from blackforge.source_runtime.rules import CorrelationRule, RuleRegistry


class PropertyResolver(Protocol):
    """Maps an untrusted key to a rule; returns None to mark not-comparable."""

    def __call__(
        self, rule_registry: RuleRegistry, property: str
    ) -> CorrelationRule | None:
        ...


# Properties whose both-present-and-differ state is a CONTRADICTION (mutually
# exclusive claims), not a plain DISCREPANCY. Both evidence records stay
# preserved; neither side is silently chosen.
_CONTRADICTION_SENSITIVE: frozenset[str] = frozenset(
    {
        "backup_enabled",
        "publicly_accessible",
        "tls_enabled",
        "readiness",
        "service_type",
    }
)


def default_property_resolver(
    rule_registry: RuleRegistry, property: str
) -> CorrelationRule | None:
    """Default: every known property compares via exact equality unless overridden."""
    # Non-comparable declared-only fields.
    if property in {"namespace", "ingress_path"}:
        return None
    if property in _CONTRADICTION_SENSITIVE:
        return rule_registry.get("sr_contradiction")
    return rule_registry.get("sr_exact")


def _source_value(record: dict, property: str) -> SourceValue:
    props = record.get("properties") or {}
    raw = props.get(property)
    normalized = str(raw).strip() if raw is not None else None
    return SourceValue(
        side=Side.SOURCE,
        property=property,
        normalized_value=normalized,
        present=normalized is not None,
    )


def _runtime_value(record: dict, property: str) -> SourceValue:
    props = record.get("properties") or {}
    raw = props.get(property)
    normalized = str(raw).strip() if raw is not None else None
    return SourceValue(
        side=Side.RUNTIME,
        property=property,
        normalized_value=normalized,
        present=normalized is not None,
    )


def _merge_properties(source: dict, runtime: dict) -> list[str]:
    source_props = set((source.get("properties") or {}).keys())
    runtime_props = set((runtime.get("properties") or {}).keys())
    return sorted(source_props | runtime_props)


def _aggregate_result(results: list[CorrelationResult]) -> CorrelationResult:
    """Aggregate per-property results for one identity, deterministically.

    Rules:
    * any explicit CONTRADICTION -> CONTRADICTION (both sides preserved)
    * DISCREPANCY present and nothing contradictory -> DISCREPANCY
    * UNKNOWN present and everything else MATCH/absent -> UNKNOWN
    * all present MATCH -> MATCH
    * otherwise -> UNKNOWN (never invented)
    """
    if any(r == CorrelationResult.CONTRADICTION for r in results):
        return CorrelationResult.CONTRADICTION
    if any(r == CorrelationResult.DISCREPANCY for r in results):
        return CorrelationResult.DISCREPANCY
    if any(r == CorrelationResult.UNKNOWN for r in results):
        return CorrelationResult.UNKNOWN
    return CorrelationResult.MATCH


def _min_confidence(source_conf: object, runtime_conf: object) -> object:
    """Confidence of the comparison may never exceed either side's confidence.

    A LOW + LOW pairing is never upgraded to HIGH; only the weaker of the two
    is used. This is the confidence-propagation floor required by the DoD.
    """

    def _score(value: object) -> float:
        score = getattr(value, "to_score", None)
        if callable(score):
            return float(score())
        return 0.5

    if _score(source_conf) <= _score(runtime_conf):
        return source_conf
    return runtime_conf


class CorrelationEvaluator:
    """Deterministic, rule-driven source/runtime comparison for one identity."""

    def __init__(self, rule_registry: RuleRegistry) -> None:
        self.rule_registry = rule_registry

    def compare_records(
        self,
        *,
        source_record: dict | None,
        runtime_record: dict | None,
        source_conf: object,
        runtime_conf: object,
        capability_id: str,
        resolver: PropertyResolver = default_property_resolver,
    ) -> CorrelationOutcome | None:
        """Compute an outcome for one identity.

        When either side is missing the comparison is not fabricated: the
        outcome is UNKNOWN (never a MATCH) and carries a comparison that
        records the missing side only. Both missing -> None (nothing to state).
        """
        if source_record is None and runtime_record is None:
            return None

        present_record = source_record if source_record is not None else runtime_record
        present_identity = present_record.get("identity") or {}
        present_id = build_correlation_identity(
            present_identity.get("scope_kind", ""),
            present_identity.get("scope_parts"),
            present_identity.get("name", ""),
        )
        side_present = Side.SOURCE if source_record is not None else Side.RUNTIME
        side_missing = Side.RUNTIME if source_record is not None else Side.SOURCE

        if source_record is None or runtime_record is None:
            # Do not invent the missing side. Record the partial evidence.
            return CorrelationOutcome(
                capability_id=capability_id,
                identity=present_id,
                result=CorrelationResult.UNKNOWN,
                confidence=_min_confidence(source_conf, runtime_conf),
                comparisons=[
                    CorrelationComparison(
                        property="*",
                        result=CorrelationResult.UNKNOWN,
                        source_value=(
                            f"({side_present.value} side present)"
                        ),
                        runtime_value=None,
                        rule=RuleReference(rule_id="sr_missing", version="1.0.0"),
                        note=(
                            f"missing {side_missing.value} evidence for "
                            f"{present_id.identity}; state is not invented"
                        ),
                    )
                ],
            )

        source_identity = source_record.get("identity") or {}
        runtime_identity = runtime_record.get("identity") or {}

        src_id = build_correlation_identity(
            source_identity.get("scope_kind", ""),
            source_identity.get("scope_parts"),
            source_identity.get("name", ""),
        )
        rnt_id = build_correlation_identity(
            runtime_identity.get("scope_kind", ""),
            runtime_identity.get("scope_parts"),
            runtime_identity.get("name", ""),
        )

        if not same_correlation_identity(src_id, rnt_id):
            return CorrelationOutcome(
                capability_id=capability_id,
                identity=rnt_id if rnt_id.identity else src_id,
                result=CorrelationResult.NOT_COMPARABLE,
                confidence=_min_confidence(source_conf, runtime_conf),
                comparisons=[
                    CorrelationComparison(
                        property="identity",
                        result=CorrelationResult.NOT_COMPARABLE,
                        source_value=src_id.identity,
                        runtime_value=rnt_id.identity,
                        rule=RuleReference(rule_id="sr_identity", version="1.0.0"),
                        note="same resource name in different canonical scope; no match",
                    )
                ],
            )

        comparisons: list[CorrelationComparison] = []
        for property in _merge_properties(source_record, runtime_record):
            rule = resolver(self.rule_registry, property)
            if rule is None:
                continue
            sv = _source_value(source_record, property)
            rv = _runtime_value(runtime_record, property)
            result = rule.compare(source=sv, runtime=rv)
            comparisons.append(
                CorrelationComparison(
                    property=property,
                    result=result,
                    source_value=sv.normalized_value,
                    runtime_value=rv.normalized_value,
                    rule=rule.reference,
                )
            )

        if not comparisons:
            return CorrelationOutcome(
                capability_id=capability_id,
                identity=src_id,
                result=CorrelationResult.NOT_COMPARABLE,
                confidence=_min_confidence(source_conf, runtime_conf),
                comparisons=[
                    CorrelationComparison(
                        property="*",
                        result=CorrelationResult.NOT_COMPARABLE,
                        rule=RuleReference(rule_id="sr_none", version="1.0.0"),
                        note="no comparable properties between the two sides",
                    )
                ],
            )

        aggregated = _aggregate_result([c.result for c in comparisons])
        # Contradiction: both sides preserved; confidence stays the weaker side.
        conf = _min_confidence(source_conf, runtime_conf)
        return CorrelationOutcome(
            capability_id=capability_id,
            identity=src_id,
            result=aggregated,
            confidence=conf,
            comparisons=comparisons,
        )


__all__ = [
    "CorrelationEvaluator",
    "PropertyResolver",
    "default_property_resolver",
    "_aggregate_result",
    "_min_confidence",
]
