from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from blackforge.business_logic.models import (
    BusinessLogicHypothesisObservation,
    BusinessLogicValidationObservation,
    BusinessRuleObservation,
    HypothesisOutcome,
    Observation,
    OwnershipObservation,
    ReplaySafetyClass,
    RoleBoundaryObservation,
    StateObservation,
    StateTransitionObservation,
    TransitionResult,
    ValidationResult,
    WorkflowConsistencyObservation,
    WorkflowObservation,
    WorkflowReplayObservation,
)
from blackforge.core.errors import BusinessLogicNormalizationError
from blackforge.world_model.canonical import normalize_hostname, normalize_url


class BusinessNormalizedOutput(BaseModel):
    """Business logic adapter result with optional transport error metadata.

    An ``error`` document is a *handled* negative outcome (rate limited,
    unreachable, throttled, malformed) — it becomes a business logic status,
    never a crash.
    """

    observations: list[Observation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    error: dict | None = None


class BusinessToolAdapter(ABC):
    """Boundary between mock raw output and typed business logic observations."""

    tool: str = "unknown"

    @abstractmethod
    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> BusinessNormalizedOutput:
        ...


def _load_document(raw_output: object) -> Any:
    if isinstance(raw_output, str):
        try:
            return json.loads(raw_output)
        except json.JSONDecodeError as exc:
            raise BusinessLogicNormalizationError(
                f"tool produced malformed JSON: {exc}"
            ) from exc
    if isinstance(raw_output, (dict, list)):
        return raw_output
    raise BusinessLogicNormalizationError("tool output is not a parseable document")


def _require_string(document: dict[str, Any], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value.strip():
        raise BusinessLogicNormalizationError(f"missing or empty string field: {field}")
    return value.strip()


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _string_list(value: object, field: str) -> list[str]:
    if not isinstance(value, list):
        raise BusinessLogicNormalizationError(f"invalid list field: {field}")
    result = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise BusinessLogicNormalizationError(f"invalid entry in {field}")
        result.append(item.strip())
    return result


def _normalize_url_raise(value: object) -> str:
    try:
        url = normalize_url(_require_string({"url": value}, "url"))
    except (ValueError, BusinessLogicNormalizationError) as exc:
        raise BusinessLogicNormalizationError(f"invalid url: {exc}") from exc
    if not url.startswith(("http://", "https://")):
        raise BusinessLogicNormalizationError("url must be http(s)")
    return url


def _normalize_host_raise(value: object) -> str:
    try:
        return normalize_hostname(_require_string({"host": value}, "host"))
    except (ValueError, BusinessLogicNormalizationError) as exc:
        raise BusinessLogicNormalizationError(f"invalid host: {exc}") from exc


def _base_output(
    document: dict[str, Any],
    *,
    observations: list[Observation],
    warnings: list[str],
) -> BusinessNormalizedOutput:
    if document.get("error") is not None:
        error = document["error"]
        if not isinstance(error, dict):
            raise BusinessLogicNormalizationError("tool error must be an object")
    return BusinessNormalizedOutput(observations=observations, warnings=warnings)


def _error_output(document: dict[str, Any]) -> BusinessNormalizedOutput:
    error = document.get("error")
    if not isinstance(error, dict):
        raise BusinessLogicNormalizationError("tool error must be an object")
    return BusinessNormalizedOutput(observations=[], warnings=[], error=dict(error))


def _require_url_host(document: dict[str, Any]) -> tuple[str, str]:
    try:
        url = _normalize_url_raise(document.get("observed_url"))
        host = _normalize_host_raise(document.get("host"))
    except BusinessLogicNormalizationError as exc:
        raise BusinessLogicNormalizationError(
            f"observation url invalid: {exc}"
        ) from exc
    return url, host


class WorkflowDiscoveryAdapter(BusinessToolAdapter):
    """Parses ``discover_workflows`` output."""

    tool = "discover_workflows"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> BusinessNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise BusinessLogicNormalizationError(
                "workflow discovery output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        workflow = _require_string(document, "workflow")
        observations: list[Observation] = [
            WorkflowObservation(
                url=url,
                host=host,
                workflow=workflow,
                application=_optional_string(document.get("application")),
                description=_optional_string(document.get("description")),
                state_names=_string_list(document.get("state_names", []), "state_names"),
                action_names=_string_list(
                    document.get("action_names", []), "action_names"
                ),
                note=_optional_string(document.get("note")),
            )
        ]
        return _base_output(document, observations=observations, warnings=[])


class WorkflowModelingAdapter(BusinessToolAdapter):
    """Parses ``model_workflow`` output into state observations."""

    tool = "model_workflow"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> BusinessNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise BusinessLogicNormalizationError("workflow model output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        workflow = _require_string(document, "workflow")
        initial_state = _optional_string(document.get("initial_state")) or ""
        terminal_states = set(
            _string_list(document.get("terminal_states", []), "terminal_states")
        )
        observations: list[Observation] = []
        for item in document.get("states", []):
            if not isinstance(item, dict):
                raise BusinessLogicNormalizationError("state entry must be an object")
            try:
                state = _require_string(item, "state")
            except BusinessLogicNormalizationError as exc:
                raise BusinessLogicNormalizationError(f"invalid state entry: {exc}") from exc
            observations.append(
                StateObservation(
                    url=url,
                    host=host,
                    workflow=workflow,
                    state=state,
                    initial=state == initial_state,
                    terminal=state in terminal_states,
                    allowed_roles=[
                        r
                        for r in item.get("allowed_roles", [])
                        if isinstance(r, str)
                    ],
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            return _base_output(
                document,
                observations=[],
                warnings=["no workflow states modeled"],
            )
        return _base_output(document, observations=observations, warnings=[])


class StateTransitionAdapter(BusinessToolAdapter):
    """Parses ``analyze_state_transitions`` output."""

    tool = "analyze_state_transitions"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> BusinessNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise BusinessLogicNormalizationError(
                "state transition output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        workflow = _require_string(document, "workflow")
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("state_transitions", []):
            if not isinstance(item, dict):
                warnings.append("discarded state transition entry: not an object")
                continue
            try:
                action = _require_string(item, "action")
                source_state = _require_string(item, "source_state")
                target_state = _require_string(item, "target_state")
            except BusinessLogicNormalizationError as exc:
                warnings.append(f"discarded state transition entry: {exc}")
                continue
            observations.append(
                StateTransitionObservation(
                    url=url,
                    host=host,
                    workflow=workflow,
                    action=action,
                    source_state=source_state,
                    target_state=target_state,
                    direct=bool(item.get("direct", True)),
                    prerequisite=_optional_string(item.get("prerequisite")),
                    resource=_optional_string(item.get("resource")),
                    anomalous=bool(item.get("anomalous", False)),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            note = _optional_string(document.get("note")) or "no state transitions observed"
            warnings.append(note)
        return _base_output(document, observations=observations, warnings=warnings)


class BusinessRuleAdapter(BusinessToolAdapter):
    """Parses ``analyze_business_rules`` output."""

    tool = "analyze_business_rules"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> BusinessNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise BusinessLogicNormalizationError("business rule output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        workflow = _require_string(document, "workflow")
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("business_rules", []):
            if not isinstance(item, dict):
                warnings.append("discarded business rule entry: not an object")
                continue
            try:
                rule = _require_string(item, "rule")
            except BusinessLogicNormalizationError as exc:
                warnings.append(f"discarded business rule entry: {exc}")
                continue
            enforcement = _optional_string(item.get("enforcement")) or "not_applicable"
            observations.append(
                BusinessRuleObservation(
                    url=url,
                    host=host,
                    workflow=workflow,
                    rule=rule,
                    description=_optional_string(item.get("description")),
                    enforcement=enforcement,
                    observed=bool(item.get("observed", False)),
                    detail=_optional_string(item.get("detail")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            note = _optional_string(document.get("note")) or "no business rules observed"
            warnings.append(note)
        return _base_output(document, observations=observations, warnings=warnings)


class OwnershipAdapter(BusinessToolAdapter):
    """Parses ``analyze_ownership`` output (controlled identities only)."""

    tool = "analyze_ownership"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> BusinessNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise BusinessLogicNormalizationError("ownership output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        workflow = _require_string(document, "workflow")
        controlled = {
            str(i) for i in document.get("test_identities", []) if isinstance(i, str)
        }
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("ownership", []):
            if not isinstance(item, dict):
                warnings.append("discarded ownership entry: not an object")
                continue
            try:
                resource = _require_string(item, "resource")
                owner = _require_string(item, "owner")
            except BusinessLogicNormalizationError as exc:
                warnings.append(f"discarded ownership entry: {exc}")
                continue
            observations.append(
                OwnershipObservation(
                    url=url,
                    host=host,
                    workflow=workflow,
                    resource=resource,
                    owner=owner,
                    owner_type=_optional_string(item.get("owner_type")) or "identity",
                    controlled=owner in controlled,
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            note = (
                _optional_string(document.get("note"))
                or "no ownership entries for the controlled identities"
            )
            warnings.append(note)
        return _base_output(document, observations=observations, warnings=warnings)


class RoleBoundaryAdapter(BusinessToolAdapter):
    """Parses ``analyze_role_boundaries`` output."""

    tool = "analyze_role_boundaries"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> BusinessNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise BusinessLogicNormalizationError("role boundary output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        workflow = _require_string(document, "workflow")
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("role_boundaries", []):
            if not isinstance(item, dict):
                warnings.append("discarded role boundary entry: not an object")
                continue
            try:
                role = _require_string(item, "role")
                action = _require_string(item, "action")
                resource = _require_string(item, "resource")
            except BusinessLogicNormalizationError as exc:
                warnings.append(f"discarded role boundary entry: {exc}")
                continue
            expected = item.get("expected")
            expected_value: bool | None = None
            if isinstance(expected, bool):
                expected_value = expected
            observations.append(
                RoleBoundaryObservation(
                    url=url,
                    host=host,
                    workflow=workflow,
                    role=role,
                    action=action,
                    resource=resource,
                    allowed=bool(item.get("allowed", False)),
                    expected=expected_value,
                    consistent=(
                        bool(item["consistent"])
                        if isinstance(item.get("consistent"), bool)
                        else None
                    ),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            note = (
                _optional_string(document.get("note")) or "no role boundaries observed"
            )
            warnings.append(note)
        return _base_output(document, observations=observations, warnings=warnings)


class WorkflowConsistencyAdapter(BusinessToolAdapter):
    """Parses ``check_workflow_consistency`` output."""

    tool = "check_workflow_consistency"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> BusinessNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise BusinessLogicNormalizationError(
                "workflow consistency output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        workflow = _require_string(document, "workflow")
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("invariants", []):
            if not isinstance(item, dict):
                warnings.append("discarded invariant entry: not an object")
                continue
            try:
                invariant = _require_string(item, "invariant")
            except BusinessLogicNormalizationError as exc:
                warnings.append(f"discarded invariant entry: {exc}")
                continue
            observations.append(
                WorkflowConsistencyObservation(
                    url=url,
                    host=host,
                    workflow=workflow,
                    invariant=invariant,
                    status=_optional_string(item.get("status")) or "unknown",
                    detail=_optional_string(item.get("detail")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            note = _optional_string(document.get("note")) or "no invariants to check"
            warnings.append(note)
        return _base_output(document, observations=observations, warnings=warnings)


class WorkflowReplayAdapter(BusinessToolAdapter):
    """Parses ``replay_workflow`` output into per-step replay observations."""

    tool = "replay_workflow"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> BusinessNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise BusinessLogicNormalizationError("workflow replay output must be a dict")
        if document.get("error") is not None:
            error = document.get("error")
            if isinstance(error, dict) and error.get("kind") == "replay_rejected":
                return _base_output(
                    document,
                    observations=[],
                    warnings=[str(error.get("message", "replay rejected"))],
                )
            return _error_output(document)
        url, host = _require_url_host(document)
        workflow = _require_string(document, "workflow")
        observations: list[Observation] = []
        for item in document.get("replay", []):
            if not isinstance(item, dict):
                continue
            try:
                action = _require_string(item, "action")
                source_state = _require_string(item, "source_state")
            except BusinessLogicNormalizationError:
                continue
            observations.append(
                WorkflowReplayObservation(
                    url=url,
                    host=host,
                    workflow=workflow,
                    action=action,
                    source_state=source_state,
                    target_state=_optional_string(item.get("target_state")),
                    result=_transition_result(item.get("result")),
                    safety_class=_replay_safety(item.get("safety_class")),
                    sequence_length=item.get("sequence_length")
                    if isinstance(item.get("sequence_length"), int)
                    else 1,
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            return _base_output(
                document,
                observations=[],
                warnings=["no replay steps recorded"],
            )
        return _base_output(document, observations=observations, warnings=[])


class HypothesisAdapter(BusinessToolAdapter):
    """Parses ``hypothesize_business_logic`` output."""

    tool = "hypothesize_business_logic"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> BusinessNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise BusinessLogicNormalizationError(
                "business logic hypothesis output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        workflow = _require_string(document, "workflow")
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("hypotheses", []):
            if not isinstance(item, dict):
                warnings.append("discarded hypothesis entry: not an object")
                continue
            try:
                hypothesis = _require_string(item, "hypothesis")
            except BusinessLogicNormalizationError as exc:
                warnings.append(f"discarded hypothesis entry: {exc}")
                continue
            observations.append(
                BusinessLogicHypothesisObservation(
                    url=url,
                    host=host,
                    workflow=workflow,
                    hypothesis=hypothesis,
                    outcome=_hypothesis_outcome(item.get("outcome")),
                    detail=_optional_string(item.get("detail")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            note = _optional_string(document.get("note")) or "no hypotheses evaluated"
            warnings.append(note)
        return _base_output(document, observations=observations, warnings=warnings)


class ValidationAdapter(BusinessToolAdapter):
    """Parses ``validate_business_logic`` output."""

    tool = "validate_business_logic"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> BusinessNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise BusinessLogicNormalizationError(
                "business logic validation output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        workflow = _require_string(document, "workflow")
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("validations", []):
            if not isinstance(item, dict):
                warnings.append("discarded validation entry: not an object")
                continue
            try:
                hypothesis = _require_string(item, "hypothesis")
            except BusinessLogicNormalizationError as exc:
                warnings.append(f"discarded validation entry: {exc}")
                continue
            observations.append(
                BusinessLogicValidationObservation(
                    url=url,
                    host=host,
                    workflow=workflow,
                    hypothesis=hypothesis,
                    result=_validation_result(item.get("result")),
                    evidence_reference=_optional_string(
                        item.get("evidence_reference")
                    ),
                    replay_observations=item.get("replay_observations")
                    if isinstance(item.get("replay_observations"), int)
                    else 0,
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            note = _optional_string(document.get("note")) or "no validations recorded"
            warnings.append(note)
        return _base_output(document, observations=observations, warnings=warnings)


class WorkflowEvidenceAdapter(BusinessToolAdapter):
    """Parses ``collect_workflow_evidence`` output."""

    tool = "collect_workflow_evidence"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> BusinessNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise BusinessLogicNormalizationError(
                "workflow evidence output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        workflow = _require_string(document, "workflow")
        observations: list[Observation] = [
            WorkflowObservation(
                url=url,
                host=host,
                workflow=workflow,
                application=_optional_string(document.get("application")),
                description=_optional_string(document.get("description")),
                state_names=_string_list(document.get("state_names", []), "state_names"),
                action_names=_string_list(
                    document.get("action_names", []), "action_names"
                ),
                note=_optional_string(document.get("note")),
            )
        ]
        return _base_output(document, observations=observations, warnings=[])


def _transition_result(value: object) -> TransitionResult:
    if not isinstance(value, str):
        return TransitionResult.SUCCESS
    try:
        return TransitionResult(value.strip().lower())
    except ValueError:
        return TransitionResult.MALFORMED


def _replay_safety(value: object) -> ReplaySafetyClass:
    if not isinstance(value, str):
        return ReplaySafetyClass.PROHIBITED
    try:
        return ReplaySafetyClass(value.strip().lower())
    except ValueError:
        return ReplaySafetyClass.PROHIBITED


def _hypothesis_outcome(value: object) -> HypothesisOutcome:
    if not isinstance(value, str):
        return HypothesisOutcome.INCONCLUSIVE
    try:
        return HypothesisOutcome(value.strip().lower())
    except ValueError:
        return HypothesisOutcome.INCONCLUSIVE


def _validation_result(value: object) -> ValidationResult:
    if not isinstance(value, str):
        return ValidationResult.UNVERIFIABLE
    try:
        return ValidationResult(value.strip().lower())
    except ValueError:
        return ValidationResult.UNVERIFIABLE


def adapter_for_tool(tool: str) -> BusinessToolAdapter:
    """Return the adapter registered for a business logic tool name."""
    mapping: dict[str, BusinessToolAdapter] = {
        "discover_workflows": WorkflowDiscoveryAdapter(),
        "model_workflow": WorkflowModelingAdapter(),
        "analyze_state_transitions": StateTransitionAdapter(),
        "analyze_business_rules": BusinessRuleAdapter(),
        "analyze_ownership": OwnershipAdapter(),
        "analyze_role_boundaries": RoleBoundaryAdapter(),
        "check_workflow_consistency": WorkflowConsistencyAdapter(),
        "replay_workflow": WorkflowReplayAdapter(),
        "hypothesize_business_logic": HypothesisAdapter(),
        "validate_business_logic": ValidationAdapter(),
        "collect_workflow_evidence": WorkflowEvidenceAdapter(),
    }
    adapter = mapping.get(tool)
    if adapter is None:
        raise BusinessLogicNormalizationError(f"no adapter for tool: {tool}")
    return adapter
