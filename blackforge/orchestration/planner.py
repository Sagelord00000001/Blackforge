"""Planners for the mission orchestration layer.

A planner is a pure *reasoning* component: given a structured
:class:`PlannerContext` it returns one :class:`PlannerDecision`. It can never
touch a transport, spawn a process, or mutate evidence or the world model.
The deterministic orchestrator decides whether a proposed investigation may
be executed.

Three planners ship here, all using the same interface:

* :class:`MockPlanner` — deterministic, no I/O, used for tests and offline
  demonstrations.
* :class:`RuleBasedPlanner` — deterministic heuristics over the world model,
  evidence and attack-graph gaps.
* :class:`LLMPlanner` — drives the provider-agnostic LLM abstraction. Its
  single capability choice is validated fail-closed: unknown capabilities,
  out-of-scope targets and malformed payloads raise
  :class:`PlannerInvalidDecision` and are never executed.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from blackforge.core.types import RiskLevel
from blackforge.orchestration.models import (
    DecisionKind,
    PlannerContext,
    PlannerDecision,
    PlannerSource,
    Priority,
)

if TYPE_CHECKING:  # pragma: no cover - avoids runtime import in offline tests
    from collections.abc import Callable

    from blackforge.intelligence.llm.base import LLMProvider

_RISK_RANK: dict[str, int] = {
    RiskLevel.LOW.value: 0,
    RiskLevel.MEDIUM.value: 1,
    RiskLevel.HIGH.value: 2,
    RiskLevel.CRITICAL.value: 3,
}


class PlannerInvalidDecision(Exception):  # noqa: N818 - name is part of the API
    """A planner produced a decision that must fail closed."""


class PlannerError(Exception):
    """Planner infrastructure failure."""


class PlannerBase(ABC):
    """Shared contract: one context in, one typed decision out."""

    planner_id: str = "base"

    @abstractmethod
    def plan(self, ctx: PlannerContext) -> PlannerDecision: ...


class MockPlanner(PlannerBase):
    """Deterministic planner emitting the first pending, authorized step.

    Used to prove the full pipeline offline and in tests. Scans the routing
    set in a stable order and always prefers an unexplored in-scope target;
    when nothing is left it asks the orchestrator to stop.
    """

    planner_id = "mock"

    def plan(self, ctx: PlannerContext) -> PlannerDecision:
        choice = _first_pending(ctx)
        if choice is None:
            return PlannerDecision(
                kind=DecisionKind.COMPLETE,
                capability="",
                target="",
                reason="no applicable authorized actions remain",
                source=PlannerSource.MOCK,
            )
        capability, target = choice
        return PlannerDecision(
            kind=DecisionKind.INVESTIGATE,
            capability=capability,
            target=target,
            reason="deterministic mock planner: first pending authorized step",
            priority=Priority.MEDIUM,
            source=PlannerSource.MOCK,
        )


class RuleBasedPlanner(PlannerBase):
    """Deterministic, explainable planner used as the production default.

    Ordering rules:

    1. Prefer the lowest-risk capability (the risk lookup is injected so the
       planner stays a pure function).
    2. Prefer targets with no recent evidence; never refire an executed
       capability/target pair unless the decision explicitly revalidates.
    3. Prefer the seed target and authorized world-model entities.
    4. Attack-graph gaps/uncertain edges mark high-priority targets.

    Every rule is a pure function of the context; nothing is executed here.
    """

    planner_id = "rule"

    def __init__(
        self,
        risk_lookup: Callable[[str], RiskLevel] | None = None,
    ) -> None:
        self._risk_lookup = risk_lookup or (lambda _capability: RiskLevel.MEDIUM)

    def plan(self, ctx: PlannerContext) -> PlannerDecision:
        choice = _first_pending(
            ctx, key=lambda capability: (_risk_rank(capability, self._risk_lookup),)
        )
        if choice is None:
            return PlannerDecision(
                kind=DecisionKind.COMPLETE,
                capability="",
                target="",
                reason="no applicable, authorized, unexplored action remains",
                source=PlannerSource.RULE,
            )
        capability, target = choice
        risk = self._risk_lookup(capability)
        priority = Priority.MEDIUM
        reason = "rule planner: first low-risk authorized capability"
        open_targets = _open_targets(ctx)
        if target in open_targets:
            priority = Priority.HIGH
            reason = "rule planner: target participates in an open attack-graph path"
        elif risk in (RiskLevel.LOW, RiskLevel.MEDIUM):
            reason = f"rule planner: {risk.value}-risk capability on unexplored target"
        return PlannerDecision(
            kind=DecisionKind.INVESTIGATE,
            capability=capability,
            target=target,
            reason=reason,
            priority=priority,
            source=PlannerSource.RULE,
        )


class LLMPlanner(PlannerBase):
    """LLM-backed planner with fail-closed validation.

    The provider responds with a single JSON object describing the next
    investigation (``{"decision", "capability", "target", "rationale",
    "priority"}``). The planner:

    * treats any non-``investigate`` decision as a stop request,
    * rejects a capability that is not in the routing set,
    * rejects a target that is not the seed or an authorized entity,
    * rejects malformed or non-JSON responses.

    ``planner_id`` is always ``"llm"`` so audit records attribute decisions
    to the LLM rather than the fallback.
    """

    planner_id = "llm"

    def __init__(self, provider: LLMProvider, temperature: float = 0.2) -> None:
        self._provider = provider
        self._temperature = temperature

    def plan(self, ctx: PlannerContext) -> PlannerDecision:
        payload = self._generate(ctx)
        decision = self._parse(payload, ctx)
        decision.source = PlannerSource.LLM
        return decision

    def _generate(self, ctx: PlannerContext) -> object:
        from blackforge.intelligence.llm.base import LLMRequest

        request = LLMRequest(
            prompt=_llm_prompt(ctx),
            system_prompt=(
                "You are the planning component of an authorized security "
                "assessment. You may only propose a single investigation "
                "from the capabilities and targets listed. You cannot run "
                "commands, open URLs, or access the system. Respond with "
                'exactly one JSON object: {"decision":"investigate|stop",'
                '"capability":"<capability>","target":"<authorized target>",'
                '"rationale":"<why>","priority":"low|medium|high"}.'
            ),
            temperature=self._temperature,
            max_tokens=512,
            context={
                "planner": "llm",
                "mission_id": str(ctx.mission_id),
                "seed_target": ctx.seed_target,
            },
            response_format={"type": "json_object"},
        )
        try:
            response = self._provider.generate(request)
        except Exception as exc:  # noqa: BLE001 - provider failures fail closed
            raise PlannerError(f"llm provider failure: {exc}") from exc
        content = (response.content or "").strip()
        if not content:
            raise PlannerInvalidDecision("llm returned no content")
        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            raise PlannerInvalidDecision(f"llm returned malformed JSON: {exc}") from exc

    def _parse(self, payload: object, ctx: PlannerContext) -> PlannerDecision:
        if not isinstance(payload, dict):
            raise PlannerInvalidDecision("llm payload is not an object")
        decision = str(payload.get("decision", "")).strip().lower()
        if decision in ("stop", "complete", "done", "finish"):
            return PlannerDecision(
                kind=DecisionKind.COMPLETE,
                capability="",
                target="",
                reason=str(payload.get("rationale", "llm requested stop")),
                source=PlannerSource.LLM,
            )
        capability = str(payload.get("capability", "")).strip()
        target = str(payload.get("target", "")).strip()
        rationale = str(payload.get("rationale", "")).strip() or "llm proposed step"
        priority_raw = str(payload.get("priority", "medium")).strip().lower()
        try:
            priority = Priority(priority_raw)
        except ValueError:
            priority = Priority.MEDIUM

        registered = set(ctx.routing.authorized) | set(ctx.routing.applicable)
        if not capability:
            raise PlannerInvalidDecision("llm proposed an empty capability")
        if capability not in registered:
            raise PlannerInvalidDecision(f"llm proposed unknown capability: {capability}")
        if not target:
            raise PlannerInvalidDecision("llm proposed an empty target")
        if not _target_allowed(ctx, target):
            raise PlannerInvalidDecision(f"llm proposed out-of-scope target: {target!r}")

        try:
            parsed = PlannerDecision(
                kind=DecisionKind.INVESTIGATE,
                capability=capability,
                target=target,
                reason=rationale,
                priority=priority,
                source=PlannerSource.LLM,
            )
            parsed.require_registered(registered)
        except ValueError as exc:
            raise PlannerInvalidDecision(str(exc)) from exc
        return parsed


def _target_allowed(ctx: PlannerContext, target: str) -> bool:
    if target == ctx.seed_target:
        return True
    return any(
        entity.authorized and entity.name == target for entity in ctx.world_entities
    )


def _open_targets(ctx: PlannerContext) -> set[str]:
    open_set: set[str] = set()
    for edge in ctx.graph.edges:
        if edge.state == "open":
            open_set.add(edge.source)
            open_set.add(edge.target)
    return open_set


def _risk_rank(capability: str, risk_lookup: Callable[[str], RiskLevel]) -> int:
    try:
        risk = risk_lookup(capability)
    except (KeyError, ValueError):
        return 1
    return _RISK_RANK.get(risk.value, 1)


def _first_pending(
    ctx: PlannerContext,
    key: Callable[[str], tuple] | None = None,
) -> tuple[str, str] | None:
    """First (capability, target) with no equivalent executed pair.

    The planner may *only* choose from ``routing.authorized``. If nothing is
    authorized the planner must fail closed by returning ``None`` (a stop
    request), never falling back to merely applicable capabilities.
    """
    names = sorted(set(ctx.routing.authorized))
    if not names:
        return None
    if key is not None:
        names = sorted(names, key=key)
    seen: set[tuple[str, str]] = {
        (evidence.source_capability, evidence.target)
        for evidence in ctx.recent_evidence
    }
    seen.update(_pair_from_action(a) for a in ctx.previous_actions)
    targets: list[str] = [ctx.seed_target]
    for entity in ctx.world_entities:
        if entity.authorized and entity.name not in targets:
            targets.append(entity.name)
    for capability in names:
        for target in targets:
            if (capability, target) in seen:
                continue
            return capability, target
    return None


def _pair_from_action(action: str) -> tuple[str, str]:
    if "@" in action:
        capability, _, target = action.partition("@")
        return capability, target
    return (action, "")


def _llm_prompt(ctx: PlannerContext) -> str:
    lines = [
        f"OBJECTIVE: {ctx.objective}",
        f"SEED TARGET: {ctx.seed_target}",
        "AUTHORIZED TARGETS: "
        + ",".join(
            dict.fromkeys(
                [ctx.seed_target]
                + [e.name for e in ctx.world_entities if e.authorized]
            )
        ),
        "SCOPE MAX RISK: " + str(ctx.scope.max_risk_level.value),
        "AVAILABLE CAPABILITIES: "
        + ",".join(
            sorted(
                set(ctx.routing.real_controlled)
                | set(ctx.routing.authorized)
                | set(ctx.routing.applicable)
            )
        ),
    ]
    if ctx.recent_evidence:
        lines.append("RECENT OBSERVATIONS:")
        for row in ctx.recent_evidence[-5:]:
            lines.append(f"- [{row.source_capability} @ {row.target}] {row.summary}")
    if ctx.graph.gaps:
        lines.append("OPEN QUESTIONS: " + "; ".join(ctx.graph.gaps[:5]))
    lines.append(
        f"BUDGET: {ctx.steps_used}/{ctx.steps_limit} steps, "
        f"{ctx.capability_calls_used}/{ctx.capability_calls_limit} calls used"
    )
    lines.append(
        '{RESPONSE FORMAT: {"decision":"investigate","capability":"<cap>",'
        '"target":"<(seed|authorized entity)>","rationale":"<why>",'
        '"priority":"<low|medium|high>"}}'
    )
    return "\n".join(lines)


__all__ = [
    "LLMPlanner",
    "MockPlanner",
    "PlannerBase",
    "PlannerError",
    "PlannerInvalidDecision",
    "RuleBasedPlanner",
]
